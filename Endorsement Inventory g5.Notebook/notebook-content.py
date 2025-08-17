# Fabric notebook source

# METADATA ********************

# META {
# META   "kernel_info": {
# META     "name": "synapse_pyspark"
# META   },
# META   "dependencies": {
# META     "lakehouse": {
# META       "default_lakehouse": "2e429734-1ea8-4dfe-a2fb-ab43a109d72c",
# META       "default_lakehouse_name": "LHSand",
# META       "default_lakehouse_workspace_id": "1f236e20-cd40-40c8-ac77-820025dcfdf3",
# META       "known_lakehouses": [
# META         {
# META           "id": "2e429734-1ea8-4dfe-a2fb-ab43a109d72c"
# META         }
# META       ]
# META     }
# META   }
# META }

# CELL ********************

# -*- coding: utf-8 -*-
"""
Fabric + Power BI Scanner governance check:
- Enumerate domains -> workspaces (Fabric Admin API)
- Run Scanner API on workspaces (Power BI Admin)
- Inventory endorsements & sensitivity labels
- Raise on missing labels / expired certifications

Tested with Python 3.10+.
"""

import os, sys, time, json, math, logging, itertools, csv
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Iterable, Tuple, Optional

import requests
import pandas as pd
from dateutil import parser as dtparser
from msal import ConfidentialClientApplication

# -------------------------
# CONFIGURATION
# -------------------------

# Required: tenant & app creds (via environment variables)
TENANT_ID     = os.environ.get("TENANT_ID")
CLIENT_ID     = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")

if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
    raise RuntimeError("TENANT_ID, CLIENT_ID, and CLIENT_SECRET must be set as environment variables.")

# Token audiences (scopes) / resources
SCOPE_FABRIC  = "https://api.fabric.microsoft.com/.default"            # Fabric Admin/REST (domains, etc.)
SCOPE_POWERBI = "https://analysis.windows.net/powerbi/api/.default"    # Power BI Admin (Scanner API)

# APIs
FABRIC_BASE   = "https://api.fabric.microsoft.com/v1"
PBI_BASE      = "https://api.powerbi.com/v1.0/myorg"

# Scanner batch size (1..100)
SCANNER_BATCH_SIZE = 100

# Scanner optional flags (we don't need heavy payload to get endorsements/labels)
SCANNER_QUERY = {
    "lineage": "false",
    "datasourceDetails": "false",
    "datasetSchema": "false",
    "datasetExpressions": "false",
    "getArtifactUsers": "false",
}

# Governed item types where sensitivity labels are required
ENFORCE_LABEL_ITEM_TYPES = {"Report", "Dataset", "SemanticModel", "Dataflow", "Dashboard", "Datamart"}

# Certification expiry policy
CERT_MAX_AGE_DAYS = int(os.environ.get("CERT_MAX_AGE_DAYS", "365"))  # adjust to your policy
CERT_REGISTRY_PATH = os.environ.get("CERT_REGISTRY_PATH", "")        # JSON or CSV with artifactId, certifiedDate (ISO 8601)
TREAT_UNKNOWN_ATTESTATION_AS_EXPIRED = bool(int(os.environ.get("TREAT_UNKNOWN_ATTESTATION_AS_EXPIRED", "0")))

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("fabric-scanner")


# -------------------------
# AUTH HELPERS
# -------------------------

def get_token(scope: str) -> str:
    """Acquire an app-only token for the given scope using MSAL (client credentials)."""
    authority = f"https://login.microsoftonline.com/{TENANT_ID}"
    app = ConfidentialClientApplication(client_id=CLIENT_ID, client_credential=CLIENT_SECRET, authority=authority)
    result = app.acquire_token_for_client(scopes=[scope])
    if "access_token" not in result:
        raise RuntimeError(f"Failed to acquire token for scope {scope}. Error: {result}")
    return result["access_token"]


# -------------------------
# FABRIC ADMIN (DOMAINS)
# -------------------------

def fabric_get(url: str, token: str, params: Dict = None) -> Dict:
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers, params=params or {}, timeout=60)
    if r.status_code >= 400:
        raise RuntimeError(f"Fabric API GET failed {r.status_code}: {r.text}")
    return r.json() if r.text else {}

def list_domains(fabric_token: str) -> List[Dict]:
    """List all domains (id, displayName, etc.)."""
    url = f"{FABRIC_BASE}/admin/domains"
    results = []
    next_link = None
    while True:
        payload = fabric_get(next_link or url, fabric_token)
        values = payload.get("value") or payload.get("data") or []
        results.extend(values)
        next_link = payload.get("@odata.nextLink") or payload.get("nextLink")
        if not next_link:
            break
    return results

def list_domain_workspaces(fabric_token: str, domain_id: str) -> List[Dict]:
    """List workspaces assigned to a specific domain."""
    url = f"{FABRIC_BASE}/admin/domains/{domain_id}/workspaces"
    results = []
    next_link = None
    while True:
        payload = fabric_get(next_link or url, fabric_token)
        values = payload.get("value") or payload.get("data") or []
        results.extend(values)
        next_link = payload.get("@odata.nextLink") or payload.get("nextLink")
        if not next_link:
            break
    return results


# -------------------------
# POWER BI ADMIN (SCANNER)
# -------------------------

def pbi_post(url: str, token: str, json_body: Dict, params: Dict = None) -> Dict:
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = requests.post(url, headers=headers, params=params or {}, json=json_body, timeout=120)
    if r.status_code >= 400:
        raise RuntimeError(f"PBI API POST failed {r.status_code}: {r.text}")
    return r.json() if r.text else {}

def pbi_get(url: str, token: str, params: Dict = None) -> Dict:
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers, params=params or {}, timeout=120)
    if r.status_code >= 400:
        raise RuntimeError(f"PBI API GET failed {r.status_code}: {r.text}")
    return r.json() if r.text else {}

def trigger_scan(pbi_token: str, workspace_ids: List[str]) -> str:
    """POST admin/workspaces/getInfo -> returns scanId (202)."""
    url = f"{PBI_BASE}/admin/workspaces/getInfo"
    body = {"workspaces": workspace_ids}
    resp = pbi_post(url, pbi_token, body, params=SCANNER_QUERY)
    scan_id = resp.get("id")
    if not scan_id:
        raise RuntimeError(f"No scanId returned for workspaces batch (count={len(workspace_ids)}). Response: {resp}")
    return scan_id

def wait_for_scan(pbi_token: str, scan_id: str, timeout_sec: int = 600, poll_sec: int = 5) -> None:
    """Poll GET admin/workspaces/scanStatus/{scanId} until Succeeded or error."""
    url = f"{PBI_BASE}/admin/workspaces/scanStatus/{scan_id}"
    start = time.time()
    while True:
        resp = pbi_get(url, pbi_token)
        status = resp.get("status")
        if status in {"Succeeded"}:
            return
        if status in {"Failed", "Error"}:
            raise RuntimeError(f"Scan {scan_id} failed: {resp}")
        if time.time() - start > timeout_sec:
            raise TimeoutError(f"Scan {scan_id} timed out after {timeout_sec}s")
        time.sleep(poll_sec)

def get_scan_result(pbi_token: str, scan_id: str) -> Dict:
    """GET admin/workspaces/scanResult/{scanId}."""
    url = f"{PBI_BASE}/admin/workspaces/scanResult/{scan_id}"
    return pbi_get(url, pbi_token)


# -------------------------
# GOVERNANCE LOGIC
# -------------------------

def load_cert_registry(path: str) -> Dict[str, datetime]:
    """Load certification/attestation registry: artifactId -> certifiedDate (datetime)."""
    if not path:
        return {}
    if not os.path.isfile(path):
        raise FileNotFoundError(f"CERT_REGISTRY_PATH not found: {path}")

    registry: Dict[str, datetime] = {}
    if path.lower().endswith(".json"):
        data = json.load(open(path, "r", encoding="utf-8"))
        # support dict {artifactId: isoDate} or list of {artifactId, certifiedDate}
        if isinstance(data, dict):
            for k, v in data.items():
                registry[str(k).lower()] = dtparser.parse(v).replace(tzinfo=timezone.utc)
        elif isinstance(data, list):
            for row in data:
                aid = str(row.get("artifactId", "")).lower()
                dt = row.get("certifiedDate")
                if aid and dt:
                    registry[aid] = dtparser.parse(dt).replace(tzinfo=timezone.utc)
    else:
        # assume CSV with columns artifactId, certifiedDate
        with open(path, "r", encoding="utf-8") as fh:
            rdr = csv.DictReader(fh)
            for row in rdr:
                aid = str(row.get("artifactId", "")).lower()
                dt = row.get("certifiedDate")
                if aid and dt:
                    registry[aid] = dtparser.parse(dt).replace(tzinfo=timezone.utc)
    return registry

def flatten_scan_result(scan: Dict, wsid_to_domain: Dict[str, str]) -> pd.DataFrame:
    """Turn the scan result into a flat table of artifacts + governance fields."""
    rows = []
    for ws in scan.get("workspaces", []):
        ws_id   = ws.get("id")
        ws_name = ws.get("name")
        domain  = wsid_to_domain.get(ws_id)
        # artifact collections we care about
        for coll_name, item_type in [
            ("reports",   "Report"),
            ("datasets",  "Dataset"),  # semantic models
            ("dataflows", "Dataflow"),
            ("dashboards","Dashboard"),
            ("datamarts", "Datamart"),
        ]:
            for it in ws.get(coll_name, []) or []:
                rid   = it.get("id") or it.get("objectId")
                name  = it.get("name") or it.get("displayName")
                endors= (it.get("endorsementDetails") or {}).get("endorsement")
                certby= (it.get("endorsementDetails") or {}).get("certifiedBy")
                sens  = (it.get("sensitivityLabel") or {}).get("labelId")
                rows.append({
                    "domain": domain,
                    "workspaceId": ws_id,
                    "workspaceName": ws_name,
                    "itemType": item_type,
                    "artifactId": (rid or "").lower(),
                    "itemName": name,
                    "endorsement": endors,
                    "certifiedBy": certby,
                    "sensitivityLabelId": sens,
                })
    return pd.DataFrame(rows)

class MissingLabelError(Exception): ...
class ExpiredCertificationError(Exception): ...

def evaluate_governance(df: pd.DataFrame,
                        enforce_types: Iterable[str],
                        cert_registry: Dict[str, datetime],
                        max_age_days: int,
                        treat_unknown_as_expired: bool) -> None:
    """Raise exceptions if governance violations are found."""
    violations = []

    # Missing labels
    df_missing = df[
        (df["itemType"].isin(set(enforce_types))) &
        (df["sensitivityLabelId"].isna() | (df["sensitivityLabelId"] == ""))
    ]
    if not df_missing.empty:
        samples = df_missing[["domain","workspaceName","itemType","itemName"]].head(25).to_dict(orient="records")
        msg = f"{len(df_missing)} item(s) missing required sensitivity labels."
        msg += f"\nSample (first 25): {json.dumps(samples, ensure_ascii=False, indent=2)}"
        violations.append(("MissingLabelError", msg))

    # Expired certifications
    now = datetime.now(timezone.utc)
    df_cert = df[df["endorsement"].str.lower() == "certified"]
    expired_rows = []
    for _, r in df_cert.iterrows():
        aid = (r["artifactId"] or "").lower()
        attested_on = cert_registry.get(aid)
        if attested_on is None:
            if treat_unknown_as_expired:
                expired_rows.append((r, "unknown attestation date"))
            continue
        age_days = (now - attested_on).days
        if age_days > max_age_days:
            expired_rows.append((r, f"age={age_days}d > {max_age_days}d"))

    if expired_rows:
        sample = [
            dict(domain=row["domain"],
                 workspace=row["workspaceName"],
                 itemType=row["itemType"],
                 itemName=row["itemName"],
                 artifactId=row["artifactId"])
            for (row, _) in expired_rows[:25]
        ]
        msg = f"{len(expired_rows)} certified item(s) exceed certification max age ({max_age_days} days)."
        msg += f"\nSample (first 25): {json.dumps(sample, ensure_ascii=False, indent=2)}"
        violations.append(("ExpiredCertificationError", msg))

    # Raise combined
    if violations:
        # Prefer raising the first error type with details; include others below it
        primary_type, primary_msg = violations[0]
        extra = "\n\n".join([f"[{t}] {m}" for t, m in violations[1:]])
        full_msg = primary_msg + (("\n\n" + extra) if extra else "")
        if primary_type == "MissingLabelError":
            raise MissingLabelError(full_msg)
        else:
            raise ExpiredCertificationError(full_msg)


# -------------------------
# WORKSPACE DISCOVERY
# -------------------------

def discover_workspaces_via_domains(fabric_token: str) -> Tuple[Dict[str, str], List[str]]:
    """
    Returns:
      - wsid_to_domain: workspaceId -> domainName
      - workspace_ids: list of workspaceIds
    """
    domains = list_domains(fabric_token)
    if not domains:
        log.warning("No domains returned (is Domains API enabled for your principal?).")
    wsid_to_domain = {}
    for dom in domains:
        dom_id = dom.get("id") or dom.get("domainId")
        dom_name = dom.get("displayName") or dom.get("name") or dom_id
        if not dom_id:
            continue
        wss = list_domain_workspaces(fabric_token, dom_id)
        for w in wss:
            wid = w.get("id") or w.get("workspaceId")
            if wid:
                wsid_to_domain[wid] = dom_name
    workspace_ids = list(wsid_to_domain.keys())
    return wsid_to_domain, workspace_ids

def fallback_discover_all_workspaces(pbi_token: str) -> List[str]:
    """
    Optional fallback if Domains Admin API isn't available:
    You can feed *all* workspace IDs to the scanner by using other Admin listing APIs.
    For brevity, we assume you maintain your own list or call GetGroupsAsAdmin.

    This stub returns an empty list to avoid fetching large tenants unintentionally.
    """
    log.warning("Fallback workspace discovery not implemented in this sample. Provide your workspace list here.")
    return []


# -------------------------
# MAIN
# -------------------------

def main():
    # Acquire tokens
    log.info("Acquiring tokens...")
    fabric_token = get_token(SCOPE_FABRIC)   # Fabric Admin (domains)
    pbi_token    = get_token(SCOPE_POWERBI)  # Power BI Admin (scanner)

    # Discover workspaces via Domains API
    log.info("Discovering domains and workspaces...")
    wsid_to_domain, workspace_ids = discover_workspaces_via_domains(fabric_token)

    if not workspace_ids:
        # Fallback: (optional) discover all workspaces without domains (or supply a list)
        workspace_ids = fallback_discover_all_workspaces(pbi_token)

    if not workspace_ids:
        log.warning("No workspaces discovered. Exiting.")
        return

    # Run scanner in batches
    log.info(f"Scanning {len(workspace_ids)} workspace(s) in batches of {SCANNER_BATCH_SIZE}...")
    all_records = []
    for i in range(0, len(workspace_ids), SCANNER_BATCH_SIZE):
        batch = workspace_ids[i:i+SCANNER_BATCH_SIZE]
        scan_id = trigger_scan(pbi_token, batch)
        log.info(f"Triggered scan {scan_id} for {len(batch)} workspace(s). Waiting...")
        wait_for_scan(pbi_token, scan_id)
        result = get_scan_result(pbi_token, scan_id)
        df_batch = flatten_scan_result(result, wsid_to_domain)
        all_records.append(df_batch)
        log.info(f"Batch {i//SCANNER_BATCH_SIZE + 1}: {len(df_batch)} artifacts inventoried.")

    df = pd.concat(all_records, ignore_index=True) if all_records else pd.DataFrame(columns=[
        "domain","workspaceId","workspaceName","itemType","artifactId","itemName","endorsement","certifiedBy","sensitivityLabelId"
    ])

    log.info(f"Total artifacts inventoried: {len(df)}")

    # Persist inventory (optional)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_csv = f"fabric_endorsement_inventory_{ts}.csv"
    df.to_csv(out_csv, index=False, encoding="utf-8")
    log.info(f"Wrote inventory CSV: {out_csv}")

    # Governance checks
    cert_registry = load_cert_registry(CERT_REGISTRY_PATH) if CERT_REGISTRY_PATH else {}
    evaluate_governance(
        df=df,
        enforce_types=ENFORCE_LABEL_ITEM_TYPES,
        cert_registry=cert_registry,
        max_age_days=CERT_MAX_AGE_DAYS,
        treat_unknown_as_expired=TREAT_UNKNOWN_ATTESTATION_AS_EXPIRED
    )

    log.info("Governance checks passed: no violations detected.")

if __name__ == "__main__":
    try:
        main()
    except MissingLabelError as e:
        log.error(str(e))
        # Non-zero exit to fail pipelines/Actions
        sys.exit(2)
    except ExpiredCertificationError as e:
        log.error(str(e))
        sys.exit(3)
    except Exception as e:
        log.exception("Unhandled error")
        sys.exit(1)


# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "synapse_pyspark"
# META }
