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

import requests
from datetime import datetime, timezone
from auth import get_token

BASE_URL = "https://api.fabric.microsoft.com/v1"


def inventory_endorsements():
    """Inventory endorsements across all domains and validate them.

    Raises:
        RuntimeError: If any artifact is missing a label or has an expired certification.
    """
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}

    res = requests.get(f"{BASE_URL}/admin/domains", headers=headers)
    res.raise_for_status()
    domains = res.json().get("value", [])

    errors = []
    for domain in domains:
        domain_id = domain.get("id")
        domain_name = domain.get("name", domain_id)
        artifacts_url = f"{BASE_URL}/admin/domains/{domain_id}/artifacts"
        art_res = requests.get(artifacts_url, headers=headers)
        art_res.raise_for_status()
        artifacts = art_res.json().get("value", [])

        for artifact in artifacts:
            artifact_id = artifact.get("id")
            artifact_name = artifact.get("name", artifact_id)
            endorsement = artifact.get("endorsement", {})
            label = endorsement.get("label")
            if not label:
                errors.append(f"{domain_name}/{artifact_name} has no endorsement label")
                continue
            certification = endorsement.get("certification", {})
            expiry = certification.get("expiresOn")
            if expiry:
                try:
                    expires_on = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                    if expires_on < datetime.now(timezone.utc):
                        errors.append(
                            f"{domain_name}/{artifact_name} certification expired {expiry}"
                        )
                except ValueError:
                    errors.append(
                        f"{domain_name}/{artifact_name} has invalid certification expiry {expiry}"
                    )

    if errors:
        raise RuntimeError("Endorsement validation failed:\n" + "\n".join(errors))
    print("All endorsements have valid labels and certifications.")


if __name__ == "__main__":
    inventory_endorsements()

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "synapse_pyspark"
# META }
