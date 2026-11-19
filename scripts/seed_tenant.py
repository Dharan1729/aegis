"""Seeds the demo tenant "acme" through the admin API: tenant config, Cedar
schema, then policy. Every step goes through the same validation an
operator's request would, and the policy write is pushed to every
aegis-server replica at once (no restart, no TTL wait).

Needs the docker-compose stack running and dev keys generated
(scripts/gen_test_keys.py).
"""

import json
import os
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mint_token import mint

AEGIS_SERVER_URL = os.environ.get("AEGIS_URL", "http://localhost:8000")
# Must match app/config.py's admin_oidc_issuer/admin_oidc_required_scope defaults.
ADMIN_ISSUER = "https://idp.aegis-admin.test"
ADMIN_REQUIRED_SCOPE = "aegis:admin"

TENANT_ID = "acme"
EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
TENANT_CONFIG = json.loads((EXAMPLES / "tenant.json").read_text())
SAMPLE_POLICY = (EXAMPLES / "policies" / "acme.cedar").read_text()
# Cedar's JSON schema format. Matches the entities aegis-server builds:
# Human (role, department), Resource (type), Agent (agent_name).
CEDAR_SCHEMA = (EXAMPLES / "policies" / "acme.schema.json").read_text()


def _put(client: httpx.Client, path: str, body: dict) -> dict:
    resp = client.put(path, json=body)
    if resp.status_code != 200:
        sys.exit(f"PUT {path} failed ({resp.status_code}): {resp.text}")
    return resp.json()


def main() -> None:
    admin_token = mint("seed-script-admin", iss=ADMIN_ISSUER, scope=ADMIN_REQUIRED_SCOPE)
    with httpx.Client(
        base_url=AEGIS_SERVER_URL, headers={"Authorization": f"Bearer {admin_token}"}, timeout=10.0
    ) as client:
        _put(client, f"/admin/tenants/{TENANT_ID}", TENANT_CONFIG)
        print(f"tenant '{TENANT_ID}': identity and approval webhook configured")
        _put(client, f"/admin/schema/{TENANT_ID}", {"cedar_schema": CEDAR_SCHEMA})
        print(f"tenant '{TENANT_ID}': Cedar schema saved; policies are now schema-checked")
        policy = _put(client, f"/admin/policies/{TENANT_ID}", {"policy_script": SAMPLE_POLICY})
        print(f"tenant '{TENANT_ID}': policy {policy['policy_version']} live on every replica")


if __name__ == "__main__":
    main()
