"""End-to-end smoke test against the docker-compose stack.

Verifies: dual-JWT principal validation via the jwks-mock JWKS, tenant
issuer cross-check, Redis-backed nonce replay rejection, the Redis-backed
policy cache (pushed by scripts/seed_tenant.py, no restart needed), the
real Cedar sidecar's authorization decision plus policy-annotation-derived
mask_fields/approval_required, and the ALLOW/DENY shape of POST /v1/evaluate.
"""

import os
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mint_token import mint

BASE_URL = os.environ.get("AEGIS_URL", "http://localhost:8000")
ISSUER_HUMAN = "https://idp.acme.test/human"
ISSUER_SERVICE = "https://idp.acme.test/service"


def evaluate_raw(human_token: str, service_token: str) -> httpx.Response:
    return httpx.post(
        f"{BASE_URL}/v1/evaluate",
        headers={
            "X-Aegis-Tenant-Id": "acme",
            "X-Aegis-User-Token": human_token,
            "Authorization": f"Bearer {service_token}",
        },
        json={
            "execution_principal": {"session_id": "sess_9981", "workflow_id": "wf_112"},
            "action": "execute_query",
            "resource": {
                "type": "database_table",
                "urn": "urn:enterprise:db:finance:q3_revenue",
            },
            "context": {"tool_name": "sql_agent_tool"},
        },
        timeout=10.0,
    )


def evaluate(human_role: str, human_iss: str = ISSUER_HUMAN) -> httpx.Response:
    human_token = mint("alice", role=human_role, department="Finance", iss=human_iss)
    service_token = mint("agent-1", agent_name="sql_agent", iss=ISSUER_SERVICE)
    return evaluate_raw(human_token, service_token)


def main() -> None:
    print("--- Analyst querying q3_revenue (ALLOW + annotation-derived policy) ---")
    resp = evaluate("Analyst")
    resp.raise_for_status()
    allow_result = resp.json()
    print(allow_result)
    assert allow_result["decision"] == "ALLOW", f"expected ALLOW, got {allow_result}"
    assert set(allow_result["execution_policy"]["mask_fields"]) == {"ssn", "compensation"}, (
        "mask_fields should come from the Cedar policy's @mask_fields annotation, "
        f"got {allow_result['execution_policy']}"
    )
    assert allow_result["execution_policy"]["approval_required"] is False

    print("\n--- Junior Analyst querying q3_revenue (default-deny) ---")
    resp = evaluate("Junior Analyst")
    resp.raise_for_status()
    deny_result = resp.json()
    print(deny_result)
    assert deny_result["decision"] == "DENY", f"expected DENY, got {deny_result}"
    assert deny_result["graceful_rejection_message"], "DENY must carry a graceful_rejection_message"

    print("\n--- Analyst with wrong human-token issuer (fail-closed DENY) ---")
    resp = evaluate("Analyst", human_iss="https://evil.example/human")
    resp.raise_for_status()
    wrong_iss_result = resp.json()
    print(wrong_iss_result)
    assert wrong_iss_result["decision"] == "DENY", f"expected fail-closed DENY, got {wrong_iss_result}"

    print("\n--- Nonce replay: same token pair sent twice ---")
    human_token = mint("alice", role="Analyst", department="Finance", iss=ISSUER_HUMAN)
    service_token = mint("agent-1", agent_name="sql_agent", iss=ISSUER_SERVICE)
    first = evaluate_raw(human_token, service_token)
    first.raise_for_status()
    first_result = first.json()
    print("first use:", first_result)
    assert first_result["decision"] == "ALLOW"

    second = evaluate_raw(human_token, service_token)
    second.raise_for_status()
    second_result = second.json()
    print("replayed use:", second_result)
    assert second_result["decision"] == "DENY", "replayed nonce must be rejected"
    assert "unable to verify" in second_result["graceful_rejection_message"]

    print("\nALL SMOKE TESTS PASSED")


if __name__ == "__main__":
    main()
