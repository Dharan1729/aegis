"""Every outcome Aegis can produce, through the SDK, against the demo stack.

No LLM and no API key: the "tools" are plain functions, and the SDK's Guard
does what every framework adapter does around a real tool call.

    python scripts/gen_test_keys.py
    docker compose up --build -d
    python scripts/seed_tenant.py
    pip install -e ./aegis-sdk
    python examples/quickstart.py
"""

import json
import os
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from aegis import AegisClient, AegisContext, Guard
from mint_token import mint  # dev tokens, signed with dev/jwks/private_key.pem

AEGIS_URL = os.environ.get("AEGIS_URL", "http://localhost:8000")
TENANT = "acme"  # seeded by scripts/seed_tenant.py
HUMAN_ISS, SERVICE_ISS = "https://idp.acme.test/human", "https://idp.acme.test/service"


def context(role: str) -> AegisContext:
    """In production these tokens come from your identity provider: the end
    user's token, and the agent's own service token. The demo tenant uses
    single-use tokens, so every call gets a fresh pair."""
    return AegisContext(
        tenant_id=TENANT,
        human_token=mint("alice", iss=HUMAN_ISS, role=role, department="Finance"),
        service_token=mint("finance-agent", iss=SERVICE_ISS, agent_name="finance_agent"),
        session_id=f"sess-{uuid.uuid4().hex[:6]}",
        workflow_id="quickstart",
    )


# The "tools". In an agent, the model picks these and fills in the arguments.
TOOLS = {
    "execute_query": lambda: [
        {"employee": "Ada", "ssn": "123-45-6789", "compensation": 180000, "team": "Core"}
    ],
    "transfer_funds": lambda: {"status": "sent", "amount": 120},
    "transfer_medium_funds": lambda: {"status": "sent", "amount": 12_000},
    "transfer_large_funds": lambda: {"status": "sent", "amount": 2_000_000},
}


def call(guard: Guard, role: str, tool: str) -> None:
    verdict = guard.check(lambda: context(role), tool)
    if not verdict.allowed:
        print(f"  DENY   {verdict.message}")
        return
    output = guard.finish(verdict, TOOLS[tool]())
    approved = verdict.result.execution_policy.approved_by if verdict.result else None
    extra = f" (approved by {approved})" if approved else ""
    print(f"  ALLOW{extra}\n         {json.dumps(output)}")


def main() -> None:
    guard = Guard(AegisClient(AEGIS_URL))
    steps = [
        ("An analyst queries payroll: allowed, ssn and compensation masked", "Analyst", "execute_query"),
        ("A junior analyst tries the same query: no policy permits it", "Junior Analyst", "execute_query"),
        (
            "A manager makes a small transfer: approval required, low risk, auto-approved",
            "Manager",
            "transfer_funds",
        ),
        ("A medium transfer: sent to the approval webhook, approved", "Manager", "transfer_medium_funds"),
        ("A large transfer: sent to the approval webhook, refused", "Manager", "transfer_large_funds"),
    ]
    for title, role, tool in steps:
        print(f"\n{title}\n  {role} -> {tool}")
        call(guard, role, tool)

    print("\naegis-server unreachable: the guard denies instead of failing open")
    call(Guard(AegisClient("http://localhost:1", timeout=1.0)), "Analyst", "execute_query")


if __name__ == "__main__":
    main()
