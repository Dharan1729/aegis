"""Integration tests proving the audit hash chain's tamper-evidence
claims are real, not just that the code runs without error — each test
performs the tamper itself and asserts the verifier catches it, then
restores state so it doesn't poison other tests/tenants."""

import sys
import uuid
from pathlib import Path

import asyncpg
import httpx
import pytest

from tests.integration.conftest import DSN, TENANT_ID, evaluate_headers, human_token, service_token

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from app.audit_hash import chain_hash
from app.config import settings


async def _write_one_row(base_url: str) -> None:
    h = human_token("Analyst")
    s = service_token()
    body = {
        "execution_principal": {"session_id": "sess_chain", "workflow_id": "wf_chain"},
        "action": "execute_query",
        "resource": {"type": "database_table", "urn": f"urn:x:chain-{uuid.uuid4().hex[:8]}"},
        "context": {"tool_name": "execute_query"},
    }
    httpx.post(f"{base_url}/v1/evaluate", headers=evaluate_headers(h, s), json=body, timeout=10.0)


async def _verify_chain_intact(tenant_id: str) -> bool:
    conn = await asyncpg.connect(DSN)
    try:
        rows = await conn.fetch(
            """SELECT evaluation_id, timestamp, tenant_id, human_id, agent_id, action,
                      resource_urn, decision, matched_policy, policy_version,
                      evaluation_reason, previous_hash, hash
               FROM audit_ledger WHERE tenant_id = $1 AND hash != 'pre-chain'
               ORDER BY timestamp ASC""",
            tenant_id,
        )
    finally:
        await conn.close()

    if not rows or rows[0]["previous_hash"] is not None:
        return False
    previous_hash = None
    for row in rows:
        if row["previous_hash"] != previous_hash:
            return False
        expected = chain_hash(
            secret=settings.audit_chain_hmac_secret,
            evaluation_id=row["evaluation_id"],
            timestamp=row["timestamp"],
            tenant_id=row["tenant_id"],
            human_id=row["human_id"],
            agent_id=row["agent_id"],
            action=row["action"],
            resource_urn=row["resource_urn"],
            decision=row["decision"],
            matched_policy=row["matched_policy"],
            policy_version=row["policy_version"],
            evaluation_reason=row["evaluation_reason"],
            previous_hash=previous_hash,
        )
        if expected != row["hash"]:
            return False
        previous_hash = row["hash"]
    return True


@pytest.mark.asyncio
async def test_chain_is_intact_after_normal_writes(base_url):
    await _write_one_row(base_url)
    assert await _verify_chain_intact(TENANT_ID) is True


@pytest.mark.asyncio
async def test_editing_a_row_without_the_hmac_secret_breaks_the_chain(base_url):
    """The core tamper-evidence claim: an attacker with DB write access
    but not the app's HMAC secret cannot produce a self-consistent edit."""
    await _write_one_row(base_url)

    conn = await asyncpg.connect(DSN)
    try:
        row = await conn.fetchrow(
            "SELECT evaluation_id, hash, evaluation_reason FROM audit_ledger WHERE tenant_id = $1 "
            "ORDER BY timestamp DESC LIMIT 1",
            TENANT_ID,
        )
        original_hash = row["hash"]
        original_reason = row["evaluation_reason"]
        await conn.execute(
            "UPDATE audit_ledger SET evaluation_reason = 'FORGED BY TEST' WHERE evaluation_id = $1",
            row["evaluation_id"],
        )
        try:
            assert await _verify_chain_intact(TENANT_ID) is False
        finally:
            # Restore exact prior state (reason + hash) so this test tenant's
            # chain is clean for any test that runs after it.
            await conn.execute(
                "UPDATE audit_ledger SET evaluation_reason = $1, hash = $2 WHERE evaluation_id = $3",
                original_reason,
                original_hash,
                row["evaluation_id"],
            )
    finally:
        await conn.close()
