"""Integration test for per-tenant rate limiting against the live stack."""

import asyncpg
import httpx
import pytest

from tests.integration.conftest import DSN, TENANT_ID, evaluate_headers, human_token, service_token


@pytest.mark.asyncio
async def test_exceeding_rate_limit_returns_429(base_url):
    conn = await asyncpg.connect(DSN)
    try:
        await conn.execute(
            "UPDATE tenant_configs SET rate_limit_per_minute = 2 WHERE tenant_id = $1", TENANT_ID
        )
    finally:
        await conn.close()

    try:
        statuses = []
        for i in range(4):
            h = human_token("Analyst")
            s = service_token()
            body = {
                "execution_principal": {"session_id": f"sess_rl_{i}", "workflow_id": "wf_rl"},
                "action": "execute_query",
                "resource": {"type": "database_table", "urn": f"urn:x:rl-{i}"},
                "context": {"tool_name": "execute_query"},
            }
            resp = httpx.post(
                f"{base_url}/v1/evaluate", headers=evaluate_headers(h, s), json=body, timeout=10.0
            )
            statuses.append(resp.status_code)
        assert 429 in statuses, f"expected at least one 429 among {statuses}"
    finally:
        conn = await asyncpg.connect(DSN)
        try:
            await conn.execute(
                "UPDATE tenant_configs SET rate_limit_per_minute = 600 WHERE tenant_id = $1",
                TENANT_ID,
            )
        finally:
            await conn.close()
