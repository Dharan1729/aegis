"""Integration test fixtures. These tests run against the real
docker-compose stack (aegis-server, cedar-sidecar, Postgres, Redis,
jwks-mock, approval-mock) on localhost — see .github/workflows/ci.yml,
which brings the stack up before running pytest. This mirrors exactly how
the system has been manually verified throughout development; it is not
a mocked-out unit-test fiction of the real request path.

Tests use their own tenant ("pytest-tenant") seeded fresh in a
session-scoped fixture, so they don't depend on (or clobber) the
"acme" tenant scripts/seed_tenant.py sets up for manual/demo use.
"""

import json
import os
import time
import uuid
from pathlib import Path

import asyncpg
import httpx
import jwt
import pytest
import pytest_asyncio
import redis.asyncio as redis

BASE_URL = os.environ.get("AEGIS_URL", "http://localhost:8000")
DSN = os.environ.get("AEGIS_DSN", "postgresql://aegis:aegis@localhost:5432/aegis")
REDIS_URL = os.environ.get("AEGIS_REDIS_URL", "redis://localhost:6380/0")
# Must match app/config.py's admin_oidc_issuer/admin_oidc_required_scope defaults.
ADMIN_ISSUER = "https://idp.aegis-admin.test"
ADMIN_REQUIRED_SCOPE = "aegis:admin"

TENANT_ID = "pytest-tenant"
ISSUER_HUMAN = "https://idp.pytest.test/human"
ISSUER_SERVICE = "https://idp.pytest.test/service"
APPROVAL_WEBHOOK_URL = "http://approval-mock:8090/approve"
# Must match approval-mock's APPROVAL_WEBHOOK_HMAC_SECRET in docker-compose.yml.
APPROVAL_WEBHOOK_HMAC_SECRET = "dev-approval-webhook-secret"

JWKS_DIR = Path(__file__).resolve().parents[3] / "dev" / "jwks"
PRIVATE_KEY = (JWKS_DIR / "private_key.pem").read_text()
KID = "dev-key-1"

SAMPLE_POLICY = """
@mask_fields("ssn,compensation")
@approval_required("false")
permit(
    principal,
    action == Action::"execute_query",
    resource
) when {
    principal.role == "Analyst"
};

@approval_required("true")
@risk_tier("low")
permit(
    principal,
    action == Action::"transfer_funds",
    resource
) when {
    principal.role == "Manager"
};

@approval_required("true")
@risk_tier("medium")
permit(
    principal,
    action == Action::"transfer_medium_funds",
    resource
) when {
    principal.role == "Manager"
};

@approval_required("true")
@risk_tier("high")
permit(
    principal,
    action == Action::"transfer_large_funds",
    resource
) when {
    principal.role == "Manager"
};
"""


def mint(sub: str, ttl_seconds: int = 300, iss: str | None = None, **extra_claims: str) -> str:
    now = int(time.time())
    claims = {
        "sub": sub,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
        **extra_claims,
    }
    if iss:
        claims["iss"] = iss
    return jwt.encode(claims, PRIVATE_KEY, algorithm="RS256", headers={"kid": KID})


def human_token(role: str, iss: str = ISSUER_HUMAN, **extra: str) -> str:
    return mint("pytest-human", role=role, department="Testing", iss=iss, **extra)


def service_token(iss: str = ISSUER_SERVICE, **extra: str) -> str:
    return mint("pytest-agent", agent_name="pytest_agent", iss=iss, **extra)


def evaluate_headers(human_tok: str, service_tok: str, tenant_id: str = TENANT_ID) -> dict:
    return {
        "X-Aegis-Tenant-Id": tenant_id,
        "X-Aegis-User-Token": human_tok,
        "Authorization": f"Bearer {service_tok}",
    }


def admin_token(iss: str = ADMIN_ISSUER, scope: str = ADMIN_REQUIRED_SCOPE, **extra: str) -> str:
    return mint("pytest-admin", iss=iss, scope=scope, **extra)


def admin_headers() -> dict:
    return {"Authorization": f"Bearer {admin_token()}", "Content-Type": "application/json"}


@pytest_asyncio.fixture(scope="session", autouse=True)
async def seeded_tenant():
    """Seeds the pytest tenant once per test session, the same way
    scripts/seed_tenant.py seeds "acme" for manual use — Postgres row,
    Redis push, and a real Cedar schema saved through the admin API."""
    conn = await asyncpg.connect(DSN)
    try:
        await conn.execute(
            """
            INSERT INTO tenant_configs
                (tenant_id, jwks_uri_human, jwks_uri_service,
                 expected_issuer_human, expected_issuer_service, rate_limit_per_minute,
                 approval_webhook_url, approval_webhook_hmac_secret)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (tenant_id) DO UPDATE
                SET jwks_uri_human = EXCLUDED.jwks_uri_human,
                    jwks_uri_service = EXCLUDED.jwks_uri_service,
                    expected_issuer_human = EXCLUDED.expected_issuer_human,
                    expected_issuer_service = EXCLUDED.expected_issuer_service,
                    rate_limit_per_minute = EXCLUDED.rate_limit_per_minute,
                    approval_webhook_url = EXCLUDED.approval_webhook_url,
                    approval_webhook_hmac_secret = EXCLUDED.approval_webhook_hmac_secret
            """,
            TENANT_ID,
            "http://jwks-mock:80/jwks.json",
            "http://jwks-mock:80/jwks.json",
            ISSUER_HUMAN,
            ISSUER_SERVICE,
            600,
            APPROVAL_WEBHOOK_URL,
            APPROVAL_WEBHOOK_HMAC_SECRET,
        )
        await conn.execute(
            """
            INSERT INTO tenant_policies (tenant_id, policy_script, updated_at)
            VALUES ($1, $2, now())
            ON CONFLICT (tenant_id) DO UPDATE
                SET policy_script = EXCLUDED.policy_script, updated_at = now()
            """,
            TENANT_ID,
            SAMPLE_POLICY,
        )
    finally:
        await conn.close()

    r = redis.from_url(REDIS_URL, decode_responses=True)
    try:
        await r.set(
            f"aegis:policy:{TENANT_ID}",
            json.dumps({"policy_script": SAMPLE_POLICY, "policy_version": "pytest-seed"}),
            ex=300,
        )
        await r.publish("aegis:policy_updates", TENANT_ID)
    finally:
        await r.aclose()

    cedar_schema = json.dumps(
        {
            "": {
                "entityTypes": {
                    "Human": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "role": {"type": "String"},
                                "department": {"type": "String"},
                            },
                        }
                    },
                    "Resource": {"shape": {"type": "Record", "attributes": {"type": {"type": "String"}}}},
                    "Agent": {
                        "shape": {
                            "type": "Record",
                            "attributes": {"agent_name": {"type": "String"}},
                        }
                    },
                },
                "actions": {
                    name: {
                        "appliesTo": {
                            "principalTypes": ["Human"],
                            "resourceTypes": ["Resource"],
                            "context": {
                                "type": "Record",
                                "attributes": {
                                    "agent_id": {"type": "String"},
                                    "agent": {"type": "Entity", "name": "Agent"},
                                    "session_id": {"type": "String"},
                                    "workflow_id": {"type": "String"},
                                    "tool_name": {"type": "String", "required": False},
                                },
                            },
                        }
                    }
                    for name in [
                        "execute_query",
                        "transfer_funds",
                        "transfer_medium_funds",
                        "transfer_large_funds",
                    ]
                },
            }
        }
    )

    async with httpx.AsyncClient() as client:
        resp = await client.put(
            f"{BASE_URL}/admin/schema/{TENANT_ID}",
            headers=admin_headers(),
            json={"cedar_schema": cedar_schema},
            timeout=10.0,
        )
        resp.raise_for_status()

    yield TENANT_ID


@pytest.fixture
def base_url() -> str:
    return BASE_URL
