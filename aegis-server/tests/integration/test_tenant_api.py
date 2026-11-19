"""The tenant admin API, and the identity settings it controls, end to end."""

import uuid

import httpx

from tests.integration.conftest import (
    BASE_URL,
    ISSUER_HUMAN,
    ISSUER_SERVICE,
    SAMPLE_POLICY,
    admin_headers,
    evaluate_headers,
    human_token,
    mint,
    service_token,
)

JWKS = "http://jwks-mock:80/jwks.json"


def put_tenant(tenant_id: str, **overrides) -> httpx.Response:
    body = {
        "jwks_uri_human": JWKS,
        "jwks_uri_service": JWKS,
        "expected_issuer_human": ISSUER_HUMAN,
        "expected_issuer_service": ISSUER_SERVICE,
        **overrides,
    }
    return httpx.put(
        f"{BASE_URL}/admin/tenants/{tenant_id}", headers=admin_headers(), json=body, timeout=10.0
    )


def put_policy(tenant_id: str) -> None:
    resp = httpx.put(
        f"{BASE_URL}/admin/policies/{tenant_id}",
        headers=admin_headers(),
        json={"policy_script": SAMPLE_POLICY},
        timeout=10.0,
    )
    resp.raise_for_status()


def evaluate(tenant_id: str, human: str, service: str) -> dict:
    resp = httpx.post(
        f"{BASE_URL}/v1/evaluate",
        headers=evaluate_headers(human, service, tenant_id=tenant_id),
        json={
            "execution_principal": {"session_id": "s", "workflow_id": "w"},
            "action": "execute_query",
            "resource": {"type": "database_table", "urn": "urn:x"},
            "context": {"tool_name": "sql"},
        },
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()


def new_tenant() -> str:
    return f"t-{uuid.uuid4().hex[:8]}"


def test_tenant_api_requires_admin_auth():
    resp = httpx.put(f"{BASE_URL}/admin/tenants/x", json={}, timeout=10.0)
    assert resp.status_code in (401, 422)


def test_create_read_and_secret_is_write_only():
    tid = new_tenant()
    resp = put_tenant(
        tid, approval_webhook_url="http://approval-mock:8090/approve", approval_webhook_hmac_secret="s" * 32
    )
    assert resp.status_code == 200, resp.text
    view = httpx.get(f"{BASE_URL}/admin/tenants/{tid}", headers=admin_headers(), timeout=10.0).json()
    assert view["approval_webhook_secret_set"] is True
    assert "s" * 32 not in str(view)
    assert view["single_use_tokens"] is True

    # Omitting the secret on a later PUT keeps it.
    resp = put_tenant(tid, approval_webhook_url="http://approval-mock:8090/approve", rate_limit_per_minute=5)
    assert resp.status_code == 200 and resp.json()["approval_webhook_secret_set"] is True


def test_webhook_without_secret_is_refused():
    resp = put_tenant(new_tenant(), approval_webhook_url="http://approval-mock:8090/approve")
    assert resp.status_code == 422
    assert "unsigned" in resp.text


def test_missing_issuer_is_refused():
    body = {"jwks_uri_human": JWKS, "jwks_uri_service": JWKS, "expected_issuer_human": ISSUER_HUMAN}
    resp = httpx.put(
        f"{BASE_URL}/admin/tenants/{new_tenant()}", headers=admin_headers(), json=body, timeout=10.0
    )
    assert resp.status_code == 422


def test_reusable_tokens_mode_allows_reuse():
    tid = new_tenant()
    assert put_tenant(tid, single_use_tokens=False).status_code == 200
    put_policy(tid)
    human, service = human_token("Analyst"), service_token()
    assert evaluate(tid, human, service)["decision"] == "ALLOW"
    assert evaluate(tid, human, service)["decision"] == "ALLOW"


def test_single_use_mode_refuses_reuse():
    tid = new_tenant()
    assert put_tenant(tid).status_code == 200
    put_policy(tid)
    human, service = human_token("Analyst"), service_token()
    assert evaluate(tid, human, service)["decision"] == "ALLOW"
    assert evaluate(tid, human, service)["decision"] == "DENY"


def test_audience_is_enforced_when_configured():
    tid = new_tenant()
    assert put_tenant(tid, expected_audience_human="aegis-demo").status_code == 200
    put_policy(tid)
    wrong = mint("alice", iss=ISSUER_HUMAN, role="Analyst", aud="another-app")
    right = mint("alice", iss=ISSUER_HUMAN, role="Analyst", aud="aegis-demo")
    assert evaluate(tid, wrong, service_token())["decision"] == "DENY"
    assert evaluate(tid, right, service_token())["decision"] == "ALLOW"


def test_ready_reports_every_dependency():
    body = httpx.get(f"{BASE_URL}/ready", timeout=10.0).json()
    assert body == {"status": "ok", "checks": {"postgres": "ok", "redis": "ok", "cedar_sidecar": "ok"}}
