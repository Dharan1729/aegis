"""Integration tests for the Policy Admin API against the live stack."""

import httpx

from tests.integration.conftest import BASE_URL, TENANT_ID, admin_headers, admin_token


def test_missing_admin_token_rejected():
    resp = httpx.get(f"{BASE_URL}/admin/policies/{TENANT_ID}", timeout=10.0)
    assert resp.status_code == 422  # FastAPI: required Authorization header absent


def test_garbage_admin_token_rejected():
    resp = httpx.get(
        f"{BASE_URL}/admin/policies/{TENANT_ID}",
        headers={"Authorization": "Bearer not-a-real-jwt"},
        timeout=10.0,
    )
    assert resp.status_code == 401


def test_admin_token_with_wrong_issuer_rejected():
    """Signature is valid (same dev key as everything else) but the `iss`
    claim doesn't match app/config.py's admin_oidc_issuer — proves issuer
    is actually checked, not just signature."""
    resp = httpx.get(
        f"{BASE_URL}/admin/policies/{TENANT_ID}",
        headers={"Authorization": f"Bearer {admin_token(iss='https://not-the-real-admin-idp.test')}"},
        timeout=10.0,
    )
    assert resp.status_code == 401


def test_admin_token_with_null_scope_claim_rejected_not_500():
    """Some OIDC providers emit `"scope": null` (not omitted, not `""`)
    for a token with no granted scopes — `claims.get("scope", "")`'s
    default only applies when the key is absent, so this must be
    explicitly handled or it crashes with an unhandled 500 instead of
    the intended 403."""
    resp = httpx.get(
        f"{BASE_URL}/admin/policies/{TENANT_ID}",
        headers={"Authorization": f"Bearer {admin_token(scope=None)}"},
        timeout=10.0,
    )
    assert resp.status_code == 403


def test_admin_token_without_required_scope_rejected():
    """A validly-signed, correctly-issued token that simply never granted
    the 'aegis:admin' scope must still be rejected — proves this is real
    authorization, not just authentication."""
    resp = httpx.get(
        f"{BASE_URL}/admin/policies/{TENANT_ID}",
        headers={"Authorization": f"Bearer {admin_token(scope='some-other-scope')}"},
        timeout=10.0,
    )
    assert resp.status_code == 403


def test_expired_admin_token_rejected():
    resp = httpx.get(
        f"{BASE_URL}/admin/policies/{TENANT_ID}",
        headers={"Authorization": f"Bearer {admin_token(ttl_seconds=-60)}"},
        timeout=10.0,
    )
    assert resp.status_code == 401


def test_validate_rejects_bad_syntax():
    resp = httpx.post(
        f"{BASE_URL}/admin/policies/validate",
        headers=admin_headers(),
        json={"policy_script": "permit(this is not cedar"},
        timeout=10.0,
    )
    body = resp.json()
    assert body["valid"] is False
    assert body["errors"]


def test_validate_against_schema_catches_undeclared_attribute():
    """Regression test for real Cedar schema validation (not just
    syntax-only parsing) — an attribute the schema never declared must
    be caught."""
    resp = httpx.post(
        f"{BASE_URL}/admin/policies/validate",
        headers=admin_headers(),
        json={
            "policy_script": (
                'permit(principal, action == Action::"execute_query", resource) '
                'when { principal.nonexistent_attribute == "x" };'
            ),
            "tenant_id": TENANT_ID,
        },
        timeout=10.0,
    )
    body = resp.json()
    assert body["schema_checked"] is True
    assert body["valid"] is False


def test_save_and_load_policy_roundtrip():
    # tests/integration/conftest.py's tenant is session-scoped and shared with every
    # other test module — every assertion below runs inside try/finally
    # so a failure here can't leave the tenant on this throwaway policy
    # for the rest of the session (SAMPLE_POLICY's execute_query/
    # transfer_* rules are what test_evaluate_api.py, test_rate_limit.py,
    # and test_approval_workflow.py all depend on).
    from tests.integration.conftest import SAMPLE_POLICY

    policy = (
        'permit(principal, action == Action::"execute_query", resource) '
        'when { principal.role == "TestRoundtripRole" };'
    )
    try:
        put_resp = httpx.put(
            f"{BASE_URL}/admin/policies/{TENANT_ID}",
            headers=admin_headers(),
            json={"policy_script": policy},
            timeout=10.0,
        )
        assert put_resp.status_code == 200

        get_resp = httpx.get(f"{BASE_URL}/admin/policies/{TENANT_ID}", headers=admin_headers(), timeout=10.0)
        assert get_resp.json()["policy_script"] == policy

        history_resp = httpx.get(
            f"{BASE_URL}/admin/policies/{TENANT_ID}/history", headers=admin_headers(), timeout=10.0
        )
        assert len(history_resp.json()) >= 1
    finally:
        restore = httpx.put(
            f"{BASE_URL}/admin/policies/{TENANT_ID}",
            headers=admin_headers(),
            json={"policy_script": SAMPLE_POLICY},
            timeout=10.0,
        )
        assert restore.status_code == 200
