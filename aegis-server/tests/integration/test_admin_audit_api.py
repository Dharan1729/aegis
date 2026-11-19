"""Integration tests for the read-only GET /admin/audit/{tenant_id}
endpoint (built for the aegis-console decision-explainer view) against
the live stack. Auth (401/403/expired/wrong-issuer/missing-scope) is
already thoroughly covered in test_admin_api.py against other /admin/*
routes sharing the exact same require_admin_auth dependency — this file
focuses on the audit query logic itself: filtering, pagination, and
that real /v1/evaluate decisions actually show up."""

import uuid

import httpx

from tests.integration.conftest import TENANT_ID, admin_headers, evaluate_headers, human_token, service_token


def evaluate(base_url, action):
    h = human_token("Analyst")
    s = service_token()
    body = {
        "execution_principal": {"session_id": "sess_audit_api", "workflow_id": "wf_audit_api"},
        "action": action,
        "resource": {"type": "account", "urn": f"urn:x:{action}"},
        "context": {"tool_name": action},
    }
    return httpx.post(f"{base_url}/v1/evaluate", headers=evaluate_headers(h, s), json=body, timeout=10.0)


def get_audit(base_url, **params):
    return httpx.get(
        f"{base_url}/admin/audit/{TENANT_ID}", headers=admin_headers(), params=params, timeout=10.0
    )


def test_recorded_decisions_show_up_in_the_audit_log(base_url):
    # Analyst has no permit rule for an unrecognized action — Cedar's
    # default-deny means this reliably produces a DENY, and the unique
    # action name isolates this test's rows from every other test's
    # traffic against the same shared session-scoped tenant.
    action = f"audit_api_test_{uuid.uuid4().hex[:8]}"
    eval_resp = evaluate(base_url, action)
    assert eval_resp.json()["decision"] == "DENY"

    audit_resp = get_audit(base_url, action=action)
    assert audit_resp.status_code == 200
    entries = audit_resp.json()
    assert len(entries) == 1
    assert entries[0]["action"] == action
    assert entries[0]["decision"] == "DENY"
    assert entries[0]["tenant_id"] == TENANT_ID
    assert entries[0]["resource_urn"] == f"urn:x:{action}"


def test_decision_filter_narrows_results(base_url):
    action = f"audit_api_filter_test_{uuid.uuid4().hex[:8]}"
    evaluate(base_url, action)  # DENY (Analyst has no rule for this action)

    deny_only = get_audit(base_url, action=action, decision="DENY").json()
    allow_only = get_audit(base_url, action=action, decision="ALLOW").json()
    assert len(deny_only) == 1
    assert len(allow_only) == 0


def test_pagination_limit_and_offset(base_url):
    action = f"audit_api_page_test_{uuid.uuid4().hex[:8]}"
    for _ in range(3):
        evaluate(base_url, action)

    page1 = get_audit(base_url, action=action, limit=2, offset=0).json()
    page2 = get_audit(base_url, action=action, limit=2, offset=2).json()
    assert len(page1) == 2
    assert len(page2) == 1
    # Most-recent-first, non-overlapping pages.
    ids_page1 = {e["evaluation_id"] for e in page1}
    ids_page2 = {e["evaluation_id"] for e in page2}
    assert ids_page1.isdisjoint(ids_page2)


def test_unknown_action_filter_returns_empty_not_error(base_url):
    resp = get_audit(base_url, action=f"definitely-never-happened-{uuid.uuid4().hex[:8]}")
    assert resp.status_code == 200
    assert resp.json() == []
