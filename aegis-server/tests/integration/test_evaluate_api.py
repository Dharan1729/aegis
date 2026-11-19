"""Integration tests against a live POST /v1/evaluate."""

import httpx
import pytest

from tests.integration.conftest import evaluate_headers, human_token, service_token


def evaluate(base_url, action, resource_type, resource_urn, role, iss_human=None, tool_name=None):
    kwargs = {}
    if iss_human is not None:
        kwargs["iss"] = iss_human
    h = human_token(role, **kwargs) if iss_human is not None else human_token(role)
    s = service_token()
    body = {
        "execution_principal": {"session_id": "sess_test", "workflow_id": "wf_test"},
        "action": action,
        "resource": {"type": resource_type, "urn": resource_urn},
        "context": {"tool_name": tool_name or action},
    }
    return httpx.post(f"{base_url}/v1/evaluate", headers=evaluate_headers(h, s), json=body, timeout=10.0)


class TestBasicAuthorization:
    def test_analyst_allowed(self, base_url):
        resp = evaluate(base_url, "execute_query", "database_table", "urn:x:analyst-allow", "Analyst")
        body = resp.json()
        assert resp.status_code == 200
        assert body["decision"] == "ALLOW"
        assert set(body["execution_policy"]["mask_fields"]) == {"ssn", "compensation"}
        assert body["execution_policy"]["approval_required"] is False

    def test_junior_analyst_denied_default_deny(self, base_url):
        resp = evaluate(base_url, "execute_query", "database_table", "urn:x:junior-deny", "Junior Analyst")
        body = resp.json()
        assert body["decision"] == "DENY"
        assert body["graceful_rejection_message"]

    def test_wrong_issuer_fails_closed(self, base_url):
        resp = evaluate(
            base_url,
            "execute_query",
            "database_table",
            "urn:x:wrong-issuer",
            "Analyst",
            iss_human="https://evil.example/human",
        )
        assert resp.json()["decision"] == "DENY"


class TestReplayProtection:
    def test_replayed_token_pair_is_denied(self, base_url):
        h = human_token("Analyst")
        s = service_token()
        body = {
            "execution_principal": {"session_id": "sess_replay", "workflow_id": "wf_replay"},
            "action": "execute_query",
            "resource": {"type": "database_table", "urn": "urn:x:replay"},
            "context": {"tool_name": "execute_query"},
        }
        headers = evaluate_headers(h, s)
        first = httpx.post(f"{base_url}/v1/evaluate", headers=headers, json=body, timeout=10.0)
        second = httpx.post(f"{base_url}/v1/evaluate", headers=headers, json=body, timeout=10.0)
        assert first.json()["decision"] == "ALLOW"
        assert second.json()["decision"] == "DENY"
        assert "unable to verify" in second.json()["graceful_rejection_message"]


class TestContextCannotOverrideIdentity:
    """Regression test for the security-review finding: caller-supplied
    `context` used to be spread after (and could silently override) the
    server-derived agent_id/session_id/workflow_id sent to Cedar."""

    def test_spoofed_agent_id_in_context_is_ignored(self, base_url):
        h = human_token("Analyst")
        s = service_token()
        body = {
            "execution_principal": {"session_id": "sess_spoof", "workflow_id": "wf_spoof"},
            "action": "execute_query",
            "resource": {"type": "database_table", "urn": "urn:x:spoof-test"},
            "context": {
                "tool_name": "execute_query",
                "agent_id": "some-other-trusted-agent",
                "session_id": "spoofed-session",
                "workflow_id": "spoofed-workflow",
            },
        }
        resp = httpx.post(f"{base_url}/v1/evaluate", headers=evaluate_headers(h, s), json=body, timeout=10.0)
        # This policy doesn't reference context.agent_id, so the request
        # still succeeds — the point of this test is that it succeeds
        # for the *real* agent, not a proof by itself. The authoritative
        # proof lives in tests/test_cedar_client_context.py, which
        # inspects the actual payload built for cedar-sidecar.
        assert resp.json()["decision"] == "ALLOW"


@pytest.mark.parametrize("action", ["transfer_funds", "transfer_large_funds"])
def test_approval_required_actions_need_manager_role(base_url, action):
    resp = evaluate(base_url, action, "account", f"urn:x:{action}", "Analyst")
    # Analyst role doesn't match either transfer policy at all (default deny),
    # independent of the approval workflow.
    assert resp.json()["decision"] == "DENY"
