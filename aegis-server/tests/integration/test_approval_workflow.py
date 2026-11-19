"""Integration tests for the approval-workflow resolver and risk-tiered
auto-approval, against the live stack (including the real approval-mock
service, which denies any action with "large" in its name).

Also covers the signed request/response round trip in app/approval.py
directly (not just through /v1/evaluate), including adversarial proof
that a forged/unsigned response is rejected rather than trusted (see
docs/guide/approvals.md)."""

import asyncio
import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

from app.approval import resolve_approval
from tests.integration.conftest import (
    APPROVAL_WEBHOOK_HMAC_SECRET,
    evaluate_headers,
    human_token,
    service_token,
)


def call(base_url, action):
    h = human_token("Manager")
    s = service_token()
    body = {
        "execution_principal": {"session_id": "sess_approval", "workflow_id": "wf_approval"},
        "action": action,
        "resource": {"type": "account", "urn": f"urn:x:{action}"},
        "context": {"tool_name": action},
    }
    return httpx.post(f"{base_url}/v1/evaluate", headers=evaluate_headers(h, s), json=body, timeout=10.0)


def test_low_risk_action_is_auto_approved_without_hitting_webhook(base_url):
    resp = call(base_url, "transfer_funds")
    body = resp.json()
    assert body["decision"] == "ALLOW"
    assert body["execution_policy"]["approval_required"] is True
    assert body["execution_policy"]["risk_tier"] == "low"
    assert body["execution_policy"]["approved_by"] == "auto (low risk)"


def test_medium_risk_action_is_escalated_and_approved_via_signed_round_trip(base_url):
    """The one seeded action that actually completes a genuine signed
    request -> approval-mock -> signed response round trip (transfer_funds
    never reaches the webhook at all; transfer_large_funds reaches it but
    is always denied) — proves the happy path works, not just the
    fail-closed paths below."""
    resp = call(base_url, "transfer_medium_funds")
    body = resp.json()
    assert body["decision"] == "ALLOW"
    assert body["execution_policy"]["risk_tier"] == "medium"
    assert body["execution_policy"]["approved_by"] == "mock-approver"


def test_high_risk_action_is_escalated_and_denied_by_mock(base_url):
    resp = call(base_url, "transfer_large_funds")
    body = resp.json()
    assert body["decision"] == "DENY"
    assert "requires approval that was not granted" in body["graceful_rejection_message"]
    assert "large" in body["graceful_rejection_message"]


def test_webhook_configured_without_secret_fails_closed():
    result = asyncio.run(resolve_approval("http://localhost:8090/approve", None, {"action": "whatever"}))
    assert result.approved is False
    assert "without an HMAC secret" in result.reason


def test_wrong_secret_is_rejected_by_the_real_mock_fail_closed():
    """approval-mock itself rejects an incorrectly-signed request with
    401 — proves request-side authentication actually works, not just
    that our own client thinks it signed something."""
    result = asyncio.run(
        resolve_approval(
            "http://localhost:8090/approve",
            "definitely-the-wrong-secret",
            {"tenant_id": "t", "action": "transfer_medium_funds", "resource_urn": "urn:x:1"},
        )
    )
    assert result.approved is False
    assert "approval resolver failed" in result.reason


class _UnsignedApprovalHandler(BaseHTTPRequestHandler):
    """A rogue webhook that returns a plausible, well-formed 'approved'
    body but never signs it — simulates a MITM or compromised service
    answering on the configured URL without knowing the shared secret."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        request_body = json.loads(self.rfile.read(length))
        body = json.dumps(
            {
                "approved": True,
                "approver": "attacker",
                "reason": "forged",
                "request_id": request_body.get("request_id"),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        # Deliberately no X-Aegis-Signature header at all.
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # keep test output quiet


class _WrongSignatureApprovalHandler(BaseHTTPRequestHandler):
    """A rogue webhook that signs its response, but with a secret the
    real tenant never configured — simulates an attacker who can guess
    the response *shape* but not the actual shared secret."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        request_body = json.loads(self.rfile.read(length))
        resp_payload = {
            "approved": True,
            "approver": "attacker",
            "reason": "forged",
            "request_id": request_body.get("request_id"),
        }
        body = json.dumps(resp_payload, sort_keys=True, separators=(",", ":")).encode()
        request_id = request_body.get("request_id", "")
        forged_signature = hmac.new(
            b"attacker-guessed-secret", f"{request_id}.".encode() + body, hashlib.sha256
        ).hexdigest()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Aegis-Signature", forged_signature)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def rogue_server(request):
    handler = request.param
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/approve"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.parametrize("rogue_server", [_UnsignedApprovalHandler], indirect=True)
def test_unsigned_forged_response_is_rejected_not_trusted(rogue_server):
    result = asyncio.run(
        resolve_approval(
            rogue_server,
            APPROVAL_WEBHOOK_HMAC_SECRET,
            {"tenant_id": "t", "action": "transfer_medium_funds", "resource_urn": "urn:x:1"},
        )
    )
    assert result.approved is False
    assert "not signed" in result.reason


@pytest.mark.parametrize("rogue_server", [_WrongSignatureApprovalHandler], indirect=True)
def test_response_signed_with_wrong_secret_is_rejected_not_trusted(rogue_server):
    result = asyncio.run(
        resolve_approval(
            rogue_server,
            APPROVAL_WEBHOOK_HMAC_SECRET,
            {"tenant_id": "t", "action": "transfer_medium_funds", "resource_urn": "urn:x:1"},
        )
    )
    assert result.approved is False
    assert "signature invalid" in result.reason
