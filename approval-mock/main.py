"""Dev/test stand-in for a real approval system (Slack/Teams/ticketing).
Approves everything except actions whose name contains "large" — just
enough logic to demonstrate both the approved and denied paths through
Aegis's approval-workflow resolver without needing a real integration.

Verifies the inbound request signature and signs its own response the
same way a real integration would — see aegis-server/app/approval.py for
the matching client-side implementation and why: an unsigned response
lets anything able to answer on this URL (compromised service, MITM on
http://) forge an approval."""

import hashlib
import hmac
import json
import os
import time

from fastapi import FastAPI, HTTPException, Request, Response

app = FastAPI(title="Aegis Approval Mock")

# Must match the `approval_webhook_hmac_secret` seeded for the tenant this
# mock is configured as the webhook for (scripts/seed_tenant.py,
# aegis-server/tests/conftest.py). Dev-only default — a real deployment
# sets this via env, same posture as aegis-server's own secrets.
HMAC_SECRET = os.environ.get("APPROVAL_WEBHOOK_HMAC_SECRET", "dev-approval-webhook-secret")
# Requests older than this are rejected even with a valid signature, so a
# captured request can't be replayed indefinitely.
MAX_REQUEST_AGE_SECONDS = 300


def _sign(material: bytes) -> str:
    return hmac.new(HMAC_SECRET.encode(), material, hashlib.sha256).hexdigest()


@app.post("/approve")
async def approve(request: Request) -> Response:
    body = await request.body()
    signature = request.headers.get("X-Aegis-Signature")
    if not signature or not hmac.compare_digest(_sign(body), signature):
        raise HTTPException(status_code=401, detail="invalid or missing request signature")

    payload = json.loads(body)
    request_id = payload.get("request_id")
    timestamp = payload.get("timestamp")
    if not request_id or not isinstance(timestamp, int):
        raise HTTPException(status_code=400, detail="missing request_id or timestamp")
    if abs(time.time() - timestamp) > MAX_REQUEST_AGE_SECONDS:
        raise HTTPException(status_code=400, detail="request timestamp outside allowed window")

    action = payload.get("action", "")
    if "large" in action.lower():
        decision = {
            "approved": False,
            "approver": None,
            "reason": "mock: actions named 'large_*' are always denied",
        }
    else:
        decision = {
            "approved": True,
            "approver": "mock-approver",
            "reason": "auto-approved by mock",
        }

    # Echoing request_id back binds this response to that specific request
    # — see the signature computation below and the matching check on the
    # aegis-server side, which rejects a response for a different request.
    resp_payload = {**decision, "request_id": request_id}
    resp_body = json.dumps(resp_payload, sort_keys=True, separators=(",", ":")).encode()
    resp_signature = _sign(f"{request_id}.".encode() + resp_body)
    return Response(
        content=resp_body,
        media_type="application/json",
        headers={"X-Aegis-Signature": resp_signature},
    )
