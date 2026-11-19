import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass

import httpx


@dataclass
class ApprovalDecision:
    approved: bool
    approver: str | None
    reason: str | None


def _sign(secret: str, material: bytes) -> str:
    return hmac.new(secret.encode(), material, hashlib.sha256).hexdigest()


async def _resolve_via_webhook(
    url: str, secret: str, payload: dict, timeout_seconds: float = 5.0
) -> ApprovalDecision:
    # request_id binds this specific request to whatever response comes
    # back — without it, a captured "approved" response for one call could
    # be replayed as the answer to an unrelated one, even with a valid
    # signature over the response body alone.
    request_id = uuid.uuid4().hex
    signed_payload = {**payload, "request_id": request_id, "timestamp": int(time.time())}
    # Signed and sent as-is (json.dumps, not httpx's `json=`) so the exact
    # bytes we sign are the exact bytes on the wire — no risk of the
    # signature covering a different serialization than what the receiver
    # actually reads.
    body = json.dumps(signed_payload, sort_keys=True, separators=(",", ":")).encode()
    signature = _sign(secret, body)

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            resp = await client.post(
                url,
                content=body,
                headers={"Content-Type": "application/json", "X-Aegis-Signature": signature},
            )
        resp.raise_for_status()

        response_signature = resp.headers.get("X-Aegis-Signature")
        if not response_signature:
            return ApprovalDecision(approved=False, approver=None, reason="approval response was not signed")
        # Bind the response signature to this request_id the same way the
        # request was bound to it, so a stolen/cached signed response from
        # a *different* request can't be replayed as this one's answer.
        expected = _sign(secret, f"{request_id}.".encode() + resp.content)
        if not hmac.compare_digest(expected, response_signature):
            return ApprovalDecision(
                approved=False, approver=None, reason="approval response signature invalid"
            )

        resp_body = json.loads(resp.content)
        if resp_body.get("request_id") != request_id:
            return ApprovalDecision(
                approved=False, approver=None, reason="approval response request_id mismatch"
            )
        return ApprovalDecision(
            approved=bool(resp_body.get("approved", False)),
            approver=resp_body.get("approver"),
            reason=resp_body.get("reason"),
        )
    except (httpx.HTTPError, ValueError) as exc:
        # Fail-closed: a network error, timeout, non-2xx status, or a
        # response body that isn't valid JSON all resolve to "not approved"
        # rather than raising — a flaky approval webhook must never turn
        # into either a hung request or a silent ALLOW.
        return ApprovalDecision(approved=False, approver=None, reason=f"approval resolver failed: {exc}")


async def resolve_approval(
    webhook_url: str | None, hmac_secret: str | None, payload: dict
) -> ApprovalDecision:
    """No resolver configured is itself a fail-closed case: a policy that
    requires approval, on a tenant that hasn't wired up a way to grant it,
    must deny rather than silently drop the requirement. Likewise, a
    webhook URL configured without a matching HMAC secret fails closed
    rather than falling back to sending/trusting unsigned traffic — a
    misconfigured tenant should get a visible DENY, not a silent
    downgrade to the same unauthenticated-response gap this replaced."""
    if not webhook_url:
        return ApprovalDecision(
            approved=False, approver=None, reason="no approval resolver configured for this tenant"
        )
    if not hmac_secret:
        return ApprovalDecision(
            approved=False,
            approver=None,
            reason="approval webhook configured without an HMAC secret",
        )
    return await _resolve_via_webhook(webhook_url, hmac_secret, payload)
