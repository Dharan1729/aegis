# Approvals

A policy annotated `@approval_required("true")` makes an ALLOW conditional on someone (or something) agreeing. Aegis asks your approval webhook synchronously and answers ALLOW only if it says yes.

## When the webhook is called

| Matching policies say | Result |
|---|---|
| no `approval_required`, or `"false"` | no approval needed |
| `approval_required("true")` and every one says `risk_tier("low")` | approved automatically; `approved_by` is `auto (low risk)` |
| `approval_required("true")`, any other tier or none | webhook called |

If the tenant has no webhook, or the webhook fails in any way, the answer is DENY.

## Protocol

**Request.** `POST <approval_webhook_url>`, `Content-Type: application/json`, header `X-Aegis-Signature`. The body is compact JSON with sorted keys:

```json
{"action":"transfer_medium_funds","agent_id":"finance-agent","correlation_id":"eval_3f1c9a2b7d10",
 "human_id":"alice","matched_policy":"policy2","request_id":"8b1e...","resource_urn":"urn:tool:transfer_medium_funds",
 "tenant_id":"acme","timestamp":1763500000}
```

`X-Aegis-Signature` is the hex HMAC-SHA256 of the exact body bytes, keyed with the tenant's `approval_webhook_hmac_secret`.

**Your webhook must:**

1. Recompute the HMAC over the raw body and compare in constant time; reject on mismatch.
2. Reject a `timestamp` more than a few minutes old (the mock allows 300 s), so a captured request cannot be replayed later.
3. Decide, then respond within 5 seconds (Aegis's timeout) with JSON that echoes `request_id`:

```json
{"approved": true, "approver": "bob@example.com", "reason": "within limit", "request_id": "8b1e..."}
```

4. Sign the response: header `X-Aegis-Signature` = hex HMAC-SHA256 over `request_id + "." + <raw response body bytes>`.

**Aegis denies** if the response is not 2xx, is not JSON, is unsigned, has a bad signature, or carries a different `request_id`. Binding the response signature to the request ID means a captured "approved" response cannot be replayed as the answer to another request.

[`approval-mock/main.py`](../../approval-mock/main.py) is a complete, 80-line implementation (it approves everything except actions with "large" in the name).

## Waiting for a human

The webhook is synchronous and has 5 seconds. For decisions a person makes over minutes, have the webhook answer `approved: false` with a reason such as "approval requested, ask again in a few minutes", record the pending request in your system, and let the agent retry the call after it has been approved there. The model sees the reason in the denial text.

## Where approvals show up

The ALLOW's `execution_policy.approved_by` names the approver, and the audit entry's reason records it: `allowed by policy policy2; approved by bob@example.com`. Refusals are recorded with the webhook's reason.
