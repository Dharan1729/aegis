# API reference

aegis-server also serves an OpenAPI description at `/docs` and `/openapi.json`.

## Decisions

### `POST /v1/evaluate`

| Header | |
|---|---|
| `X-Aegis-Tenant-Id` | tenant ID |
| `X-Aegis-User-Token` | the end user's JWT |
| `Authorization` | `Bearer <the agent's JWT>` |

```json
{
  "execution_principal": {"session_id": "sess-42", "workflow_id": "payroll-assistant"},
  "action": "execute_query",
  "resource": {"type": "database_table", "urn": "urn:db:payroll"},
  "context": {"tool_name": "execute_query"}
}
```

`context` is passed to Cedar as `context`, after the server overwrites `agent_id`, `agent`, `session_id` and `workflow_id` with verified values.

**200, allowed**

```json
{
  "decision": "ALLOW",
  "correlation_id": "eval_3f1c9a2b7d10",
  "latency_ms": 4.4,
  "execution_policy": {
    "allowed_tools": ["execute_query"],
    "mask_fields": ["compensation", "ssn"],
    "approval_required": false,
    "risk_tier": null,
    "approved_by": null
  },
  "graceful_rejection_message": null
}
```

**200, denied**

```json
{
  "decision": "DENY",
  "correlation_id": "eval_8c2d...",
  "latency_ms": 3.1,
  "execution_policy": null,
  "graceful_rejection_message": "Access Denied: 'execute_query' is not permitted on 'urn:db:payroll' for this principal."
}
```

A failed identity check, a missing policy, an unavailable dependency, a refused approval, and a failed audit write are all `200` with `"decision": "DENY"`. The `correlation_id` matches the audit entry and the server logs.

| Status | When |
|---|---|
| 200 | a decision, ALLOW or DENY |
| 401 | `Authorization` is not a `Bearer` token |
| 422 | malformed body or missing header |
| 429 | the tenant is over its rate limit |

### `GET /v1/policy-version/{tenant_id}`

`{"tenant_id": "acme", "policy_version": "2fe45ec3b0bdf1d5"}`, or 404. Unauthenticated, so that SDKs can cheaply notice a policy change (the LangGraph checkpointer uses it). It reveals whether a tenant ID exists.

## Health

| Endpoint | Meaning |
|---|---|
| `GET /health` | the process is up (liveness) |
| `GET /ready` | Postgres, Redis and cedar-sidecar all answer; 503 with per-dependency status otherwise (readiness) |
| `GET /metrics` | Prometheus metrics |

Metrics: `aegis_evaluate_decisions_total{decision}`, `aegis_evaluate_fail_closed_total{cause}`, `aegis_audit_write_failures_total`, `aegis_evaluate_stage_latency_seconds{stage}` (stages: `rate_limit`, `principal_validation`, `policy_lookup`, `cedar_call`, `approval_resolution`, `audit_write`), plus the standard HTTP metrics.

## Admin

Every `/admin/*` endpoint needs `Authorization: Bearer <OIDC token with the aegis:admin scope>` ([tenants](tenants.md#admin-access)): 401 for a bad token, 403 without the scope.

| Method and path | |
|---|---|
| `GET /admin/tenants/{id}` | tenant configuration; the webhook secret is reported as `approval_webhook_secret_set` |
| `PUT /admin/tenants/{id}` | create or replace ([fields](tenants.md)); 422 for a webhook without a secret, or plain `http` URLs in production |
| `POST /admin/policies/validate` | `{"policy_script": "...", "tenant_id": "acme"?}` → `{"valid", "errors", "schema_checked"}` |
| `GET /admin/policies/{id}` | current policy, version, update time |
| `PUT /admin/policies/{id}` | `{"policy_script": "..."}`: validate (against the schema, if any), save, version, push to every replica. 422 with Cedar's errors if invalid |
| `GET /admin/policies/{id}/history` | the last 50 versions and when each was saved |
| `GET /admin/schema/{id}` / `PUT /admin/schema/{id}` | the tenant's Cedar JSON schema; saving one turns on strict validation |
| `GET /admin/audit/{id}` | audit entries, newest first; `limit` (≤200), `offset`, exact-match `action` and `decision` filters |

`/admin-ui/` is a small browser editor for policies and schemas over the same API.

## cedar-sidecar

Internal; aegis-server is its only intended client.

| | |
|---|---|
| `POST /authorize` | `{policy_set, entities, principal, action, resource, context}` → `{decision, determining_policies, errors, annotations}` (annotations merged strictly) |
| `POST /validate` | `{policy_set, schema?}` → `{valid, errors, schema_checked}` |
| `GET /health` | |
