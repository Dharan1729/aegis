# aegis-server

The Aegis decision runtime: a FastAPI service that verifies the caller's two identity tokens, evaluates the tenant's Cedar policy through `cedar-sidecar`, resolves approvals, records every decision in a tamper-evident audit log, and answers `ALLOW` or `DENY`. Any failure along the way is a `DENY`.

Run it with the repository's `docker-compose.yml`; see the [quickstart](../docs/guide/quickstart.md), the [API reference](../docs/guide/api.md) and the [deployment guide](../docs/guide/deployment.md).

Layout:

```
app/main.py           HTTP layer (/v1/evaluate, /health, /ready, /metrics)
app/decision.py       the decision pipeline, independent of HTTP
app/principal_validator.py   the two-token identity check
app/cedar_client.py   cedar-sidecar client with a circuit breaker
app/approval.py       signed approval-webhook round trip
app/audit.py, audit_hash.py  per-tenant HMAC hash chain
app/policy_store.py   Postgres-backed policy cache in Redis, pushed to every replica
app/admin.py          admin API: tenants, policies, schemas, audit log
alembic/              schema migrations
tests/unit            no services needed
tests/integration     against the running docker-compose stack
```
