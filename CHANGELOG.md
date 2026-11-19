# Changelog

## 0.2.0

First public release.

### Security fixes

- **Overlapping policies no longer drop obligations.** When several policies allowed a request, cedar-sidecar merged their annotations last-write-wins, in an order that varied per request. With two policies masking different fields, one field went unmasked on 500 of 500 requests. Annotations are now merged strictly and deterministically: masked fields are unioned, approval is required if any policy requires it, and automatic low-risk approval needs every matching policy to say `low` (benchmark B3).
- **Every failure in the decision pipeline is a DENY.** A Redis or Postgres outage, or any unexpected exception, used to surface as HTTP 500. They are now DENY decisions with an audit entry. If the audit entry itself cannot be written, the answer is DENY (`aegis_audit_write_failures_total`).
- **The SDK cannot fail open or crash the agent.** All adapters now share `aegis.Guard`, which turns transport errors, 5xx responses and context-provider exceptions into denials. Before, four of five adapters raised into the agent loop.
- **The issuer is required.** A tenant without an expected issuer for each token is denied, rather than accepting any issuer whose key is at its JWKS URI.
- **Production refuses dev settings.** With `ENVIRONMENT=production`, aegis-server will not start with the development audit secret, the development admin identity provider, or a localhost CORS origin. Tenant JWKS and webhook URLs must be `https`.
- **Images run as non-root**, with health checks; the Rust build uses `Cargo.lock`.
- **Published ports bind to 127.0.0.1** in `docker-compose.yml`.

### Added

- **Masking is enforced.** `@mask_fields` used to be returned to the caller and ignored. The SDK now masks matching keys at any depth in dicts, lists, pydantic models and JSON strings, and withholds output it cannot mask (configurable with `on_unmaskable`).
- **OpenAI Agents SDK masking**: `make_aegis_tool_guardrails` returns an input guardrail (authorize) and an output guardrail (mask).
- **Tenant admin API and CLI**: `GET/PUT /admin/tenants/{id}`, `aegisctl tenant get|put`. The webhook secret is write-only; a webhook without a secret is refused at configuration time.
- **Optional audience checks** per tenant and token type.
- **Reusable tokens** per tenant (`single_use_tokens: false`), for identity providers that issue ordinary access tokens.
- **`/ready`** reports Postgres, Redis and cedar-sidecar health.
- Metrics: `aegis_evaluate_fail_closed_total{cause}`, `aegis_audit_write_failures_total`.
- **Benchmarks** with committed results: attack suite (23 cases), fault injection (6 faults), annotation merge, latency and throughput.
- `examples/quickstart.py`, example policy, schema and tenant config.
- Configurable ports, optional `observability` compose profile, `WORKERS`, `MIGRATE_ON_START`.

### Changed

- The decision pipeline moved from the HTTP handler into `app/decision.py`.
- `scripts/seed_tenant.py` uses only the admin API.
- Server tests split into `tests/unit` (no services) and `tests/integration`.
- `mask_fields` in responses is sorted (a side effect of the strict merge).
- SDK framework floors raised to the versions tested: LangGraph 1.2, CrewAI 1.15, Semantic Kernel 1.47, OpenAI Agents SDK 0.20, MCP 1.30. The MCP adapter's tests use `mcp.server.fastmcp`.
- A missing identity context in the LangGraph or Semantic Kernel adapter is now a denial rather than an exception.
- Dev tokens mint in under 1 ms (the signing key is parsed once).

### Fixed

- The Redis invalidation listener stopped for good after one disconnect; policy changes then reached that replica only through the 5 s cache expiry. It now reconnects with backoff and clears its cache on reconnect.
- CI: a Trivy action tag that no longer existed, and tests against framework versions that had changed.

### Removed

- `scripts/load_test.py`, replaced by `benchmarks/latency.py` (`aegisctl load-test` runs it).

## 0.1.0

Initial version: Cedar sidecar, two-token decision runtime, adapters for LangGraph, CrewAI, Semantic Kernel, the OpenAI Agents SDK and MCP, signed approval webhooks, per-tenant hash-chained audit log, admin API and UI, OpenTelemetry and Prometheus.
