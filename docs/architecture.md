# Architecture

## Components

```
                ┌────────────────────────── aegis-sdk ──────────────────────────┐
 agent ──tool──▶│ adapter (LangGraph / CrewAI / SK / OpenAI Agents / MCP)        │
  call          │   └─ Guard.check ─────────────┐        Guard.finish (masking) │
                └───────────────────────────────┼───────────────────────────────┘
                                                │ POST /v1/evaluate
                ┌───────────────────────────────▼──────── aegis-server ─────────┐
                │ main.py      HTTP: headers, status codes                      │
                │ decision.py  rate limit → identity → policy → Cedar →         │
                │              obligations → approval → audit → Decision        │
                │ principal_validator.py   cedar_client.py   approval.py        │
                │ policy_store.py          audit.py          admin.py           │
                └──────┬──────────────┬──────────────┬──────────────┬───────────┘
                       │              │              │              │
                   Postgres         Redis      cedar-sidecar   approval webhook
             tenants, policies,  policy cache,   (Rust, Cedar)   (yours; signed)
             history, audit      rate limits,
             chain               replay guard,
                                 pub/sub
```

| Component | Language | Responsibility | State |
|---|---|---|---|
| aegis-sdk | Python | intercept tool calls in each framework; fail closed; apply masking | none |
| aegis-server | Python (FastAPI, SQLAlchemy async) | the decision pipeline, admin API | none in process (caches only) |
| cedar-sidecar | Rust (axum, `cedar-policy` 3) | evaluate and validate Cedar; merge annotations | none |
| Postgres | | source of truth | durable |
| Redis | | shared caches and counters | disposable |

## The request path

[`decision.py`](../aegis-server/app/decision.py) runs these stages, each timed into `aegis_evaluate_stage_latency_seconds{stage}` and traced with OpenTelemetry:

1. **`rate_limit`**: read the tenant record and increment a fixed-window counter in Redis. Over the limit: HTTP 429.
2. **`principal_validation`**: verify both JWTs against the tenant's JWKS and issuers ([tenants](guide/tenants.md#token-checks)); for single-use tenants, `SET NX` each `jti` in Redis.
3. **`policy_lookup`**: the tenant's policy text, from an in-process cache (TTL 5 s), then Redis, then Postgres.
4. **`cedar_call`**: build entities (`Human`, `Agent`, `Resource`) and context, and call cedar-sidecar through a pooled client with a 0.5 s timeout and a circuit breaker.
5. **obligations and `approval_resolution`**: read the merged annotations; auto-approve low risk; otherwise call the webhook.
6. **`audit_write`**: lock the tenant's chain head, append the HMAC-chained entry, commit.

Any exception in stages 1 to 5 (except a rate-limit refusal) becomes a DENY that still goes through stage 6. An exception in stage 6 becomes a DENY that is not recorded and is counted in `aegis_audit_write_failures_total`.

## Decisions and why

**A separate Rust sidecar for Cedar.** Cedar's reference implementation is Rust and there are no official Python bindings. Wrapping the real crate gives exact Cedar semantics, including strict schema validation, rather than a reimplementation that could drift. The cost is a network hop: 0.8 ms mean on a local network. The sidecar is stateless, since policy text travels with each request, so it scales and restarts freely.

**Two tokens, not one.** An agent acting for a person is two principals. Collapsing them into one token loses either "who asked" (needed for most permissions) or "which software is acting" (needed to restrict powerful agents). Both are verified, and the agent's identity is never taken from the request body.

**Fail closed everywhere, including the client.** Authorization that fails open under load or during an outage is worse than none, because people rely on it. The server turns every failure into a DENY, and the SDK does the same for failures between the agent and the server. A denial is a normal tool result so the agent can explain or try something else, rather than an exception that crashes the run (which in some frameworks, such as CrewAI's hook dispatcher, would run the tool anyway).

**Obligations merged strictly in the sidecar.** Merging is part of evaluation: doing it next to Cedar, in one place, means no client can merge differently. "Strictly" because an obligation that one policy imposes should not disappear because another policy also matched ([B3](benchmarks.md#b3-overlapping-policies-and-masking-a-bug-found-and-fixed) shows what happened when it did).

**Masking in the SDK.** Only the client sees the tool's output. The server says *what* to mask; the SDK does it, by key, on structured data. Free text is withheld rather than guessed at.

**An HMAC chain per tenant.** A per-tenant chain lets tenants be verified, exported or deleted independently, and keeps one tenant's activity from serialising another's. The HMAC key, not stored in the database, stops someone with only database access from recomputing hashes after an edit. The price is that one tenant's decisions are written one at a time ([B4](benchmarks.md#b4-latency-throughput-and-where-the-time-goes)).

**Policies pushed, not polled.** A saved policy is written to Postgres, put in Redis, and announced on a pub/sub channel; every replica drops its local copy. Policy changes are usually tightening access, so they should apply immediately everywhere, not after a cache expiry. The listener reconnects after Redis outages and clears its cache when it does, since it may have missed messages.

**Single-use tokens by default, reusable on request.** Single use limits a stolen token to one call, but needs a token exchange in front of Aegis. Many deployments have only ordinary access tokens, so tenants can opt out per tenant, keeping every other check.

**Admin API in the same service, behind separate OIDC.** One deployable unit is easier to run. Admin access is platform-level, from its own identity provider and scope, independent of any tenant's identity provider.

## What is not here

- No decision cache: every call is evaluated and recorded. Decisions depend on short-lived tokens and approvals, so a cache would rarely hit and would complicate the audit trail.
- No asynchronous approvals: the webhook answers within 5 s ([pattern for slow approvals](guide/approvals.md#waiting-for-a-human)).
- No external anchoring of the audit chain ([audit](guide/audit.md#what-it-does-not-protect-against)).
- No per-argument authorization by default: resource resolvers are opt-in.
