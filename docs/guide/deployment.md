# Deployment

`docker-compose.yml` is a development and evaluation stack: fixed passwords, a dev identity provider and a mock approver. A deployment needs the same components with real settings:

| Component | Image | State | Scaling |
|---|---|---|---|
| aegis-server | `aegis-server/Dockerfile` | none | replicas behind a load balancer |
| cedar-sidecar | `cedar-sidecar/Dockerfile` | none (policy arrives with each request) | next to each aegis-server replica, or as a shared service |
| Postgres | any 14+ (tested on 16) | tenants, policies, policy history, audit log | managed Postgres recommended |
| Redis | any 6+ (tested on 7) | caches, rate-limit counters, replay guard, invalidation pub/sub | one instance; losing it loses nothing durable |

Both images run as a non-root user and have health checks.

## Configuration

aegis-server reads environment variables (case-insensitive).

| Variable | Default | |
|---|---|---|
| `ENVIRONMENT` | `development` | `production` refuses to start with any dev default below, and requires `https` URLs in tenant configs |
| `DATABASE_URL` | `postgresql+asyncpg://aegis:aegis@localhost:5432/aegis` | |
| `REDIS_URL` | `redis://localhost:6379/0` | |
| `CEDAR_SIDECAR_URL` | `http://localhost:8180` | |
| `AUDIT_CHAIN_HMAC_SECRET` | dev value | **required in production**, at least 32 characters. Keep it out of the database's backups and access |
| `ADMIN_OIDC_JWKS_URI` | dev JWKS | your identity provider's JWKS |
| `ADMIN_OIDC_ISSUER` | dev issuer | |
| `ADMIN_OIDC_REQUIRED_SCOPE` | `aegis:admin` | |
| `CONSOLE_CORS_ORIGINS` | `["http://localhost:5173"]` | JSON list of browser origins allowed to call the API |
| `MAX_TOKEN_AGE_SECONDS` | `300` | single-use tokens: maximum age |
| `DEFAULT_RATE_LIMIT_PER_WINDOW` | `600` | per tenant, when the tenant sets none |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | |
| `DB_POOL_SIZE`, `DB_MAX_OVERFLOW` | `20`, `20` | per process; keep total connections under Postgres's `max_connections` |
| `POLICY_LOCAL_CACHE_TTL_SECONDS` | `5` | safety net only; updates are pushed |
| `POLICY_REDIS_CACHE_TTL_SECONDS` | `300` | |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | empty (off) | OTLP gRPC endpoint for traces |
| `MIGRATE_ON_START` | `true` | run `alembic upgrade head` before serving |
| `WORKERS` | `1` | uvicorn worker processes; see [Scaling](#scaling) |

## Production checklist

- [ ] `ENVIRONMENT=production`. The server then refuses to start with the dev audit secret, the dev admin identity provider, or a localhost CORS origin.
- [ ] `AUDIT_CHAIN_HMAC_SECRET`: 32+ random bytes from your secret manager. Losing it means old entries can no longer be verified; leaking it means they can be forged.
- [ ] Admin access through your real identity provider; grant `aegis:admin` to few people.
- [ ] Every tenant: real JWKS URIs and issuers over `https`, an audience if your identity provider serves other applications, and a deliberate choice of [single-use or reusable tokens](tenants.md#single-use-tokens-default).
- [ ] Approval webhooks over `https` with a random secret per tenant.
- [ ] Postgres: automated backups shipped off-host, point-in-time recovery, and a tested restore that includes [verifying the audit chain](operations.md#33-verify-a-restore-before-trusting-it).
- [ ] TLS in front of aegis-server (it speaks plain HTTP). Keep cedar-sidecar, Postgres and Redis on a private network.
- [ ] Restrict `/metrics` and `/v1/policy-version/*` at the network edge if tenant names are sensitive.
- [ ] Readiness probe on `/ready`, liveness on `/health`.
- [ ] Alert on `aegis_audit_write_failures_total` and on a rising `aegis_evaluate_fail_closed_total`: both mean legitimate requests are being denied.
- [ ] Schedule `scripts/verify_audit_chain.py`, and anchor each tenant's chain head somewhere append-only ([audit](audit.md#what-it-does-not-protect-against)).

## Migrations

With `MIGRATE_ON_START=true`, each replica runs `alembic upgrade head` before serving. Concurrent starts are safe: migrations take a Postgres advisory lock, so one replica migrates and the others wait and find nothing to do. To migrate as a separate step instead, set `MIGRATE_ON_START=false` and run `alembic upgrade head` from the aegis-server image as a one-off job before rolling out.

## Scaling

- **Replicas.** aegis-server keeps no state of its own, so add replicas. Policy updates reach all of them at once through Redis pub/sub; the rate limiter and replay guard are shared through Redis; the audit chain lock is in Postgres.
- **Per tenant.** One tenant's decisions are recorded one at a time (the audit chain lock). On a laptop that held one tenant at roughly 300 to 350 decisions per second; spreading load across tenants removes most of the wait ([B4](../benchmarks.md#b4-latency-throughput-and-where-the-time-goes)).
- **Workers.** Prefer one worker per container and more replicas. With `WORKERS=4` throughput rose at low concurrency but fell sharply above 25 concurrent requests in our runs, for reasons not yet understood. Prometheus metrics are also per process, so each scrape of a multi-worker container sees only one worker.
- **Approval webhooks** add a network round trip (up to the 5 s timeout) to every call that needs one.

## Kubernetes

There is no Helm chart yet. The pieces: a Deployment for aegis-server (readiness `/ready`, liveness `/health`, secrets from your secret store), cedar-sidecar as a second container in the same pod (`CEDAR_SIDECAR_URL=http://localhost:8180`), and managed Postgres and Redis.
