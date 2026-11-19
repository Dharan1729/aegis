# Operations

## 1. Service levels

These are starting points derived from [benchmark B4](../benchmarks.md#b4-latency-throughput-and-where-the-time-goes) (one replica, one laptop). Re-measure on your own infrastructure before you promise them to anyone.

| Indicator | Starting target | Basis |
|---|---|---|
| `/v1/evaluate` p50 | < 50 ms | 4.6 ms unloaded, 26 to 60 ms at 10 to 50 concurrent requests |
| `/v1/evaluate` p99 | < 1 s | 11 ms unloaded, 797 ms at 50 concurrent requests on one tenant |
| Throughput per replica | ~250 req/s | 270 to 350 req/s measured, single worker |
| cedar-sidecar `/authorize` | < 10 ms | 0.8 ms mean as seen from aegis-server |
| Fail-closed | 0 ALLOWs while a dependency is down | [B2](../benchmarks.md#b2-fault-injection-does-anything-fail-open) |

Availability is not defined: multi-replica failover has not been tested.

What makes it worse: one very busy tenant (its decisions are recorded one at a time), approval webhooks (a network round trip each), and a database connection pool smaller than concurrent load (`DB_POOL_SIZE` + `DB_MAX_OVERFLOW`, default 40 per process; too small a pool showed up in testing as 10-second client timeouts).

## 2. Playbooks

### 2.1 Everything is being denied

`aegis_evaluate_fail_closed_total{cause}` says why. `GET /ready` shows which dependency is down.

| `cause` | Likely problem |
|---|---|
| `CedarEngineError` | cedar-sidecar down or unreachable. After 5 consecutive connection failures a circuit breaker fails calls immediately for 10 s, then lets one trial through; it recovers by itself once the sidecar is back |
| `ConnectionError`, `TimeoutError` (from Redis) | Redis down |
| `gaierror`, `ConnectionRefusedError`, `OperationalError`, `InterfaceError` | Postgres unreachable (the first two are name-resolution and connection failures). `aegis_audit_write_failures_total` rises too |
| `PrincipalValidationError` | token problems; see 2.4 |

This is the intended behaviour while a dependency is down. Fix the dependency; no restart of aegis-server is needed (measured recovery: 1 to 11 s, [B2](../benchmarks.md#b2-fault-injection-does-anything-fail-open)).

### 2.2 Approval-required actions are always denied

The denial message and the audit reason say which:

- `no approval resolver configured for this tenant`: the tenant has no webhook.
- `approval resolver failed: ...`: the webhook is unreachable, timed out (5 s), or returned non-2xx.
- `approval response was not signed` / `signature invalid` / `request_id mismatch`: the shared secret differs between the tenant and the webhook, or the webhook signs the wrong bytes ([protocol](approvals.md#protocol)).

### 2.3 A policy change is not taking effect

```bash
aegisctl policy get <tenant>                                  # what is saved
curl -s http://<aegis>/v1/policy-version/<tenant>             # what this replica uses
```

Saved policies are pushed to every replica through Redis pub/sub. If a replica lost its Redis connection, its listener reconnects with backoff and clears its local cache on reconnect; meanwhile the local copy expires after `POLICY_LOCAL_CACHE_TTL_SECONDS` (5 s). A difference lasting longer than that points at Redis connectivity from that replica (look for `policy invalidation listener lost Redis` in its logs).

### 2.4 Tokens are rejected

The audit reason holds the precise check that failed (`token issuer ... does not match`, `nonce replay detected`, `token too old, possible replay`, `Signature verification failed`, `Invalid audience`). The common causes:

- the tenant's `expected_issuer_*` does not match the token's `iss` exactly (trailing slashes count);
- single-use tokens being reused across calls: switch the tenant to `single_use_tokens: false`, or mint per call;
- clocks: tokens issued more than 5 s in the future are refused.

### 2.5 Admin API returns 401 or 403

401: the admin token failed signature or issuer checks against `ADMIN_OIDC_JWKS_URI` / `ADMIN_OIDC_ISSUER`. 403: the token is valid but lacks the `aegis:admin` scope.

### 2.6 Migrations did not apply

```bash
docker compose logs aegis-server | grep -i alembic
psql "$DATABASE_URL" -c "SELECT version_num FROM alembic_version;"
```

Compare with the newest file in `aegis-server/alembic/versions/`. Do not edit `alembic_version` by hand to skip a failed migration; find out why it failed.

### 2.7 High tail latency

Check, in order: one tenant carrying most of the load (`aegis_evaluate_stage_latency_seconds{stage="audit_write"}` dominates), pool exhaustion (`DB_POOL_SIZE`), and slow approval webhooks (`stage="approval_resolution"`). Then add replicas.

## 3. Backup and restore

Postgres holds everything that matters: tenants, policies and their history, and the audit chain. Redis holds only things that rebuild themselves (caches, rate-limit windows, replay-guard entries that expire with their tokens) and does not need backing up.

### 3.1 Backup

```bash
pg_dump -Fc "$DATABASE_URL" -f aegis_$(date +%Y%m%d_%H%M%S).dump
```

Schedule it (or use your managed Postgres's automated backups), ship it off-host, and enable point-in-time recovery. A backup on the database's own disk is not a backup.

### 3.2 Restore

Into a new, empty database:

```bash
pg_restore --no-owner --no-privileges -d "$NEW_DATABASE_URL" aegis_20261119_120000.dump
```

### 3.3 Verify a restore before trusting it

An exit code of 0 is not proof. Compare row counts with the source, then re-verify every tenant's audit chain against the restored copy, explicitly:

```bash
psql "$NEW_DATABASE_URL" -c "SELECT count(*) FROM audit_ledger;"
AEGIS_VERIFY_DSN="$NEW_DATABASE_URL" AEGIS_VERIFY_HMAC_SECRET="$AUDIT_CHAIN_HMAC_SECRET" \
  python scripts/verify_audit_chain.py
```

This procedure was run end to end during development: a dump of the development stack (16,346 audit entries) restored into a separate Postgres container, with identical counts and every chain intact. To be sure the verifier read the restored copy, the original database was stopped first.

### 3.4 Not covered

cedar-sidecar and the approval mock hold no state. The dev signing key (`dev/jwks/`) is regenerated per checkout and is not a production secret. Your identity provider's keys are its own responsibility.
