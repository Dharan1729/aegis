# Audit log

Every decision is recorded before it is returned: tenant, user, agent, action, resource, decision, the policies that determined it, the policy version, and a human-readable reason (`allowed by policy policy2; approved by bob@example.com`, `fail-closed: token validation failed: ...`). If the record cannot be written, the decision is DENY.

## Reading it

```bash
aegisctl audit acme --limit 20 --decision DENY
curl -H "Authorization: Bearer $AEGIS_ADMIN_TOKEN" "http://localhost:8000/admin/audit/acme?action=transfer_funds"
```

`policy_version` is a hash of the exact policy text in force. `GET /admin/policies/{tenant}/history` maps versions to dates, and the `tenant_policy_history` table holds the full text of every version, so any past decision can be traced to the policy that produced it.

## The hash chain

Each tenant's entries form a chain. An entry's `hash` is an HMAC-SHA256, keyed with `AUDIT_CHAIN_HMAC_SECRET`, over every field of the entry and the previous entry's hash. Changing any field of any entry, deleting one, or inserting one makes verification fail from that point on.

Why a keyed hash: with a plain SHA-256 chain, anyone who can write to the database could edit an entry and recompute every hash after it. The key lives with aegis-server, not in the database, so forging a valid chain needs both.

Writing is serialised per tenant: the tenant's chain head is locked (`SELECT ... FOR UPDATE`) for the length of the insert, so concurrent replicas cannot fork the chain. Different tenants never wait for each other. This lock is the main throughput limit for a single busy tenant ([benchmark B4](../benchmarks.md#b4-latency-throughput-and-where-the-time-goes)).

## Verifying

```bash
AEGIS_VERIFY_DSN=postgresql://... AEGIS_VERIFY_HMAC_SECRET=... python scripts/verify_audit_chain.py
```

It recomputes every tenant's chain from the database independently of the server, using the same hash function (`aegis-server/app/audit_hash.py`, standard library only), and exits non-zero if any tenant's chain is broken. Run it on a schedule, and after every restore ([operations](operations.md#3-backup-and-restore)).

## What it does not protect against

- **Someone with both database write access and the HMAC secret**, for example an attacker who controls aegis-server, can rewrite history undetectably.
- **Truncation of the newest entries** is detected only if you know where the chain should end.

Both are closed by anchoring the chain outside the system: periodically copy each tenant's latest hash (`audit_chain_head.last_hash`) to append-only storage (object-lock storage, a transparency log, a ticket). Aegis does not do this for you yet.
