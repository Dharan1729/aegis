"""Independently recomputes each tenant's audit_ledger hash chain and
confirms no row has been edited, deleted, reordered, or truncated since
it was written — this is the actual point of hash-chaining the ledger
(see docs/guide/audit.md): a plain database row can be
silently edited by anyone with DB access; a broken hash chain cannot be
produced without visibly breaking the chain from that point forward,
*provided* the attacker doesn't also hold the HMAC secret (app/audit_hash.py)
— a plain unkeyed hash would be publicly recomputable and thus forgeable
by anyone with DB write access alone, which is why the chain is HMAC-keyed
rather than a bare SHA-256.

Chains are per-tenant (see migration 0006), so each tenant's rows are
verified as their own independent sequence, ordered by timestamp — which
is a valid total order *within* one tenant because app/audit.py's
SELECT...FOR UPDATE on that tenant's chain-head row serializes writes for
that tenant (across tenants, there's no shared lock and no shared chain,
so cross-tenant timestamp comparisons are never made here).

Imports the exact same chain_hash() aegis-server's app/audit.py uses
(via app/audit_hash.py, which has no dependencies beyond the stdlib) so
there is exactly one implementation of the hash formula, not two that
could silently drift apart.

Run against the Postgres exposed by docker-compose (localhost:5432) by
default, or any other Postgres — e.g. a restored backup — via
AEGIS_VERIFY_DSN (see docs/guide/operations.md, backup/restore
verification step). The HMAC secret below must match aegis-server's
AUDIT_CHAIN_HMAC_SECRET env var (dev default matches app/config.py's dev
default); override via AEGIS_VERIFY_HMAC_SECRET for the same reason.
"""

import asyncio
import os
import sys
from itertools import groupby
from pathlib import Path

import asyncpg

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "aegis-server"))
from app.audit_hash import chain_hash

DSN = os.environ.get(
    "AEGIS_VERIFY_DSN", os.environ.get("AEGIS_DSN", "postgresql://aegis:aegis@localhost:5432/aegis")
)
HMAC_SECRET = os.environ.get("AEGIS_VERIFY_HMAC_SECRET", "dev-audit-chain-secret-do-not-use-in-prod")


async def main() -> None:
    conn = await asyncpg.connect(DSN)
    try:
        rows = await conn.fetch(
            """
            SELECT evaluation_id, timestamp, tenant_id, human_id, agent_id,
                   action, resource_urn, decision, matched_policy,
                   policy_version, evaluation_reason, previous_hash, hash
            FROM audit_ledger
            WHERE hash != 'pre-chain'
            ORDER BY tenant_id ASC, timestamp ASC
            """
        )
    finally:
        await conn.close()

    if not rows:
        print("No hash-chained audit rows to verify.")
        return

    any_broken = False
    for tenant_id, tenant_rows_iter in groupby(rows, key=lambda r: r["tenant_id"]):
        tenant_rows = list(tenant_rows_iter)

        # A genuine genesis row has no predecessor. If the earliest
        # surviving row for this tenant claims one anyway, the true
        # earliest rows may have been deleted outright — a truncation an
        # in-place-edit detector alone would never see, since deleting
        # rows (rather than editing them) doesn't touch any hash at all.
        if tenant_rows[0]["previous_hash"] is not None:
            any_broken = True
            print(
                f"Tenant '{tenant_id}': FIRST SURVIVING ROW IS NOT A GENESIS ROW "
                f"(previous_hash={tenant_rows[0]['previous_hash']!r}) — earlier rows may have "
                "been deleted. Refusing to treat this as a trusted starting point."
            )
            continue

        previous_hash = None
        broken_at = None
        for i, row in enumerate(tenant_rows):
            if row["previous_hash"] != previous_hash:
                broken_at = i
                break
            expected = chain_hash(
                secret=HMAC_SECRET,
                evaluation_id=row["evaluation_id"],
                timestamp=row["timestamp"],
                tenant_id=row["tenant_id"],
                human_id=row["human_id"],
                agent_id=row["agent_id"],
                action=row["action"],
                resource_urn=row["resource_urn"],
                decision=row["decision"],
                matched_policy=row["matched_policy"],
                policy_version=row["policy_version"],
                evaluation_reason=row["evaluation_reason"],
                previous_hash=previous_hash,
            )
            if expected != row["hash"]:
                broken_at = i
                break
            previous_hash = row["hash"]

        print(f"Tenant '{tenant_id}': verified {len(tenant_rows)} rows.", end=" ")
        if broken_at is None:
            print("Chain intact.")
        else:
            any_broken = True
            bad = tenant_rows[broken_at]
            print(
                f"CHAIN BROKEN at row {broken_at} (evaluation_id={bad['evaluation_id']}, "
                f"timestamp={bad['timestamp']}) — this row or one before it was tampered with."
            )

    if any_broken:
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
