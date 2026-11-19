"""Pure hash-chain math, deliberately dependency-free (stdlib only) so
scripts/verify_audit_chain.py can import this exact function without
pulling in SQLAlchemy/the app's DB engine — a verifier that reimplements
the hash formula separately from the writer is a real drift risk: if the
two ever disagree, the tamper-evidence guarantee silently breaks.

Keyed with an HMAC secret (not a plain hash): a plain SHA-256 chain is
publicly recomputable by anyone with direct database write access — they
could edit a row and recompute every hash after it from the same public
formula, producing a chain that still verifies as "intact." HMAC-ing with
a secret aegis-server holds (and the database does not) means forging a
valid chain also requires that secret, not just DB access. This still
doesn't defend against an attacker who compromises the app server itself
(they'd have the secret too) — real defense-in-depth needs an external
anchor (WORM store, signed checkpoint published elsewhere) that this MVP
doesn't have yet; see docs/guide/audit.md.
"""

import hmac
from datetime import datetime
from uuid import UUID


def chain_hash(
    *,
    secret: str,
    evaluation_id: UUID,
    timestamp: datetime,
    tenant_id: str,
    human_id: str | None,
    agent_id: str | None,
    action: str,
    resource_urn: str,
    decision: str,
    matched_policy: str | None,
    policy_version: str | None,
    evaluation_reason: str,
    previous_hash: str | None,
) -> str:
    # Every persisted column with evidentiary value is covered — not just
    # the identity/decision fields. matched_policy/policy_version/
    # evaluation_reason record *why* a decision was made (including
    # approval-workflow outcomes) and are exactly what an attacker editing
    # history would want to change; leaving them out of the hash would let
    # that edit pass verification silently.
    material = "|".join(
        [
            str(evaluation_id),
            timestamp.isoformat(),
            tenant_id,
            human_id or "",
            agent_id or "",
            action,
            resource_urn,
            decision,
            matched_policy or "",
            policy_version or "",
            evaluation_reason,
            previous_hash or "",
        ]
    )
    return hmac.new(secret.encode(), material.encode(), "sha256").hexdigest()
