import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, true
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class TenantConfig(Base):
    """Tenant validation metadata — where to fetch JWKS for the two identity tokens."""

    __tablename__ = "tenant_configs"

    tenant_id: Mapped[str] = mapped_column(String, primary_key=True)
    jwks_uri_human: Mapped[str] = mapped_column(String)
    jwks_uri_service: Mapped[str] = mapped_column(String)
    # Cross-checked against the `iss` claim on each token, so a caller can't
    # pass a different tenant's valid JWT alongside this tenant's header and
    # have it accepted just because the JWKS lookup succeeds. Nullable in the
    # schema for older rows, but a tenant without both issuers is denied
    # every request (app/principal_validator.py).
    expected_issuer_human: Mapped[str | None] = mapped_column(String, nullable=True)
    expected_issuer_service: Mapped[str | None] = mapped_column(String, nullable=True)
    # Optional `aud` checks. When set, a token minted for another application
    # by the same identity provider (same issuer, different audience) is
    # rejected.
    expected_audience_human: Mapped[str | None] = mapped_column(String, nullable=True)
    expected_audience_service: Mapped[str | None] = mapped_column(String, nullable=True)
    # True (default): every token is single use. Each must carry a unique
    # `jti` and be younger than `max_token_age_seconds`; a second use is a
    # replay and is denied. Suits a token-exchange setup that mints a short
    # token per tool call. False: tokens are ordinary bearer tokens, valid
    # until `exp`, as most identity providers issue them.
    single_use_tokens: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    rate_limit_per_minute: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Cedar JSON schema text (Cedar's JSON schema format, not the
    # human-readable DSL). Nullable: schema authoring is opt-in per tenant,
    # not required — without one, policy validation stays syntax-only.
    cedar_schema: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Webhook to call when a policy annotation requires human approval.
    # No webhook configured + approval required => fail-closed DENY.
    approval_webhook_url: Mapped[str | None] = mapped_column(String, nullable=True)
    # HMAC secret shared with the approval webhook, signing both the
    # outgoing request (so the webhook can trust it's really us) and the
    # incoming response (so we can trust the decision wasn't forged by a
    # MITM or a compromised service on that URL — see app/approval.py). A
    # webhook URL configured without a matching secret fails closed rather
    # than silently sending/trusting unsigned traffic.
    approval_webhook_hmac_secret: Mapped[str | None] = mapped_column(String, nullable=True)


class TenantPolicy(Base):
    """Raw Cedar policy text per tenant — the current version only.
    See TenantPolicyHistory for every version that's ever been active."""

    __tablename__ = "tenant_policies"

    tenant_id: Mapped[str] = mapped_column(String, primary_key=True)
    policy_script: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class TenantPolicyHistory(Base):
    """Insert-only log of every policy version a tenant has had, so an
    audit_ledger row's `matched_policy` (a Cedar policy id like "policy0",
    not stable across edits) can still be traced back to the exact policy
    text that produced it via `policy_version`."""

    __tablename__ = "tenant_policy_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String, index=True)
    policy_script: Mapped[str] = mapped_column(Text)
    policy_version: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AuditLedger(Base):
    """Immutable, hash-chained log of every evaluate() decision. Each row's
    `hash` covers its own fields plus `previous_hash`, so editing or
    deleting a past row (without recomputing every hash after it) is
    detectable by scripts/verify_audit_chain.py — a plain row in a
    database can be silently edited; this can't be, without the edit
    showing up as a broken chain from that point forward."""

    __tablename__ = "audit_ledger"

    evaluation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    tenant_id: Mapped[str] = mapped_column(String, index=True)
    human_id: Mapped[str | None] = mapped_column(String, nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String, nullable=True)
    action: Mapped[str] = mapped_column(String)
    resource_urn: Mapped[str] = mapped_column(String)
    decision: Mapped[str] = mapped_column(String)
    matched_policy: Mapped[str | None] = mapped_column(String, nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String, nullable=True)
    evaluation_reason: Mapped[str] = mapped_column(Text)
    previous_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    hash: Mapped[str] = mapped_column(String)


class AuditChainHead(Base):
    """One row per tenant, tracking the tip of that tenant's audit hash
    chain. Locked with SELECT ... FOR UPDATE inside the same transaction
    as each audit_ledger insert, so concurrent aegis-server replicas
    can't both read the same "previous hash" and silently fork the chain.

    Deliberately keyed per-tenant rather than one global row: a single
    shared chain would (a) serialize every tenant's writes onto one lock,
    turning a multi-tenant hot path into a global bottleneck, and (b)
    couple tenants' audit trails together — verifying tenant A's chain
    would require walking tenant B's rows too, leaking relative activity
    timing across a boundary that's supposed to be tenant-isolated."""

    __tablename__ = "audit_chain_head"

    tenant_id: Mapped[str] = mapped_column(String, primary_key=True)
    last_hash: Mapped[str | None] = mapped_column(String, nullable=True)
