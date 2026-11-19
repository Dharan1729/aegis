import uuid
from datetime import datetime

import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.cedar_client import CedarEngineError, validate_policy
from app.config import settings
from app.db import get_session
from app.models import AuditLedger, TenantConfig, TenantPolicy, TenantPolicyHistory
from app.policy_store import publish_policy_update, version_for

router = APIRouter(prefix="/admin", tags=["policy-admin"])

_admin_jwks_client: jwt.PyJWKClient | None = None


def _admin_jwks() -> jwt.PyJWKClient:
    global _admin_jwks_client
    if _admin_jwks_client is None:
        _admin_jwks_client = jwt.PyJWKClient(settings.admin_oidc_jwks_uri)
    return _admin_jwks_client


def require_admin_auth(authorization: str = Header(...)) -> dict:
    """Validates an OIDC bearer token: JWKS signature, issuer, and a
    required 'aegis:admin' scope claim.

    Deliberately no single-use nonce/replay check here (unlike
    principal_validator.py's execution-principal tokens, which are
    single-use per tool-call by design): a standard OAuth2 admin access
    token is meant to be reused across many requests within its validity
    window, so treating it as single-use would break normal usage."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing or malformed admin bearer token")
    token = authorization.removeprefix("Bearer ")
    try:
        signing_key = _admin_jwks().get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            issuer=settings.admin_oidc_issuer,
            options={"require": ["exp", "iat", "sub", "iss"], "verify_aud": False},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"invalid admin token: {exc}") from exc

    # `claims.get("scope", "")` alone isn't enough: that default only
    # applies when the key is absent, but some OIDC providers emit
    # `"scope": null` for a token with no granted scopes, which would
    # otherwise reach `None.split()` and crash with an unhandled 500
    # instead of the intended 403.
    scopes = (claims.get("scope") or "").split()
    if settings.admin_oidc_required_scope not in scopes:
        raise HTTPException(status_code=403, detail="admin token missing required scope")
    return claims


class PolicyView(BaseModel):
    tenant_id: str
    policy_script: str
    policy_version: str
    updated_at: datetime | None = None


class ValidateRequest(BaseModel):
    policy_script: str
    # Optional: validate against this tenant's Cedar schema, if it has one.
    # Omit to get syntax-only validation regardless of whether the tenant
    # has a schema on file.
    tenant_id: str | None = None


class ValidateResponse(BaseModel):
    valid: bool
    errors: list[str]
    schema_checked: bool


class HistoryEntry(BaseModel):
    policy_version: str
    created_at: datetime


class TenantUpdate(BaseModel):
    """Everything aegis-server needs to verify a tenant's two tokens and
    reach its approval webhook. PUT replaces the whole record, except that
    an omitted approval_webhook_hmac_secret keeps the stored one."""

    jwks_uri_human: str
    jwks_uri_service: str
    expected_issuer_human: str
    expected_issuer_service: str
    expected_audience_human: str | None = None
    expected_audience_service: str | None = None
    single_use_tokens: bool = True
    rate_limit_per_minute: int | None = Field(default=None, ge=1)
    approval_webhook_url: str | None = None
    approval_webhook_hmac_secret: str | None = Field(default=None, min_length=16)


class TenantView(BaseModel):
    tenant_id: str
    jwks_uri_human: str
    jwks_uri_service: str
    expected_issuer_human: str | None
    expected_issuer_service: str | None
    expected_audience_human: str | None
    expected_audience_service: str | None
    single_use_tokens: bool
    rate_limit_per_minute: int | None
    approval_webhook_url: str | None
    # The secret itself is write-only.
    approval_webhook_secret_set: bool
    has_cedar_schema: bool

    @classmethod
    def of(cls, row: TenantConfig) -> "TenantView":
        return cls(
            tenant_id=row.tenant_id,
            jwks_uri_human=row.jwks_uri_human,
            jwks_uri_service=row.jwks_uri_service,
            expected_issuer_human=row.expected_issuer_human,
            expected_issuer_service=row.expected_issuer_service,
            expected_audience_human=row.expected_audience_human,
            expected_audience_service=row.expected_audience_service,
            single_use_tokens=row.single_use_tokens is not False,
            rate_limit_per_minute=row.rate_limit_per_minute,
            approval_webhook_url=row.approval_webhook_url,
            approval_webhook_secret_set=bool(row.approval_webhook_hmac_secret),
            has_cedar_schema=bool(row.cedar_schema),
        )


class SchemaView(BaseModel):
    tenant_id: str
    cedar_schema: str | None = None


class SchemaUpdateRequest(BaseModel):
    cedar_schema: str


async def _tenant_schema(session: AsyncSession, tenant_id: str | None) -> str | None:
    if not tenant_id:
        return None
    tenant_config = await session.get(TenantConfig, tenant_id)
    return tenant_config.cedar_schema if tenant_config else None


@router.post(
    "/policies/validate", response_model=ValidateResponse, dependencies=[Depends(require_admin_auth)]
)
async def validate(req: ValidateRequest, session: AsyncSession = Depends(get_session)) -> ValidateResponse:
    """Syntax-only unless `tenant_id` is given and that tenant has a Cedar
    schema on file — then this runs real strict-mode semantic validation."""
    schema = await _tenant_schema(session, req.tenant_id)
    try:
        valid, errors, schema_checked = await validate_policy(req.policy_script, schema=schema)
    except CedarEngineError as exc:
        raise HTTPException(status_code=502, detail=f"cedar-sidecar unreachable: {exc}") from exc
    return ValidateResponse(valid=valid, errors=errors, schema_checked=schema_checked)


@router.get("/policies/{tenant_id}", response_model=PolicyView, dependencies=[Depends(require_admin_auth)])
async def get_policy(tenant_id: str, session: AsyncSession = Depends(get_session)) -> PolicyView:
    row = await session.get(TenantPolicy, tenant_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"no policy for tenant '{tenant_id}'")
    return PolicyView(
        tenant_id=tenant_id,
        policy_script=row.policy_script,
        policy_version=version_for(row.policy_script),
        updated_at=row.updated_at,
    )


@router.put("/policies/{tenant_id}", response_model=PolicyView, dependencies=[Depends(require_admin_auth)])
async def put_policy(
    tenant_id: str, req: ValidateRequest, session: AsyncSession = Depends(get_session)
) -> PolicyView:
    """Validates (against the tenant's Cedar schema if one is on file),
    persists to Postgres, records a history row, and pushes the update
    straight into the shared Redis cache with a pub/sub invalidation —
    every aegis-server replica picks it up immediately, no restart and no
    waiting on a TTL."""
    schema = await _tenant_schema(session, tenant_id)
    try:
        valid, errors, _schema_checked = await validate_policy(req.policy_script, schema=schema)
    except CedarEngineError as exc:
        raise HTTPException(status_code=502, detail=f"cedar-sidecar unreachable: {exc}") from exc
    if not valid:
        raise HTTPException(status_code=422, detail={"errors": errors})

    row = await session.get(TenantPolicy, tenant_id)
    if row is None:
        row = TenantPolicy(tenant_id=tenant_id, policy_script=req.policy_script)
        session.add(row)
    else:
        row.policy_script = req.policy_script

    version = version_for(req.policy_script)
    session.add(
        TenantPolicyHistory(tenant_id=tenant_id, policy_script=req.policy_script, policy_version=version)
    )
    await session.commit()
    await session.refresh(row)

    await publish_policy_update(tenant_id, req.policy_script)

    return PolicyView(
        tenant_id=tenant_id,
        policy_script=req.policy_script,
        policy_version=version,
        updated_at=row.updated_at,
    )


@router.get(
    "/policies/{tenant_id}/history",
    response_model=list[HistoryEntry],
    dependencies=[Depends(require_admin_auth)],
)
async def get_history(tenant_id: str, session: AsyncSession = Depends(get_session)) -> list[HistoryEntry]:
    rows = (
        (
            await session.execute(
                select(TenantPolicyHistory)
                .where(TenantPolicyHistory.tenant_id == tenant_id)
                .order_by(TenantPolicyHistory.created_at.desc())
                .limit(50)
            )
        )
        .scalars()
        .all()
    )
    return [HistoryEntry(policy_version=r.policy_version, created_at=r.created_at) for r in rows]


@router.get("/tenants/{tenant_id}", response_model=TenantView, dependencies=[Depends(require_admin_auth)])
async def get_tenant(tenant_id: str, session: AsyncSession = Depends(get_session)) -> TenantView:
    row = await session.get(TenantConfig, tenant_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"no tenant '{tenant_id}'")
    return TenantView.of(row)


@router.put("/tenants/{tenant_id}", response_model=TenantView, dependencies=[Depends(require_admin_auth)])
async def put_tenant(
    tenant_id: str, req: TenantUpdate, session: AsyncSession = Depends(get_session)
) -> TenantView:
    """Creates or replaces a tenant. Misconfigurations that would otherwise
    only show up later as denied requests are rejected here instead."""
    if settings.environment == "production":
        plain = [
            name
            for name in ("jwks_uri_human", "jwks_uri_service", "approval_webhook_url")
            if (getattr(req, name) or "https://").startswith("http://")
        ]
        if plain:
            raise HTTPException(status_code=422, detail=f"must use https in production: {', '.join(plain)}")

    row = await session.get(TenantConfig, tenant_id)
    secret = req.approval_webhook_hmac_secret or (row.approval_webhook_hmac_secret if row else None)
    if req.approval_webhook_url and not secret:
        raise HTTPException(
            status_code=422,
            detail="approval_webhook_url needs approval_webhook_hmac_secret: unsigned approvals are refused",
        )

    values = req.model_dump(exclude={"approval_webhook_hmac_secret"})
    if row is None:
        row = TenantConfig(tenant_id=tenant_id, **values, approval_webhook_hmac_secret=secret)
        session.add(row)
    else:
        for name, value in values.items():
            setattr(row, name, value)
        row.approval_webhook_hmac_secret = secret
    await session.commit()
    return TenantView.of(row)


@router.get("/schema/{tenant_id}", response_model=SchemaView, dependencies=[Depends(require_admin_auth)])
async def get_schema(tenant_id: str, session: AsyncSession = Depends(get_session)) -> SchemaView:
    tenant_config = await session.get(TenantConfig, tenant_id)
    if tenant_config is None:
        raise HTTPException(status_code=404, detail=f"no tenant config for '{tenant_id}'")
    return SchemaView(tenant_id=tenant_id, cedar_schema=tenant_config.cedar_schema)


@router.put("/schema/{tenant_id}", response_model=SchemaView, dependencies=[Depends(require_admin_auth)])
async def put_schema(
    tenant_id: str, req: SchemaUpdateRequest, session: AsyncSession = Depends(get_session)
) -> SchemaView:
    """Schema authoring is opt-in per tenant. Saving one here is what makes
    /policies/validate and later policy saves for this tenant do real
    semantic validation instead of syntax-only."""
    tenant_config = await session.get(TenantConfig, tenant_id)
    if tenant_config is None:
        raise HTTPException(status_code=404, detail=f"no tenant config for '{tenant_id}'")

    # Confirm the schema itself at least parses, using a trivial permit-all
    # policy as the vehicle — cedar-sidecar's /validate always needs a
    # policy_set, and any schema-format error surfaces regardless of what
    # policy accompanies it.
    try:
        valid, errors, _ = await validate_policy(
            "permit(principal, action, resource);", schema=req.cedar_schema
        )
    except CedarEngineError as exc:
        raise HTTPException(status_code=502, detail=f"cedar-sidecar unreachable: {exc}") from exc
    if not valid:
        raise HTTPException(status_code=422, detail={"errors": errors})

    tenant_config.cedar_schema = req.cedar_schema
    await session.commit()
    return SchemaView(tenant_id=tenant_id, cedar_schema=req.cedar_schema)


class AuditEntryView(BaseModel):
    evaluation_id: uuid.UUID
    timestamp: datetime
    tenant_id: str
    human_id: str | None = None
    agent_id: str | None = None
    action: str
    resource_urn: str
    decision: str
    matched_policy: str | None = None
    policy_version: str | None = None
    # Already carries "approved by X" as free text when relevant (see
    # main.py's reason-building) — not worth a separate structured column
    # for a v1 read view; that's the one thing this omits from AuditLedger
    # besides hash/previous_hash (chain integrity stays the domain of
    # scripts/verify_audit_chain.py, not re-verified per page load here).
    evaluation_reason: str


@router.get(
    "/audit/{tenant_id}", response_model=list[AuditEntryView], dependencies=[Depends(require_admin_auth)]
)
async def get_audit_log(
    tenant_id: str,
    session: AsyncSession = Depends(get_session),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None),
    decision: str | None = Query(None),
) -> list[AuditEntryView]:
    """Read-only view over the hash-chained audit log for the
    aegis-console decision-explainer — most recent first. `action`/
    `decision` are exact-match filters, not full-text search."""
    query = select(AuditLedger).where(AuditLedger.tenant_id == tenant_id)
    if action:
        query = query.where(AuditLedger.action == action)
    if decision:
        query = query.where(AuditLedger.decision == decision)
    query = query.order_by(AuditLedger.timestamp.desc()).limit(limit).offset(offset)

    rows = (await session.execute(query)).scalars().all()
    return [
        AuditEntryView(
            evaluation_id=r.evaluation_id,
            timestamp=r.timestamp,
            tenant_id=r.tenant_id,
            human_id=r.human_id,
            agent_id=r.agent_id,
            action=r.action,
            resource_urn=r.resource_urn,
            decision=r.decision,
            matched_policy=r.matched_policy,
            policy_version=r.policy_version,
            evaluation_reason=r.evaluation_reason,
        )
        for r in rows
    ]
