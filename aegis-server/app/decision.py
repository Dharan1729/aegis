"""The decision pipeline behind POST /v1/evaluate, independent of HTTP.

    rate limit -> identity -> tenant policy -> Cedar -> obligations
               -> approval (if required) -> audit record -> Decision

Every stage can fail. The rule for all of them is the same: a failure is a
DENY, never an error that reaches the caller as a crash and never an ALLOW.
The one exception is a tenant over its rate limit, which the HTTP layer
turns into a 429 so clients can back off.

If the decision cannot be written to the audit log, it is DENY as well: an
action that cannot be recorded is not allowed to run.
"""

import logging
from dataclasses import dataclass, field

from redis.exceptions import RedisError
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.approval import resolve_approval
from app.audit import record_decision
from app.cedar_client import CedarEngineError, authorize
from app.config import settings
from app.models import TenantConfig
from app.observability import AUDIT_WRITE_FAILURES, FAIL_CLOSED, stage
from app.policy_store import PolicyNotFoundError, policy_store
from app.principal_validator import PrincipalValidationError, validate_principal
from app.rate_limiter import RateLimitExceededError, check_rate_limit
from app.schemas import EvaluateRequest, ExecutionPolicy

logger = logging.getLogger("aegis.decision")

# Failures we expect: bad identity, missing policy, a dependency that is
# down. Logged as a warning. Any other exception is also denied, but logged
# with a traceback, because it is a bug.
EXPECTED_FAILURES = (
    PrincipalValidationError,
    PolicyNotFoundError,
    CedarEngineError,
    RedisError,
    DBAPIError,
    OSError,
)

LOW_RISK_APPROVER = "auto (low risk)"


@dataclass
class Obligations:
    """What an ALLOW obliges the caller to do, read from the annotations of
    the policies that allowed the request (merged strictest-first by
    cedar-sidecar)."""

    mask_fields: list[str] = field(default_factory=list)
    approval_required: bool = False
    risk_tier: str | None = None

    @classmethod
    def from_annotations(cls, annotations: dict[str, str]) -> "Obligations":
        return cls(
            mask_fields=[f.strip() for f in annotations.get("mask_fields", "").split(",") if f.strip()],
            approval_required=annotations.get("approval_required", "").strip().lower() == "true",
            risk_tier=annotations.get("risk_tier", "").strip().lower() or None,
        )


@dataclass
class Decision:
    decision: str  # "ALLOW" or "DENY"
    correlation_id: str
    execution_policy: ExecutionPolicy | None = None
    graceful_rejection_message: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"


@dataclass
class _Outcome:
    """A decision plus what the audit log needs to explain it."""

    decision: Decision
    reason: str
    human_id: str | None = None
    agent_id: str | None = None
    matched_policy: str | None = None
    policy_version: str | None = None


async def _safe_rollback(session: AsyncSession) -> None:
    try:
        await session.rollback()
    except Exception:
        logger.warning("rollback failed", exc_info=True)


def _tool_label(req: EvaluateRequest) -> str:
    return req.context.get("tool_name", req.action)


def _deny(correlation_id: str, message: str) -> Decision:
    return Decision(decision="DENY", correlation_id=correlation_id, graceful_rejection_message=message)


async def _evaluate(
    session: AsyncSession,
    *,
    tenant_id: str,
    user_token: str,
    service_token: str,
    req: EvaluateRequest,
    correlation_id: str,
) -> _Outcome:
    with stage("rate_limit"):
        tenant_config = await session.get(TenantConfig, tenant_id)
        limit = (
            tenant_config.rate_limit_per_minute
            if tenant_config and tenant_config.rate_limit_per_minute
            else settings.default_rate_limit_per_window
        )
        await check_rate_limit(tenant_id, limit, settings.rate_limit_window_seconds)

    with stage("principal_validation"):
        identity = await validate_principal(session, tenant_id, user_token, service_token)
    outcome = _Outcome(
        decision=_deny(correlation_id, ""), reason="", human_id=identity.human_id, agent_id=identity.agent_id
    )

    with stage("policy_lookup"):
        cached_policy = await policy_store.get(tenant_id)
    outcome.policy_version = cached_policy.policy_version

    with stage("cedar_call"):
        cedar = await authorize(cached_policy.policy_script, identity, req, correlation_id=correlation_id)
    outcome.matched_policy = ",".join(cedar.determining_policies) or None

    if not cedar.allow:
        outcome.reason = "denied by policy " + (outcome.matched_policy or "<default deny>")
        outcome.decision = _deny(
            correlation_id,
            f"Access Denied: '{_tool_label(req)}' is not permitted on '{req.resource.urn}' "
            "for this principal.",
        )
        return outcome

    obligations = Obligations.from_annotations(cedar.annotations)
    approved_by: str | None = None
    if obligations.approval_required and obligations.risk_tier == "low":
        # Opted into approval but marked low risk: approve without asking a
        # person, so approvers are not flooded with trivial requests.
        approved_by = LOW_RISK_APPROVER
    elif obligations.approval_required:
        with stage("approval_resolution"):
            approval = await resolve_approval(
                tenant_config.approval_webhook_url if tenant_config else None,
                tenant_config.approval_webhook_hmac_secret if tenant_config else None,
                {
                    "tenant_id": tenant_id,
                    "human_id": identity.human_id,
                    "agent_id": identity.agent_id,
                    "action": req.action,
                    "resource_urn": req.resource.urn,
                    "matched_policy": outcome.matched_policy,
                    "correlation_id": correlation_id,
                },
            )
        if not approval.approved:
            why = approval.reason or "no resolver"
            outcome.reason = (
                f"denied: approval required by policy {outcome.matched_policy or '<none>'} "
                f"and not granted ({why})"
            )
            outcome.decision = _deny(
                correlation_id,
                f"Access Denied: '{_tool_label(req)}' requires approval that was not granted "
                f"({approval.reason or 'no approval resolver configured'}).",
            )
            return outcome
        approved_by = approval.approver or "approved"

    tool_name = req.context.get("tool_name")
    outcome.decision = Decision(
        decision="ALLOW",
        correlation_id=correlation_id,
        execution_policy=ExecutionPolicy(
            allowed_tools=[tool_name] if tool_name else [],
            mask_fields=obligations.mask_fields,
            approval_required=obligations.approval_required,
            risk_tier=obligations.risk_tier,
            approved_by=approved_by,
        ),
    )
    outcome.reason = "allowed by policy " + (outcome.matched_policy or "<none>")
    if approved_by:
        outcome.reason += f"; approved by {approved_by}"
    return outcome


async def decide(
    session: AsyncSession,
    *,
    tenant_id: str,
    user_token: str,
    service_token: str,
    req: EvaluateRequest,
    correlation_id: str,
) -> Decision:
    """Runs the pipeline and records the result. Raises only
    RateLimitExceededError; every other failure is a DENY."""
    try:
        outcome = await _evaluate(
            session,
            tenant_id=tenant_id,
            user_token=user_token,
            service_token=service_token,
            req=req,
            correlation_id=correlation_id,
        )
    except RateLimitExceededError:
        raise
    except Exception as exc:
        if isinstance(exc, EXPECTED_FAILURES):
            reason = f"fail-closed: {exc}"
            logger.warning("evaluate %s denied: %s", correlation_id, exc)
        else:
            reason = f"fail-closed: unexpected {type(exc).__name__}: {exc}"
            logger.exception("evaluate %s denied by an unexpected error", correlation_id)
        FAIL_CLOSED.labels(cause=type(exc).__name__).inc()
        outcome = _Outcome(
            decision=_deny(correlation_id, "Access Denied: unable to verify authorization for this action."),
            reason=reason,
        )
        # A failed statement can leave the transaction unusable for the
        # audit write below.
        await _safe_rollback(session)

    try:
        with stage("audit_write"):
            await record_decision(
                session,
                tenant_id=tenant_id,
                human_id=outcome.human_id,
                agent_id=outcome.agent_id,
                action=req.action,
                resource_urn=req.resource.urn,
                decision=outcome.decision.decision,
                matched_policy=outcome.matched_policy,
                policy_version=outcome.policy_version,
                evaluation_reason=outcome.reason,
            )
    except Exception:
        AUDIT_WRITE_FAILURES.inc()
        logger.exception("evaluate %s: audit write failed; denying", correlation_id)
        await _safe_rollback(session)
        return _deny(correlation_id, "Access Denied: unable to record this decision in the audit log.")

    return outcome.decision
