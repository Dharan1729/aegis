"""The decision pipeline must deny whenever any stage fails, expected or
not, and must deny when the decision cannot be recorded. No stack needed:
every stage is replaced with a stub."""

from types import SimpleNamespace

import pytest

from app import decision as d
from app.approval import ApprovalDecision
from app.cedar_client import CedarDecision, CedarEngineError
from app.policy_store import CachedPolicy, PolicyNotFoundError
from app.principal_validator import ExecutionPrincipalIdentity, PrincipalValidationError
from app.rate_limiter import RateLimitExceededError
from app.schemas import EvaluateRequest, ExecutionPrincipal, ResourceDescriptor

REQ = EvaluateRequest(
    execution_principal=ExecutionPrincipal(session_id="s", workflow_id="w"),
    action="execute_query",
    resource=ResourceDescriptor(type="database_table", urn="urn:t"),
    context={"tool_name": "sql"},
)


class FakeSession:
    def __init__(self, tenant=None):
        self.tenant = tenant or SimpleNamespace(
            rate_limit_per_minute=None,
            approval_webhook_url="https://approvals.example/hook",
            approval_webhook_hmac_secret="x" * 32,
        )
        self.rollbacks = 0

    async def get(self, model, key):
        return self.tenant

    async def rollback(self):
        self.rollbacks += 1


@pytest.fixture
def audit(monkeypatch):
    rows = []

    async def record(session, **kw):
        rows.append(kw)

    monkeypatch.setattr(d, "record_decision", record)
    return rows


@pytest.fixture
def happy(monkeypatch, audit):
    """Every stage succeeds and Cedar allows; tests override one stage."""

    async def ok_rate_limit(*a, **k):
        return None

    async def ok_principal(*a, **k):
        return ExecutionPrincipalIdentity(tenant_id="t", human_id="alice", agent_id="bot")

    async def ok_policy(tenant_id):
        return CachedPolicy(policy_script="permit(principal, action, resource);", policy_version="v1")

    async def allow(*a, **k):
        return CedarDecision(allow=True, determining_policies=["policy0"], errors=[], annotations={})

    monkeypatch.setattr(d, "check_rate_limit", ok_rate_limit)
    monkeypatch.setattr(d, "validate_principal", ok_principal)
    monkeypatch.setattr(d.policy_store, "get", ok_policy)
    monkeypatch.setattr(d, "authorize", allow)
    return audit


async def run(session=None):
    return await d.decide(
        session or FakeSession(),
        tenant_id="t",
        user_token="u",
        service_token="s",
        req=REQ,
        correlation_id="eval_test",
    )


def _raiser(exc):
    async def f(*a, **k):
        raise exc

    return f


async def test_all_stages_ok_allows(happy):
    result = await run()
    assert result.allowed
    assert happy[-1]["decision"] == "ALLOW"
    assert happy[-1]["policy_version"] == "v1"


@pytest.mark.parametrize(
    "stage,exc",
    [
        ("validate_principal", PrincipalValidationError("bad token")),
        ("authorize", CedarEngineError("sidecar down")),
        ("check_rate_limit", ConnectionError("redis down")),
        ("validate_principal", RuntimeError("bug")),
        ("authorize", KeyError("decision")),
        ("resolve_approval", TimeoutError("hung")),
    ],
)
async def test_any_stage_failure_denies_and_is_recorded(happy, monkeypatch, stage, exc):
    if stage == "resolve_approval":

        async def needs_approval(*a, **k):
            return CedarDecision(True, ["policy0"], [], {"approval_required": "true"})

        monkeypatch.setattr(d, "authorize", needs_approval)
    monkeypatch.setattr(d, stage, _raiser(exc))
    session = FakeSession()
    result = await run(session)
    assert result.decision == "DENY"
    assert result.execution_policy is None
    assert "unable to verify" in result.graceful_rejection_message
    assert happy[-1]["decision"] == "DENY"
    assert happy[-1]["evaluation_reason"].startswith("fail-closed")
    assert session.rollbacks == 1


async def test_policy_store_failure_denies(happy, monkeypatch):
    monkeypatch.setattr(d.policy_store, "get", _raiser(PolicyNotFoundError("none")))
    assert (await run()).decision == "DENY"


async def test_rate_limit_exceeded_is_raised_for_a_429(happy, monkeypatch):
    monkeypatch.setattr(d, "check_rate_limit", _raiser(RateLimitExceededError("slow down")))
    with pytest.raises(RateLimitExceededError):
        await run()


async def test_audit_write_failure_turns_an_allow_into_a_deny(happy, monkeypatch):
    monkeypatch.setattr(d, "record_decision", _raiser(ConnectionError("postgres down")))
    result = await run()
    assert result.decision == "DENY"
    assert "audit log" in result.graceful_rejection_message


async def test_cedar_deny_is_a_deny(happy, monkeypatch):
    async def deny(*a, **k):
        return CedarDecision(allow=False, determining_policies=[], errors=[], annotations={})

    monkeypatch.setattr(d, "authorize", deny)
    result = await run()
    assert result.decision == "DENY"
    assert happy[-1]["evaluation_reason"] == "denied by policy <default deny>"


async def test_obligations_reach_the_caller(happy, monkeypatch):
    async def allow_masked(*a, **k):
        return CedarDecision(True, ["policy0"], [], {"mask_fields": "ssn, salary"})

    monkeypatch.setattr(d, "authorize", allow_masked)
    result = await run()
    assert result.allowed
    assert result.execution_policy.mask_fields == ["ssn", "salary"]
    assert result.execution_policy.allowed_tools == ["sql"]


async def test_low_risk_approval_is_automatic(happy, monkeypatch):
    async def allow_low(*a, **k):
        return CedarDecision(True, ["policy0"], [], {"approval_required": "true", "risk_tier": "low"})

    called = []
    monkeypatch.setattr(d, "authorize", allow_low)
    monkeypatch.setattr(d, "resolve_approval", lambda *a, **k: called.append(1))
    result = await run()
    assert result.allowed
    assert result.execution_policy.approved_by == d.LOW_RISK_APPROVER
    assert called == []


async def test_refused_approval_denies(happy, monkeypatch):
    async def allow_high(*a, **k):
        return CedarDecision(True, ["policy0"], [], {"approval_required": "true", "risk_tier": "high"})

    async def refuse(*a, **k):
        return ApprovalDecision(approved=False, approver=None, reason="nope")

    monkeypatch.setattr(d, "authorize", allow_high)
    monkeypatch.setattr(d, "resolve_approval", refuse)
    result = await run()
    assert result.decision == "DENY"
    assert "requires approval" in result.graceful_rejection_message
    assert "not granted (nope)" in happy[-1]["evaluation_reason"]


async def test_granted_approval_allows_and_names_the_approver(happy, monkeypatch):
    async def allow_high(*a, **k):
        return CedarDecision(True, ["policy0"], [], {"approval_required": "true", "risk_tier": "high"})

    async def grant(*a, **k):
        return ApprovalDecision(approved=True, approver="bob@example.com", reason=None)

    monkeypatch.setattr(d, "authorize", allow_high)
    monkeypatch.setattr(d, "resolve_approval", grant)
    result = await run()
    assert result.allowed
    assert result.execution_policy.approved_by == "bob@example.com"
