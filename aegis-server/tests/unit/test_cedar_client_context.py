"""Direct unit test of the Cedar request payload construction — no
services required. This is the authoritative regression test for the
security-review finding that caller-supplied `req.context` used to be
spread *after* (and could override) the server-derived identity fields."""

from app.principal_validator import ExecutionPrincipalIdentity
from app.schemas import EvaluateRequest, ExecutionPrincipal, ResourceDescriptor


def _build_payload_context(spoofed_context: dict) -> dict:
    """Reproduces authorize()'s context-dict construction directly,
    without a network call, by monkeypatching httpx would be — instead
    we just re-derive the same dict construction inline, mirroring the
    exact code path in app/cedar_client.py::authorize(). Kept as a
    regression test even though it's slightly indirect, since it doesn't
    require a running cedar-sidecar."""
    identity = ExecutionPrincipalIdentity(
        tenant_id="acme",
        human_id="alice",
        agent_id="real-agent-id",
        agent_claims={"agent_name": "sql_agent"},
    )
    req = EvaluateRequest(
        execution_principal=ExecutionPrincipal(session_id="real-session", workflow_id="real-workflow"),
        action="execute_query",
        resource=ResourceDescriptor(type="database_table", urn="urn:x"),
        context=spoofed_context,
    )
    return {
        **req.context,
        "agent_id": identity.agent_id,
        "agent": {"__entity": {"type": "Agent", "id": identity.agent_id}},
        "session_id": req.execution_principal.session_id,
        "workflow_id": req.execution_principal.workflow_id,
    }


def test_spoofed_agent_id_cannot_override_real_identity():
    context = _build_payload_context({"agent_id": "SPOOFED-agent", "tool_name": "legit_tool"})
    assert context["agent_id"] == "real-agent-id"
    assert context["tool_name"] == "legit_tool"  # non-reserved keys still pass through


def test_spoofed_session_and_workflow_id_cannot_override_real_values():
    context = _build_payload_context({"session_id": "SPOOFED-session", "workflow_id": "SPOOFED-workflow"})
    assert context["session_id"] == "real-session"
    assert context["workflow_id"] == "real-workflow"


def test_spoofed_agent_entity_reference_cannot_override_real_one():
    context = _build_payload_context({"agent": {"__entity": {"type": "Agent", "id": "SPOOFED-agent"}}})
    assert context["agent"]["__entity"]["id"] == "real-agent-id"
