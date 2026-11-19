import pytest

agents_sdk = pytest.importorskip("agents")

import asyncio
import json

from agents import Agent, ToolInputGuardrail, ToolInputGuardrailData, ToolOutputGuardrailData, function_tool
from agents.tool_context import ToolContext

from aegis.adapters.openai_agents import (
    AegisContext,
    make_aegis_tool_guardrails,
    make_aegis_tool_input_guardrail,
)
from aegis.masking import MASK
from tests.conftest import EMPLOYEE, FIXED_CTX_KWARGS, FakeAegisClient

CTX = AegisContext(**FIXED_CTX_KWARGS)
guardrail = ToolInputGuardrail(guardrail_function=make_aegis_tool_input_guardrail(FakeAegisClient()))


@function_tool(tool_input_guardrails=[guardrail])
def allowed_tool(x: int) -> str:
    """An allowed tool."""
    return f"allowed_tool result: {x}"


@function_tool(name_override="forbidden_tool", tool_input_guardrails=[guardrail])
def forbidden_tool(x: int) -> str:
    """A forbidden tool."""
    return f"forbidden_tool result: {x}"


agent = Agent(name="test-agent", instructions="test", tools=[allowed_tool, forbidden_tool])


async def _run_guardrail_for(func_tool, args_json: str):
    tool_context = ToolContext(
        context=CTX, tool_name=func_tool.name, tool_call_id="call_1", tool_arguments=args_json
    )
    data = ToolInputGuardrailData(context=tool_context, agent=agent)
    return await func_tool.tool_input_guardrails[0].run(data)


def test_allowed_tool_guardrail_allows_and_tool_executes():
    out = asyncio.run(_run_guardrail_for(allowed_tool, '{"x": 1}'))
    assert out.behavior["type"] == "allow"

    tool_context = ToolContext(
        context=CTX, tool_name=allowed_tool.name, tool_call_id="call_1", tool_arguments='{"x": 1}'
    )
    result = asyncio.run(allowed_tool.on_invoke_tool(tool_context, '{"x": 1}'))
    assert "allowed_tool result" in result


def test_forbidden_tool_guardrail_rejects_with_graceful_message():
    out = asyncio.run(_run_guardrail_for(forbidden_tool, '{"x": 1}'))
    assert out.behavior["type"] == "reject_content"
    assert "Access Denied" in out.behavior["message"]


def _ctx(name, call_id="call_9", args='{"x": 1}'):
    return ToolContext(context=CTX, tool_name=name, tool_call_id=call_id, tool_arguments=args)


def test_guardrail_pair_masks_the_output_of_an_allowed_call():
    before, after = make_aegis_tool_guardrails(FakeAegisClient())
    out = asyncio.run(
        before.guardrail_function(ToolInputGuardrailData(context=_ctx("masked_tool"), agent=agent))
    )
    assert out.behavior["type"] == "allow"
    data = ToolOutputGuardrailData(context=_ctx("masked_tool"), agent=agent, output=EMPLOYEE)
    out = asyncio.run(after.guardrail_function(data))
    assert out.behavior["type"] == "reject_content"
    assert json.loads(out.behavior["message"])["ssn"] == MASK


def test_guardrail_pair_leaves_unmasked_calls_alone():
    before, after = make_aegis_tool_guardrails(FakeAegisClient())
    asyncio.run(before.guardrail_function(ToolInputGuardrailData(context=_ctx("plain", "c2"), agent=agent)))
    data = ToolOutputGuardrailData(context=_ctx("plain", "c2"), agent=agent, output="ok")
    assert asyncio.run(after.guardrail_function(data)).behavior["type"] == "allow"


def test_outage_rejects():
    before, _ = make_aegis_tool_guardrails(FakeAegisClient(raise_for="allowed_tool"))
    out = asyncio.run(
        before.guardrail_function(ToolInputGuardrailData(context=_ctx("allowed_tool"), agent=agent))
    )
    assert out.behavior["type"] == "reject_content"
