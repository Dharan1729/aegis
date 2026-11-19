import pytest

crewai = pytest.importorskip("crewai")

import asyncio

from crewai.hooks import clear_all_hooks
from crewai.hooks.tool_hooks import (
    ToolCallHookContext,
    run_after_tool_call_hooks,
    run_before_tool_call_hooks,
)
from crewai.tools import tool

from aegis.adapters.crewai import AegisContext, SecureTool, register_aegis_hooks
from aegis.masking import MASK
from tests.conftest import EMPLOYEE, FIXED_CTX_KWARGS, FakeAegisClient


@tool("allowed_tool")
def allowed_tool(x: int) -> str:
    """An allowed tool."""
    return f"allowed_tool result: {x}"


@tool("forbidden_tool")
def forbidden_tool(x: int) -> str:
    """A forbidden tool."""
    return f"forbidden_tool result: {x}"


@tool("masked_tool")
def masked_tool(x: int) -> dict:
    """Returns a record with a field the policy masks."""
    return EMPLOYEE


@tool("exploding_tool")
def exploding_tool(x: int) -> str:
    """A tool whose Aegis check raises instead of returning a decision."""
    return f"exploding_tool result: {x}"


CTX = AegisContext(**FIXED_CTX_KWARGS)


class TestSecureToolWrapping:
    def test_sync_allowed(self):
        secure = SecureTool(wrapped_tool=allowed_tool, aegis_client=FakeAegisClient(), aegis_context=CTX)
        assert "allowed_tool result" in secure.run(x=1)

    def test_sync_forbidden(self):
        secure = SecureTool(wrapped_tool=forbidden_tool, aegis_client=FakeAegisClient(), aegis_context=CTX)
        assert secure.run(x=1) == "Access Denied: policy blocked this tool."

    def test_output_is_masked(self):
        secure = SecureTool(wrapped_tool=masked_tool, aegis_client=FakeAegisClient(), aegis_context=CTX)
        assert secure.run(x=1)["ssn"] == MASK

    def test_aegis_outage_denies(self):
        secure = SecureTool(
            wrapped_tool=exploding_tool,
            aegis_client=FakeAegisClient(raise_for="exploding_tool"),
            aegis_context=CTX,
        )
        assert "Access Denied" in secure.run(x=1)

    def test_async_forbidden_short_circuits_before_wrapped_tool(self):
        secure = SecureTool(wrapped_tool=forbidden_tool, aegis_client=FakeAegisClient(), aegis_context=CTX)
        result = asyncio.run(secure.arun(x=1))
        assert result == "Access Denied: policy blocked this tool."


class TestNativeHooks:
    def _simulate_call(self, tool_fn):
        """Mirrors what crewai.utilities.tool_utils does internally around
        the before/after hook dispatch, without needing a live LLM run."""
        tool_input = {"x": 1}
        hook_context = ToolCallHookContext(tool_name=tool_fn.name, tool_input=tool_input, tool=tool_fn)
        if run_before_tool_call_hooks(hook_context):
            blocked_message = f"Tool execution blocked by hook. Tool: {tool_fn.name}"
            blocked_ctx = ToolCallHookContext(
                tool_name=tool_fn.name,
                tool_input=tool_input,
                tool=tool_fn,
                tool_result=blocked_message,
                raw_tool_result=blocked_message,
            )
            modified = run_after_tool_call_hooks(blocked_ctx)
            return modified if modified is not None else blocked_message
        raw = tool_fn.run(**tool_input)
        done_ctx = ToolCallHookContext(
            tool_name=tool_fn.name,
            tool_input=tool_input,
            tool=tool_fn,
            tool_result=str(raw),
            raw_tool_result=raw,
        )
        modified = run_after_tool_call_hooks(done_ctx)
        return modified if modified is not None else raw

    def setup_method(self):
        clear_all_hooks()
        register_aegis_hooks(FakeAegisClient(raise_for="exploding_tool"), context_provider=lambda _: CTX)

    def teardown_method(self):
        clear_all_hooks()

    def test_allowed_tool_executes(self):
        assert "allowed_tool result" in self._simulate_call(allowed_tool)

    def test_forbidden_tool_returns_our_message_not_the_generic_one(self):
        result = self._simulate_call(forbidden_tool)
        assert result == "Access Denied: policy blocked this tool."
        assert "blocked by hook" not in result

    def test_evaluate_exception_fails_closed_not_open(self):
        """Regression test for the security-review finding: CrewAI's hook
        dispatcher swallows any exception from a before_tool_call hook and
        treats it as 'not blocked' unless the hook catches it itself and
        returns False explicitly."""
        result = self._simulate_call(exploding_tool)
        assert "Access Denied" in result
        assert "exploding_tool result" not in result

    def test_hook_masks_output(self):
        result = self._simulate_call(masked_tool)
        assert MASK in result and "123-45-6789" not in result

    def test_missing_context_provider_denies(self):
        clear_all_hooks()
        register_aegis_hooks(FakeAegisClient())
        result = self._simulate_call(allowed_tool)
        assert "Access Denied" in result and "allowed_tool result" not in result
