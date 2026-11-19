import pytest

mcp = pytest.importorskip("mcp")

import asyncio

from mcp.server.fastmcp import FastMCP

from aegis.adapters.mcp import AegisContext, governed
from aegis.masking import MASK
from tests.conftest import EMPLOYEE, FIXED_CTX_KWARGS, FakeAegisClient

CTX = AegisContext(**FIXED_CTX_KWARGS)
client = FakeAegisClient(raise_for="exploding_tool")


def ctx_provider(*args, **kwargs) -> AegisContext:
    return CTX


@governed(client, context_provider=ctx_provider)
def allowed_tool(x: int) -> str:
    return f"allowed_tool result: {x}"


@governed(client, context_provider=ctx_provider)
def forbidden_tool(x: int) -> str:
    return f"forbidden_tool result: {x}"


@governed(client, context_provider=ctx_provider)
async def allowed_tool_async(x: int) -> str:
    return f"allowed_tool_async result: {x}"


@governed(client, context_provider=ctx_provider)
def masked_tool(employee_id: str) -> dict:
    return EMPLOYEE


@governed(client, context_provider=ctx_provider)
def exploding_tool(x: int) -> str:
    return "must not run"


def test_sync_allowed_tool_executes():
    assert "allowed_tool result" in allowed_tool(x=1)


def test_sync_forbidden_tool_returns_graceful_denial():
    assert forbidden_tool(x=1) == "Access Denied: policy blocked this tool."


def test_async_allowed_tool_executes():
    assert "allowed_tool_async result" in asyncio.run(allowed_tool_async(x=1))


def test_output_is_masked():
    assert masked_tool(employee_id="e1")["ssn"] == MASK


def test_aegis_outage_denies_and_the_tool_does_not_run():
    out = exploding_tool(x=1)
    assert "Access Denied" in out and out != "must not run"


def test_registers_with_a_real_mcp_server():
    server = FastMCP("test-server")

    @server.tool()
    @governed(client, context_provider=ctx_provider)
    def registered_tool(x: int) -> str:
        return f"registered_tool result: {x}"

    tools = asyncio.run(server.list_tools())
    assert "registered_tool" in [t.name for t in tools]
    assert "registered_tool result" in registered_tool(x=5)
