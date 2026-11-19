import pytest

langgraph = pytest.importorskip("langgraph")

import asyncio
import json
from typing import Annotated, TypedDict

from langchain_core.messages import AIMessage
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages

from aegis.adapters.langgraph import SecureToolNode
from aegis.masking import MASK
from tests.conftest import EMPLOYEE, FIXED_CTX_KWARGS, FakeAegisClient


def allowed_tool(x: int) -> str:
    """An allowed tool."""
    return f"allowed_tool result: {x}"


def forbidden_tool(x: int) -> str:
    """A forbidden tool."""
    return f"forbidden_tool result: {x}"


def masked_tool(x: int) -> dict:
    """Returns a record with a field the policy masks."""
    return EMPLOYEE


def exploding_tool(x: int) -> str:
    """Its Aegis check fails."""
    return "must not run"


class State(TypedDict):
    messages: Annotated[list, add_messages]


def build_graph(aegis_client):
    node = SecureToolNode(
        [allowed_tool, forbidden_tool, masked_tool, exploding_tool], aegis_client=aegis_client
    )
    g = StateGraph(State)
    g.add_node("tools", node)
    g.set_entry_point("tools")
    g.add_edge("tools", END)
    return g.compile()


def make_call(name, tool_call_id="1"):
    return {
        "messages": [AIMessage(content="", tool_calls=[{"name": name, "args": {"x": 1}, "id": tool_call_id}])]
    }


CONFIG = {"configurable": {"aegis": FIXED_CTX_KWARGS}}


def test_sync_allowed_tool_executes():
    app = build_graph(FakeAegisClient())
    result = app.invoke(make_call("allowed_tool"), config=CONFIG)
    assert "allowed_tool result" in result["messages"][-1].content


def test_sync_forbidden_tool_returns_graceful_denial():
    app = build_graph(FakeAegisClient())
    result = app.invoke(make_call("forbidden_tool"), config=CONFIG)
    assert "Access Denied" in result["messages"][-1].content


def test_async_allowed_tool_executes():
    app = build_graph(FakeAegisClient())
    result = asyncio.run(app.ainvoke(make_call("allowed_tool"), config=CONFIG))
    assert "allowed_tool result" in result["messages"][-1].content


def test_async_forbidden_tool_returns_graceful_denial():
    app = build_graph(FakeAegisClient())
    result = asyncio.run(app.ainvoke(make_call("forbidden_tool"), config=CONFIG))
    assert "Access Denied" in result["messages"][-1].content


def test_missing_aegis_config_denies_instead_of_running():
    app = build_graph(FakeAegisClient())
    result = app.invoke(make_call("allowed_tool"), config={"configurable": {}})
    assert "Access Denied" in result["messages"][-1].content


def test_output_is_masked():
    app = build_graph(FakeAegisClient())
    content = app.invoke(make_call("masked_tool"), config=CONFIG)["messages"][-1].content
    assert json.loads(content)["ssn"] == MASK
    assert "123-45-6789" not in content


def test_aegis_outage_denies_and_the_tool_does_not_run():
    app = build_graph(FakeAegisClient(raise_for="exploding_tool"))
    content = app.invoke(make_call("exploding_tool"), config=CONFIG)["messages"][-1].content
    assert "Access Denied" in content and "must not run" not in content
