import pytest

langgraph = pytest.importorskip("langgraph")

import asyncio

from langgraph.checkpoint.base import empty_checkpoint
from langgraph.checkpoint.memory import InMemorySaver

from aegis.adapters.langgraph_checkpoint import GovernedCheckpointer, StaleAuthorizationError
from aegis.client import AegisClient


class FakeVersionedClient(AegisClient):
    def __init__(self):
        super().__init__(base_url="http://unused")
        self.version = "v1"

    def policy_version(self, tenant_id: str) -> str:
        return self.version

    async def apolicy_version(self, tenant_id: str) -> str:
        return self.version


def make_checkpoint(thread_id: str):
    config = {"configurable": {"thread_id": thread_id, "checkpoint_ns": ""}}
    checkpoint = empty_checkpoint()
    metadata = {"source": "input", "step": 1, "writes": {}, "parents": {}}
    return config, checkpoint, metadata


def test_resume_with_unchanged_policy_succeeds():
    client = FakeVersionedClient()
    checkpointer = GovernedCheckpointer(InMemorySaver(), client, tenant_id="acme")
    config, checkpoint, metadata = make_checkpoint("thread-1")
    saved_config = checkpointer.put(config, checkpoint, metadata, {})

    tup = checkpointer.get_tuple(saved_config)
    assert tup is not None
    assert tup.metadata.get("aegis_policy_version") == "v1"


def test_resume_after_policy_change_raises():
    client = FakeVersionedClient()
    checkpointer = GovernedCheckpointer(InMemorySaver(), client, tenant_id="acme")
    config, checkpoint, metadata = make_checkpoint("thread-2")
    saved_config = checkpointer.put(config, checkpoint, metadata, {})

    client.version = "v2"
    with pytest.raises(StaleAuthorizationError):
        checkpointer.get_tuple(saved_config)


def test_async_resume_after_policy_change_raises():
    async def run():
        client = FakeVersionedClient()
        checkpointer = GovernedCheckpointer(InMemorySaver(), client, tenant_id="acme")
        config, checkpoint, metadata = make_checkpoint("thread-3")
        saved_config = await checkpointer.aput(config, checkpoint, metadata, {})

        client.version = "v2"
        with pytest.raises(StaleAuthorizationError):
            await checkpointer.aget_tuple(saved_config)

    asyncio.run(run())


def test_list_also_detects_staleness():
    """Regression test: list()/alist() used to bypass the staleness check
    entirely, so resuming via checkpoint history (a common LangGraph
    pattern) silently skipped stale-policy detection."""
    client = FakeVersionedClient()
    checkpointer = GovernedCheckpointer(InMemorySaver(), client, tenant_id="acme")
    config, checkpoint, metadata = make_checkpoint("thread-4")
    checkpointer.put(config, checkpoint, metadata, {})

    client.version = "v2"
    with pytest.raises(StaleAuthorizationError):
        list(checkpointer.list(config))
