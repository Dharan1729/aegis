import asyncio

from app import policy_store as ps


class FakePubSub:
    """First connection fails; the next one delivers one invalidation."""

    attempts = 0
    release: asyncio.Event

    def __init__(self):
        FakePubSub.attempts += 1
        self.attempt = FakePubSub.attempts

    async def subscribe(self, channel):
        if self.attempt == 1:
            raise ConnectionError("redis down")

    async def listen(self):
        yield {"type": "subscribe", "data": 1}
        await FakePubSub.release.wait()
        yield {"type": "message", "data": "t1"}
        await asyncio.Event().wait()

    async def aclose(self):
        pass


async def test_listener_survives_a_redis_outage(monkeypatch):
    FakePubSub.attempts = 0
    FakePubSub.release = asyncio.Event()
    monkeypatch.setattr(ps.redis_client, "pubsub", FakePubSub)
    store = ps.PolicyStore()
    await store.start()
    try:
        for _ in range(50):
            await asyncio.sleep(0.05)
            if FakePubSub.attempts >= 2:
                break
        store._local_set("t1", ps.CachedPolicy("permit(principal, action, resource);", "v1"))
        store._local_set("t2", ps.CachedPolicy("permit(principal, action, resource);", "v1"))
        FakePubSub.release.set()
        for _ in range(50):
            await asyncio.sleep(0.05)
            if store._local_get("t1") is None:
                break
        assert FakePubSub.attempts == 2
        assert store._local_get("t1") is None
        assert store._local_get("t2") is not None
    finally:
        await store.stop()
