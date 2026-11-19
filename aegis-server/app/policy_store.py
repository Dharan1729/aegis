import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass

from app.config import settings
from app.db import AsyncSessionLocal
from app.models import TenantPolicy
from app.redis_client import redis_client

POLICY_UPDATES_CHANNEL = "aegis:policy_updates"

logger = logging.getLogger("aegis.policy_store")


class PolicyNotFoundError(Exception):
    pass


@dataclass
class CachedPolicy:
    policy_script: str
    policy_version: str


def _redis_key(tenant_id: str) -> str:
    return f"aegis:policy:{tenant_id}"


def version_for(policy_script: str) -> str:
    return hashlib.sha256(policy_script.encode()).hexdigest()[:16]


class PolicyStore:
    """Tenant policy cache backed by Redis (shared across every aegis-server
    replica) with a tiny local TTL cache in front purely to avoid a Redis
    round-trip on every evaluate() call.

    Correctness no longer depends on the local cache being fresh: Redis is
    the shared source of truth, and a pub/sub message on
    `aegis:policy_updates` evicts the local entry the moment a policy
    changes, instead of waiting out a TTL. The old worker-local-only,
    60-second-poll design silently diverged across replicas; this doesn't,
    because there's no per-replica copy of the truth anymore — only a
    short-lived, actively-invalidated read cache.
    """

    def __init__(self) -> None:
        self._local_cache: dict[str, tuple[CachedPolicy, float]] = {}
        self._subscriber_task: asyncio.Task | None = None

    def _local_get(self, tenant_id: str) -> CachedPolicy | None:
        entry = self._local_cache.get(tenant_id)
        if entry is None:
            return None
        cached, expires_at = entry
        if expires_at < time.monotonic():
            del self._local_cache[tenant_id]
            return None
        return cached

    def _local_set(self, tenant_id: str, cached: CachedPolicy) -> None:
        expires_at = time.monotonic() + settings.policy_local_cache_ttl_seconds
        self._local_cache[tenant_id] = (cached, expires_at)

    async def _load_from_postgres(self, tenant_id: str) -> CachedPolicy:
        async with AsyncSessionLocal() as session:
            row = await session.get(TenantPolicy, tenant_id)
        if row is None:
            raise PolicyNotFoundError(f"no policy loaded for tenant: {tenant_id}")
        cached = CachedPolicy(policy_script=row.policy_script, policy_version=version_for(row.policy_script))
        await redis_client.set(
            _redis_key(tenant_id),
            json.dumps({"policy_script": cached.policy_script, "policy_version": cached.policy_version}),
            ex=settings.policy_redis_cache_ttl_seconds,
        )
        return cached

    async def get(self, tenant_id: str) -> CachedPolicy:
        local = self._local_get(tenant_id)
        if local is not None:
            return local

        raw = await redis_client.get(_redis_key(tenant_id))
        if raw is not None:
            data = json.loads(raw)
            cached = CachedPolicy(**data)
            self._local_set(tenant_id, cached)
            return cached

        cached = await self._load_from_postgres(tenant_id)
        self._local_set(tenant_id, cached)
        return cached

    async def _listen_once(self) -> None:
        pubsub = redis_client.pubsub()
        try:
            await pubsub.subscribe(POLICY_UPDATES_CHANNEL)
            # Anything cached before (re)subscribing may have missed an
            # invalidation while the connection was down.
            self._local_cache.clear()
            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue
                self._local_cache.pop(message["data"], None)
        finally:
            await pubsub.aclose()

    async def _listen_for_invalidations(self) -> None:
        """Keeps the subscription alive across Redis outages. Without the
        retry, one dropped connection ended the listener for good and policy
        changes reached this replica only when its local TTL expired."""
        delay = 0.5
        while True:
            try:
                await self._listen_once()
                delay = 0.5
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - any connection failure: retry
                logger.warning("policy invalidation listener lost Redis (%s); retrying in %.1fs", exc, delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 10.0)

    async def start(self) -> None:
        self._subscriber_task = asyncio.create_task(self._listen_for_invalidations())

    async def stop(self) -> None:
        if self._subscriber_task is not None:
            self._subscriber_task.cancel()


policy_store = PolicyStore()


async def publish_policy_update(tenant_id: str, policy_script: str) -> str:
    """Write a tenant's policy straight into the shared Redis cache and
    notify every subscribed aegis-server replica to drop its local copy —
    the push-based counterpart to PolicyStore.get()'s pull path. Callers
    (the admin API, scripts/seed_tenant.py) must still persist to Postgres
    themselves; Postgres remains the source of truth Redis is warmed from
    on a cache miss."""
    version = version_for(policy_script)
    await redis_client.set(
        _redis_key(tenant_id),
        json.dumps({"policy_script": policy_script, "policy_version": version}),
        ex=settings.policy_redis_cache_ttl_seconds,
    )
    await redis_client.publish(POLICY_UPDATES_CHANNEL, tenant_id)
    return version
