import time

from app.redis_client import redis_client


class RateLimitExceededError(Exception):
    pass


async def check_rate_limit(tenant_id: str, limit_per_window: int, window_seconds: int) -> None:
    """Fixed-window counter in Redis, shared across every aegis-server
    replica. A noisy tenant's agent loop shouldn't be able to degrade
    decision latency for every other tenant on shared infrastructure."""
    window = int(time.time() // window_seconds)
    key = f"aegis:ratelimit:{tenant_id}:{window}"
    count = await redis_client.incr(key)
    if count == 1:
        await redis_client.expire(key, window_seconds)
    if count > limit_per_window:
        raise RateLimitExceededError(
            f"tenant {tenant_id} exceeded {limit_per_window} requests per {window_seconds}s"
        )
