"""
Global async Redis client for the BB84 QKD backend.
Usage in any module:
    from app.redis_client import get_redis
    r = get_redis()
    await r.set("key", "value")
"""
import os
import logging
import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

_redis_client: aioredis.Redis | None = None


async def init_redis() -> aioredis.Redis:
    """Create and verify the global Redis connection."""
    global _redis_client
    _redis_client = aioredis.from_url(
        REDIS_URL,
        decode_responses=True,
        max_connections=20,
    )
    await _redis_client.ping()
    logger.info(f"Redis connected: {REDIS_URL}")
    return _redis_client


async def close_redis() -> None:
    """Gracefully close the Redis connection pool."""
    global _redis_client
    if _redis_client:
        await _redis_client.aclose()
        _redis_client = None
        logger.info("Redis connection closed.")


def get_redis() -> aioredis.Redis:
    """Return the active Redis client. Raises if not initialised."""
    if _redis_client is None:
        raise RuntimeError("Redis client not initialised — was init_redis() called?")
    return _redis_client
