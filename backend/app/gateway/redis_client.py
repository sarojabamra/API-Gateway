import time
from typing import Optional

import redis
from redis.exceptions import RedisError

from app.config import settings


class RedisHandle:
    """Lazy Redis connection. Stays quiet when REDIS_URL is unset, and backs off after failures."""

    def __init__(self) -> None:
        self._client: Optional[redis.Redis] = None
        self._url: Optional[str] = None
        self._down_until = 0.0

    def get(self) -> Optional[redis.Redis]:
        url = (settings.REDIS_URL or "").strip() or None
        if not url:
            return None
        now = time.time()
        if now < self._down_until:
            return None
        if self._client is not None and self._url == url:
            return self._client
        try:
            client = redis.Redis.from_url(
                url,
                decode_responses=True,
                socket_connect_timeout=0.5,
                socket_timeout=0.5,
                health_check_interval=30,
                max_connections=100,
            )
            client.ping()
        except RedisError:
            self._client = None
            self._url = None
            self._down_until = now + 5
            return None
        self._client = client
        self._url = url
        return client

    def mark_down(self) -> None:
        self._client = None
        self._url = None
        self._down_until = time.time() + 5


redis_handle = RedisHandle()
