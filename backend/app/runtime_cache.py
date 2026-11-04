import time
from typing import Any, Dict, Optional, Tuple

from redis.exceptions import RedisError
from sqlalchemy import event

from app.config import settings
from app.gateway.redis_client import redis_handle
from app.models import BlocklistEntry, Policy, Route, Upstream


class VersionedTTLCache:
    """Process-local TTL cache coordinated by a Redis generation counter.

    Workers share one generation key so a policy, route, blocklist, or
    upstream write on any replica invalidates cached reads everywhere.
    """

    GEN_KEY = "sgw:cache:gen"

    def __init__(self, ttl: float = 2.0) -> None:
        self.ttl = ttl
        self._store: Dict[str, Tuple[float, int, Any]] = {}
        self._local_gen = 0

    def current_gen(self) -> int:
        client = redis_handle.get()
        if client is not None:
            try:
                raw = client.get(self.GEN_KEY)
                return int(raw or 0)
            except (RedisError, TypeError, ValueError):
                redis_handle.mark_down()
        return self._local_gen

    def invalidate(self) -> None:
        self._store.clear()
        client = redis_handle.get()
        if client is not None:
            try:
                client.incr(self.GEN_KEY)
                return
            except RedisError:
                redis_handle.mark_down()
        self._local_gen += 1

    def get(self, key: str) -> Optional[Any]:
        item = self._store.get(key)
        if item is None:
            return None
        expires, stored_gen, value = item
        if stored_gen != self.current_gen() or time.time() > expires:
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        self._store[key] = (time.time() + self.ttl, self.current_gen(), value)


runtime_cache = VersionedTTLCache(ttl=settings.CACHE_TTL_SECONDS)


def _bump_cache(*_args, **_kwargs) -> None:
    runtime_cache.invalidate()


for _model in (Policy, BlocklistEntry, Upstream, Route):
    event.listen(_model, "after_insert", _bump_cache)
    event.listen(_model, "after_update", _bump_cache)
    event.listen(_model, "after_delete", _bump_cache)
