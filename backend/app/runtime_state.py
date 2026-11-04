import time
from typing import Any, Dict

from redis.exceptions import RedisError

from app.config import settings
from app.gateway.redis_client import redis_handle


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


class GatewayRuntimeState:
    """Shared gateway switches. Redis-backed so every worker sees the same toggle."""

    HASH_KEY = "sgw:runtime"

    def __init__(self) -> None:
        self._local: Dict[str, Any] = {
            "gateway_enabled": settings.GATEWAY_ENABLED_BY_DEFAULT,
            "auto_block_critical": settings.AUTO_BLOCK_CRITICAL,
            "auto_block_duration_minutes": settings.AUTO_BLOCK_DURATION_MINUTES,
            "anomaly_zscore_threshold": 3.0,
        }
        self._snapshot: Dict[str, str] = {}
        self._snapshot_at = 0.0
        self._snapshot_ttl = 0.25

    def _refresh(self) -> None:
        now = time.time()
        if now - self._snapshot_at < self._snapshot_ttl and self._snapshot:
            return
        client = redis_handle.get()
        if client is not None:
            try:
                raw = client.hgetall(self.HASH_KEY)
                if raw:
                    self._snapshot = raw
                    self._snapshot_at = now
                    return
            except RedisError:
                redis_handle.mark_down()
        self._snapshot = {key: str(value) for key, value in self._local.items()}
        self._snapshot_at = now

    def _get(self, key: str) -> str:
        self._refresh()
        if key in self._snapshot:
            return self._snapshot[key]
        return str(self._local[key])

    def _set(self, key: str, value: Any) -> None:
        self._local[key] = value
        self._snapshot[key] = str(value)
        self._snapshot_at = time.time()
        client = redis_handle.get()
        if client is None:
            return
        try:
            client.hset(self.HASH_KEY, key, str(value))
        except RedisError:
            redis_handle.mark_down()

    @property
    def gateway_enabled(self) -> bool:
        return _as_bool(self._get("gateway_enabled"))

    @gateway_enabled.setter
    def gateway_enabled(self, value: bool) -> None:
        self._set("gateway_enabled", bool(value))

    @property
    def auto_block_critical(self) -> bool:
        return _as_bool(self._get("auto_block_critical"))

    @auto_block_critical.setter
    def auto_block_critical(self, value: bool) -> None:
        self._set("auto_block_critical", bool(value))

    @property
    def auto_block_duration_minutes(self) -> int:
        return int(float(self._get("auto_block_duration_minutes")))

    @auto_block_duration_minutes.setter
    def auto_block_duration_minutes(self, value: int) -> None:
        self._set("auto_block_duration_minutes", int(value))

    @property
    def anomaly_zscore_threshold(self) -> float:
        return float(self._get("anomaly_zscore_threshold"))

    @anomaly_zscore_threshold.setter
    def anomaly_zscore_threshold(self, value: float) -> None:
        self._set("anomaly_zscore_threshold", float(value))


gateway_state = GatewayRuntimeState()
