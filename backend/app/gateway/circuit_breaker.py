"""
Per-upstream circuit breaker for SentinelGW.

States: closed -> open -> half_open -> closed
Trips when consecutive failures (timeouts / 5xx) exceed a threshold.
"""
from __future__ import annotations

import time
from typing import Dict, Optional, Tuple

try:
    from app.redis_client import get_redis
except Exception:  # pragma: no cover
    get_redis = None  # type: ignore


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout_sec: float = 30.0,
        half_open_successes: int = 2,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout_sec = recovery_timeout_sec
        self.half_open_successes = half_open_successes
        self._state: Dict[str, Dict[str, float]] = {}

    def _bucket(self, key: str) -> Dict[str, float]:
        return self._state.setdefault(
            key,
            {
                "failures": 0.0,
                "successes": 0.0,
                "opened_at": 0.0,
                "state": 0.0,  # 0=closed, 1=open, 2=half_open
            },
        )

    def allow(self, upstream_key: str) -> Tuple[bool, Optional[str]]:
        b = self._bucket(upstream_key)
        state = int(b["state"])
        now = time.time()
        if state == 1:  # open
            if now - b["opened_at"] >= self.recovery_timeout_sec:
                b["state"] = 2.0
                b["successes"] = 0.0
                return True, None
            remaining = int(self.recovery_timeout_sec - (now - b["opened_at"]))
            return False, f"Circuit breaker OPEN for upstream '{upstream_key}' (retry in {max(1, remaining)}s)"
        return True, None

    def record_success(self, upstream_key: str) -> None:
        b = self._bucket(upstream_key)
        if int(b["state"]) == 2:
            b["successes"] += 1
            if b["successes"] >= self.half_open_successes:
                b["state"] = 0.0
                b["failures"] = 0.0
                b["successes"] = 0.0
        else:
            b["failures"] = 0.0
            b["state"] = 0.0

    def record_failure(self, upstream_key: str) -> None:
        b = self._bucket(upstream_key)
        b["failures"] += 1
        if int(b["state"]) == 2 or b["failures"] >= self.failure_threshold:
            b["state"] = 1.0
            b["opened_at"] = time.time()
            b["successes"] = 0.0

    def snapshot(self, upstream_key: str) -> Dict[str, float]:
        return dict(self._bucket(upstream_key))

    def reset(self, upstream_key: Optional[str] = None) -> None:
        """Clear breaker state for one upstream, or all if key is omitted."""
        if upstream_key is None:
            self._state.clear()
            return
        self._state.pop(upstream_key, None)


circuit_breaker = CircuitBreaker()
