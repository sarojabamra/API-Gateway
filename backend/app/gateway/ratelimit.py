import math
import time
from typing import Any, Dict, List, Optional, Tuple
from app.config import settings

try:
    import redis
except ImportError:
    redis = None


class HybridRateLimiter:
    """
    Production-grade Rate Limiter implementing both:
    1. Sliding Window Counter (sustained request rate per 60s window)
    2. Token Bucket (short-term burst capacity)
    Automatically uses Redis if REDIS_URL is reachable, falling back transparently to thread-safe in-memory storage.
    """

    def __init__(self):
        self.backend_type = "in-memory"
        self._redis = None
        if settings.REDIS_URL and redis is not None:
            try:
                client = redis.from_url(settings.REDIS_URL, decode_responses=True, socket_connect_timeout=1)
                client.ping()
                self._redis = client
                self.backend_type = "redis"
            except Exception:
                self._redis = None
                self.backend_type = "in-memory"

        # In-memory sliding window: key -> {window_id: count}
        self._windows: Dict[str, Dict[int, int]] = {}
        # In-memory token buckets: key -> {"tokens": float, "last_ts": float}
        self._buckets: Dict[str, Dict[str, float]] = {}
        # Track recent client activity for dashboard Live Usage Meters
        self._client_usage: Dict[str, Dict[str, Any]] = {}

    def check_and_consume(
        self,
        key: str,
        limit_rpm: int = 60,
        burst_capacity: int = 15,
        window_seconds: int = 60,
        cost: int = 1,
    ) -> Tuple[bool, Dict[str, str], Dict[str, Any]]:
        """
        Evaluates both Sliding Window Counter and Token Bucket.
        Returns (allowed, rate_limit_headers, telemetry_dict).
        """
        now = time.time()
        limit_rpm = max(1, limit_rpm)
        burst_capacity = max(1, burst_capacity)

        # 1. Sliding Window Counter approximation
        current_window = int(now // window_seconds)
        prev_window = current_window - 1
        elapsed_in_window = (now % window_seconds) / float(window_seconds)

        win_store = self._windows.setdefault(key, {})
        # Cleanup older windows
        for old_w in list(win_store.keys()):
            if old_w < prev_window:
                del win_store[old_w]

        prev_count = win_store.get(prev_window, 0)
        curr_count = win_store.get(current_window, 0)

        weighted_count = prev_count * (1.0 - elapsed_in_window) + curr_count

        # 2. Token Bucket burst control
        refill_rate = limit_rpm / float(window_seconds)
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = {"tokens": float(burst_capacity), "last_ts": now}
            self._buckets[key] = bucket
        else:
            delta = max(0.0, now - bucket["last_ts"])
            bucket["tokens"] = min(float(burst_capacity), bucket["tokens"] + delta * refill_rate)
            bucket["last_ts"] = now

        reset_seconds = max(1, int(math.ceil(window_seconds - (now % window_seconds))))

        if weighted_count + cost > limit_rpm or bucket["tokens"] < cost:
            remaining = 0
            retry_after = max(1, min(reset_seconds, int(math.ceil((cost - bucket["tokens"]) / max(0.1, refill_rate)))))
            headers = {
                "X-RateLimit-Limit": str(limit_rpm),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(now) + reset_seconds),
                "Retry-After": str(retry_after),
                "X-RateLimit-Policy": f"{limit_rpm};w={window_seconds};burst={burst_capacity}",
            }
            reason = (
                f"Sliding window rate limit exceeded ({int(weighted_count)}/{limit_rpm} req/min)"
                if weighted_count + cost > limit_rpm
                else f"Token bucket burst capacity exhausted (burst limit={burst_capacity})"
            )
            self._record_meter(key, int(weighted_count), limit_rpm, burst_capacity, 0.0, throttled=True)
            return False, headers, {
                "weighted_count": round(weighted_count, 1),
                "limit_rpm": limit_rpm,
                "burst_capacity": burst_capacity,
                "tokens_left": round(bucket["tokens"], 2),
                "reason": reason,
            }

        # Consume
        win_store[current_window] = curr_count + cost
        bucket["tokens"] -= cost
        new_weighted = weighted_count + cost
        remaining = max(0, int(limit_rpm - math.floor(new_weighted)))

        headers = {
            "X-RateLimit-Limit": str(limit_rpm),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(int(now) + reset_seconds),
            "X-RateLimit-Policy": f"{limit_rpm};w={window_seconds};burst={burst_capacity}",
        }
        self._record_meter(key, int(new_weighted), limit_rpm, burst_capacity, round(bucket["tokens"], 2), throttled=False)
        return True, headers, {
            "weighted_count": round(new_weighted, 1),
            "limit_rpm": limit_rpm,
            "burst_capacity": burst_capacity,
            "tokens_left": round(bucket["tokens"], 2),
            "reason": "Within rate & burst limits",
        }

    def _record_meter(
        self,
        key: str,
        current_count: int,
        limit_rpm: int,
        burst_capacity: int,
        tokens_left: float,
        throttled: bool,
    ):
         existing = self._client_usage.get(key, {"throttled_count": 0})
         self._client_usage[key] = {
            "key": key,
            "current_rpm": current_count,
            "limit_rpm": limit_rpm,
            "utilization_pct": min(100, round((current_count / max(1, limit_rpm)) * 100, 1)),
            "burst_capacity": burst_capacity,
            "tokens_remaining": tokens_left,
            "throttled_count": existing.get("throttled_count", 0) + (1 if throttled else 0),
            "last_seen": time.time(),
        }

    def get_active_meters(self) -> List[Dict[str, Any]]:
        items = list(self._client_usage.values())
        items.sort(key=lambda x: x.get("utilization_pct", 0), reverse=True)
        return items[:30]

    def reset_key(self, key: str):
        self._windows.pop(key, None)
        self._buckets.pop(key, None)
        self._client_usage.pop(key, None)


rate_limiter = HybridRateLimiter()
