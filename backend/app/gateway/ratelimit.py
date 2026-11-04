import math
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from redis.exceptions import RedisError

from app.gateway.redis_client import redis_handle


# Atomic fixed-window counter + token bucket.
# KEYS[1] clock-aligned window counter, KEYS[2] token bucket hash.
# Returns {allowed, count, tokens, reason} where reason is 0 ok, 1 window, 2 burst.
_CONSUME_SCRIPT = """
local limit = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local now = tonumber(ARGV[4])
local refill = tonumber(ARGV[5])
local bucket_ttl = tonumber(ARGV[6])
local window_ttl = tonumber(ARGV[7])

local count = tonumber(redis.call('GET', KEYS[1]) or '0')

local tokens_raw = redis.call('HGET', KEYS[2], 'tokens')
local last_raw = redis.call('HGET', KEYS[2], 'last_ts')
local tokens
local last_ts
if not tokens_raw then
  tokens = burst
  last_ts = now
else
  tokens = tonumber(tokens_raw)
  last_ts = tonumber(last_raw)
  local delta = now - last_ts
  if delta < 0 then delta = 0 end
  tokens = math.min(burst, tokens + delta * refill)
  last_ts = now
end

local allowed = 0
local reason = 0
if (count + cost) > limit then
  reason = 1
elseif tokens < cost then
  reason = 2
else
  allowed = 1
  count = tonumber(redis.call('INCRBY', KEYS[1], cost))
  if redis.call('TTL', KEYS[1]) < 0 then
    redis.call('EXPIRE', KEYS[1], window_ttl)
  end
  tokens = tokens - cost
end

redis.call('HSET', KEYS[2], 'tokens', string.format('%.6f', tokens), 'last_ts', string.format('%.6f', last_ts))
redis.call('EXPIRE', KEYS[2], bucket_ttl)
return {allowed, count, string.format('%.6f', tokens), reason}
"""


class HybridRateLimiter:
    """
    Sustained rate limit (Redis fixed-window counter) plus short-term burst control
    (Redis token bucket). Both updates run in one Lua script so every gateway
    process shares the same counters. If Redis is not configured, the same rules
    run against process memory.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._windows: Dict[str, Dict[int, int]] = {}
        self._buckets: Dict[str, Dict[str, float]] = {}
        self._client_usage: Dict[str, Dict[str, Any]] = {}

    @property
    def backend_type(self) -> str:
        return "redis" if redis_handle.get() is not None else "in-memory"

    def check_and_consume(
        self,
        key: str,
        limit_rpm: int = 60,
        burst_capacity: int = 15,
        window_seconds: int = 60,
        cost: int = 1,
    ) -> Tuple[bool, Dict[str, str], Dict[str, Any]]:
        now = time.time()
        limit_rpm = max(1, limit_rpm)
        burst_capacity = max(1, burst_capacity)
        window_seconds = max(1, window_seconds)
        cost = max(1, cost)

        redis_result = self._consume_redis(key, limit_rpm, burst_capacity, window_seconds, cost, now)
        if redis_result is not None:
            allowed, count, tokens, reason_code = redis_result
        else:
            allowed, count, tokens, reason_code = self._consume_memory(
                key, limit_rpm, burst_capacity, window_seconds, cost, now
            )

        refill_rate = limit_rpm / float(window_seconds)
        reset_seconds = max(1, int(math.ceil(window_seconds - (now % window_seconds))))
        engine = "Redis" if redis_result is not None else "Local"

        if not allowed:
            if reason_code == 1:
                retry_after = reset_seconds
                reason = f"{engine} fixed-window rate limit exceeded ({int(count)}/{limit_rpm} req/min)"
            else:
                deficit = max(0.0, cost - tokens)
                retry_after = max(1, int(math.ceil(deficit / max(0.1, refill_rate))))
                reason = f"{engine} token bucket burst capacity exhausted (burst limit={burst_capacity})"
            headers = {
                "X-RateLimit-Limit": str(limit_rpm),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(now) + reset_seconds),
                "Retry-After": str(retry_after),
                "X-RateLimit-Policy": f"{limit_rpm};w={window_seconds};burst={burst_capacity}",
            }
            self._record_meter(key, int(count), limit_rpm, burst_capacity, round(max(0.0, tokens), 2), True)
            return False, headers, {
                "weighted_count": round(float(count), 1),
                "limit_rpm": limit_rpm,
                "burst_capacity": burst_capacity,
                "tokens_left": round(max(0.0, tokens), 2),
                "reason": reason,
            }

        remaining = max(0, int(limit_rpm - math.floor(count)))
        headers = {
            "X-RateLimit-Limit": str(limit_rpm),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(int(now) + reset_seconds),
            "X-RateLimit-Policy": f"{limit_rpm};w={window_seconds};burst={burst_capacity}",
        }
        self._record_meter(key, int(count), limit_rpm, burst_capacity, round(tokens, 2), False)
        return True, headers, {
            "weighted_count": round(float(count), 1),
            "limit_rpm": limit_rpm,
            "burst_capacity": burst_capacity,
            "tokens_left": round(tokens, 2),
            "reason": "Within rate and burst limits",
        }

    def _consume_redis(
        self,
        key: str,
        limit_rpm: int,
        burst_capacity: int,
        window_seconds: int,
        cost: int,
        now: float,
    ) -> Optional[Tuple[bool, float, float, int]]:
        client = redis_handle.get()
        if client is None:
            return None
        window_id = int(now // window_seconds)
        window_key = f"sgw:rl:win:{key}:{window_id}"
        bucket_key = f"sgw:rl:bucket:{key}"
        refill = limit_rpm / float(window_seconds)
        try:
            allowed, count, tokens, reason = client.eval(
                _CONSUME_SCRIPT,
                2,
                window_key,
                bucket_key,
                limit_rpm,
                burst_capacity,
                cost,
                f"{now:.6f}",
                f"{refill:.6f}",
                max(window_seconds * 2, 600),
                window_seconds * 2,
            )
            return bool(int(allowed)), float(count), float(tokens), int(reason)
        except RedisError:
            redis_handle.mark_down()
            return None

    def _consume_memory(
        self,
        key: str,
        limit_rpm: int,
        burst_capacity: int,
        window_seconds: int,
        cost: int,
        now: float,
    ) -> Tuple[bool, float, float, int]:
        window_id = int(now // window_seconds)
        refill_rate = limit_rpm / float(window_seconds)
        with self._lock:
            win_store = self._windows.setdefault(key, {})
            for old_w in list(win_store.keys()):
                if old_w < window_id:
                    del win_store[old_w]
            count = win_store.get(window_id, 0)

            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = {"tokens": float(burst_capacity), "last_ts": now}
                self._buckets[key] = bucket
            else:
                delta = max(0.0, now - bucket["last_ts"])
                bucket["tokens"] = min(float(burst_capacity), bucket["tokens"] + delta * refill_rate)
                bucket["last_ts"] = now

            if count + cost > limit_rpm:
                return False, float(count), float(bucket["tokens"]), 1
            if bucket["tokens"] < cost:
                return False, float(count), float(bucket["tokens"]), 2

            win_store[window_id] = count + cost
            bucket["tokens"] -= cost
            return True, float(count + cost), float(bucket["tokens"]), 0

    def _record_meter(
        self,
        key: str,
        current_count: int,
        limit_rpm: int,
        burst_capacity: int,
        tokens_left: float,
        throttled: bool,
    ) -> None:
        snapshot = {
            "key": key,
            "current_rpm": current_count,
            "limit_rpm": limit_rpm,
            "utilization_pct": min(100, round((current_count / max(1, limit_rpm)) * 100, 1)),
            "burst_capacity": burst_capacity,
            "tokens_remaining": tokens_left,
            "last_seen": time.time(),
        }
        client = redis_handle.get()
        if client is not None:
            try:
                meter_key = f"sgw:rl:meter:{key}"
                pipe = client.pipeline()
                pipe.hset(meter_key, mapping={k: str(v) for k, v in snapshot.items()})
                pipe.hsetnx(meter_key, "throttled_count", "0")
                if throttled:
                    pipe.hincrby(meter_key, "throttled_count", 1)
                pipe.expire(meter_key, 600)
                pipe.sadd("sgw:rl:meters", key)
                pipe.execute()
                return
            except RedisError:
                redis_handle.mark_down()

        with self._lock:
            existing = self._client_usage.get(key, {"throttled_count": 0})
            snapshot["throttled_count"] = existing.get("throttled_count", 0) + (1 if throttled else 0)
            self._client_usage[key] = snapshot

    def get_active_meters(self) -> List[Dict[str, Any]]:
        client = redis_handle.get()
        if client is not None:
            try:
                return self._meters_from_redis(client)
            except RedisError:
                redis_handle.mark_down()
        with self._lock:
            now = time.time()
            items = [m for m in self._client_usage.values() if now - float(m.get("last_seen", 0)) < 600]
            items.sort(key=lambda x: x.get("utilization_pct", 0), reverse=True)
            return items[:30]

    def _meters_from_redis(self, client) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for member in client.smembers("sgw:rl:meters"):
            raw = client.hgetall(f"sgw:rl:meter:{member}")
            if not raw:
                client.srem("sgw:rl:meters", member)
                continue
            items.append({
                "key": raw.get("key", member),
                "current_rpm": int(float(raw.get("current_rpm", 0))),
                "limit_rpm": int(float(raw.get("limit_rpm", 0))),
                "utilization_pct": float(raw.get("utilization_pct", 0)),
                "burst_capacity": int(float(raw.get("burst_capacity", 0))),
                "tokens_remaining": float(raw.get("tokens_remaining", 0)),
                "throttled_count": int(float(raw.get("throttled_count", 0))),
                "last_seen": float(raw.get("last_seen", 0)),
            })
        items.sort(key=lambda x: x.get("utilization_pct", 0), reverse=True)
        return items[:30]

    def reset_key(self, key: str) -> None:
        client = redis_handle.get()
        if client is not None:
            try:
                pipe = client.pipeline()
                for window_key in client.scan_iter(match=f"sgw:rl:win:{key}:*", count=100):
                    pipe.delete(window_key)
                pipe.delete(f"sgw:rl:bucket:{key}", f"sgw:rl:meter:{key}")
                pipe.srem("sgw:rl:meters", key)
                pipe.execute()
            except RedisError:
                redis_handle.mark_down()
        with self._lock:
            self._windows.pop(key, None)
            self._buckets.pop(key, None)
            self._client_usage.pop(key, None)


rate_limiter = HybridRateLimiter()
