from datetime import datetime, timezone
import json
import math
import threading
import time
from typing import Dict, List, Optional, Tuple

from redis.exceptions import RedisError
from sqlmodel import Session, select

from app.gateway.redis_client import redis_handle
from app.models import ClientBaseline


_SEED_RPM = [4, 5, 6, 4, 5, 7, 5, 6, 4, 5, 6, 5]

# KEYS[1] bucket hash, KEYS[2] history list.
# ARGV[1] current 15s bucket id, ARGV[2] comma-separated seed RPM samples.
# Returns {current_bucket_count, hist...}.
_RECORD_SCRIPT = """
local current = tonumber(ARGV[1])
redis.call('HINCRBY', KEYS[1], tostring(current), 1)

local all = redis.call('HGETALL', KEYS[1])
local old = {}
for i = 1, #all, 2 do
  local bid = tonumber(all[i])
  if bid < current - 1 then
    table.insert(old, {id = bid, rpm = tonumber(all[i + 1]) * 4})
    redis.call('HDEL', KEYS[1], all[i])
  end
end
table.sort(old, function(a, b) return a.id < b.id end)

if redis.call('LLEN', KEYS[2]) == 0 then
  for part in string.gmatch(ARGV[2], '([^,]+)') do
    redis.call('RPUSH', KEYS[2], part)
  end
end
for _, item in ipairs(old) do
  redis.call('RPUSH', KEYS[2], tostring(item.rpm))
end
redis.call('LTRIM', KEYS[2], -30, -1)
redis.call('EXPIRE', KEYS[1], 120)
redis.call('EXPIRE', KEYS[2], 3600)

local cur = redis.call('HGET', KEYS[1], tostring(current))
local hist = redis.call('LRANGE', KEYS[2], 0, -1)
table.insert(hist, 1, cur)
return hist
"""


class RollingAnomalyDetector:
    """
    Per-client burst detector. Request counts live in Redis 15-second buckets and
    the completed-bucket history is a Redis list, shared by every gateway process.
    Z = (current_window_rate - mean_rpm) / std_rpm. Bursts are flagged when Z >= 3.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: Dict[str, Dict[int, int]] = {}
        self._history: Dict[str, List[int]] = {}
        self._last_persist: Dict[str, float] = {}

    def record_and_score(self, session: Session, client_key: str) -> Tuple[float, Dict[str, float]]:
        now = int(time.time())
        current_bucket = now // 15
        recorded = self._record_redis(client_key, current_bucket)
        if recorded is None:
            current_count, hist = self._record_memory(client_key, current_bucket)
        else:
            current_count, hist = recorded

        current_rpm = current_count * 4
        mean_rpm = sum(hist) / float(len(hist)) if hist else 5.0
        variance = sum((x - mean_rpm) ** 2 for x in hist) / float(max(1, len(hist)))
        std_rpm = max(1.5, math.sqrt(variance))
        zscore = round((current_rpm - mean_rpm) / std_rpm, 2) if current_rpm > mean_rpm else 0.0

        last_write = self._last_persist.get(client_key, 0)
        should_persist = (now - last_write) >= 5 or last_write == 0
        if should_persist:
            baseline = session.exec(select(ClientBaseline).where(ClientBaseline.client_key == client_key)).first()
            if not baseline:
                baseline = ClientBaseline(
                    client_key=client_key,
                    window_counts_json=json.dumps(hist[-15:]),
                    mean_rpm=round(mean_rpm, 2),
                    std_rpm=round(std_rpm, 2),
                    current_rpm=current_rpm,
                    last_zscore=zscore,
                    last_updated_at=datetime.now(timezone.utc),
                )
                session.add(baseline)
            else:
                baseline.window_counts_json = json.dumps(hist[-15:])
                baseline.mean_rpm = round(mean_rpm, 2)
                baseline.std_rpm = round(std_rpm, 2)
                baseline.current_rpm = current_rpm
                baseline.last_zscore = max(zscore, baseline.last_zscore if current_rpm > 12 else zscore)
                baseline.last_updated_at = datetime.now(timezone.utc)
                session.add(baseline)
            self._last_persist[client_key] = float(now)

        return zscore, {
            "current_rpm": current_rpm,
            "mean_rpm": round(mean_rpm, 2),
            "std_rpm": round(std_rpm, 2),
            "zscore": zscore,
        }

    def _record_redis(self, client_key: str, current_bucket: int) -> Optional[Tuple[int, List[int]]]:
        client = redis_handle.get()
        if client is None:
            return None
        seed = ",".join(str(v) for v in _SEED_RPM)
        try:
            raw = client.eval(
                _RECORD_SCRIPT,
                2,
                f"sgw:an:buckets:{client_key}",
                f"sgw:an:hist:{client_key}",
                current_bucket,
                seed,
            )
        except RedisError:
            redis_handle.mark_down()
            return None
        if not raw:
            return 0, list(_SEED_RPM)
        current_count = int(raw[0])
        hist = [int(float(v)) for v in raw[1:]] or list(_SEED_RPM)
        return current_count, hist

    def _record_memory(self, client_key: str, current_bucket: int) -> Tuple[int, List[int]]:
        with self._lock:
            client_win = self._buckets.setdefault(client_key, {})
            client_win[current_bucket] = client_win.get(current_bucket, 0) + 1
            hist = self._history.setdefault(client_key, list(_SEED_RPM))
            completed = []
            for b_id in list(client_win.keys()):
                if b_id < current_bucket - 1:
                    completed.append((b_id, client_win.pop(b_id) * 4))
            for _, rpm in sorted(completed):
                hist.append(rpm)
                if len(hist) > 30:
                    hist.pop(0)
            return client_win[current_bucket], list(hist)


anomaly_detector = RollingAnomalyDetector()
