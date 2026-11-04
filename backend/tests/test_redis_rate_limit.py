import time

import pytest
from sqlmodel import Session, SQLModel, create_engine

import app.models  # noqa: F401  (register tables on SQLModel.metadata)
from app.config import settings
from app.detection.anomaly import RollingAnomalyDetector
from app.gateway.ratelimit import HybridRateLimiter
from app.gateway.redis_client import redis_handle


def _use_memory(monkeypatch):
    monkeypatch.setattr(settings, "REDIS_URL", None)
    redis_handle.mark_down()
    redis_handle._down_until = 0.0
    redis_handle._client = None
    redis_handle._url = None


def test_fixed_window_blocks_after_sustained_limit(monkeypatch):
    _use_memory(monkeypatch)
    limiter = HybridRateLimiter()
    key = "window-test"
    decisions = [
        limiter.check_and_consume(key, limit_rpm=3, burst_capacity=20, window_seconds=60)[0]
        for _ in range(4)
    ]
    assert decisions == [True, True, True, False]
    reason = limiter.check_and_consume(key, limit_rpm=3, burst_capacity=20, window_seconds=60)[2]["reason"]
    assert "fixed-window" in reason


def test_token_bucket_blocks_short_burst(monkeypatch):
    _use_memory(monkeypatch)
    limiter = HybridRateLimiter()
    key = "burst-test"
    decisions = [
        limiter.check_and_consume(key, limit_rpm=60, burst_capacity=3, window_seconds=60)[0]
        for _ in range(4)
    ]
    assert decisions == [True, True, True, False]
    _, headers, meta = limiter.check_and_consume(key, limit_rpm=60, burst_capacity=3, window_seconds=60)
    assert headers["X-RateLimit-Remaining"] == "0"
    assert int(headers["Retry-After"]) >= 1
    assert "burst" in meta["reason"]


def test_reset_key_clears_local_counters(monkeypatch):
    _use_memory(monkeypatch)
    limiter = HybridRateLimiter()
    key = "reset-test"
    for _ in range(3):
        limiter.check_and_consume(key, limit_rpm=3, burst_capacity=3, window_seconds=60)
    limiter.reset_key(key)
    allowed, _, _ = limiter.check_and_consume(key, limit_rpm=3, burst_capacity=3, window_seconds=60)
    assert allowed is True


def test_meters_report_utilization(monkeypatch):
    _use_memory(monkeypatch)
    limiter = HybridRateLimiter()
    limiter.check_and_consume("meter-client", limit_rpm=10, burst_capacity=10, window_seconds=60)
    meters = limiter.get_active_meters()
    assert meters[0]["key"] == "meter-client"
    assert meters[0]["current_rpm"] == 1
    assert meters[0]["utilization_pct"] == 10.0


def test_burst_score_rises_above_baseline(monkeypatch):
    _use_memory(monkeypatch)
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    detector = RollingAnomalyDetector()
    with Session(engine) as session:
        quiet, _ = detector.record_and_score(session, "quiet-client")
        session.commit()
        for _ in range(15):
            zscore, stats = detector.record_and_score(session, "burst-client")
        session.commit()
    assert quiet == 0.0
    assert stats["current_rpm"] == 60
    assert zscore >= 3.0


def test_redis_rate_limit_and_burst_detection_when_available(monkeypatch):
    url = "redis://127.0.0.1:6379/15"
    monkeypatch.setattr(settings, "REDIS_URL", url)
    redis_handle.mark_down()
    redis_handle._down_until = 0.0
    client = redis_handle.get()
    if client is None:
        pytest.skip("Redis is not running on 127.0.0.1:6379")
    client.flushdb()

    limiter = HybridRateLimiter()
    assert limiter.backend_type == "redis"
    key = f"redis-burst-{time.time_ns()}"
    allowed = [
        limiter.check_and_consume(key, limit_rpm=60, burst_capacity=2, window_seconds=60)[0]
        for _ in range(3)
    ]
    assert allowed == [True, True, False]
    meters = limiter.get_active_meters()
    assert any(m["key"] == key and m["throttled_count"] >= 1 for m in meters)
    limiter.reset_key(key)
    assert limiter.check_and_consume(key, limit_rpm=60, burst_capacity=2, window_seconds=60)[0] is True

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    detector = RollingAnomalyDetector()
    with Session(engine) as session:
        for _ in range(12):
            zscore, stats = detector.record_and_score(session, "redis-shared-burst")
        session.commit()
    assert stats["current_rpm"] == 48
    assert zscore >= 3.0
