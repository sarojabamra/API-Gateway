from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session

from app.config import settings
from app.db import check_database, create_db_and_tables, engine
from app.gateway.http_client import close_http_client
from app.gateway.ratelimit import rate_limiter
from app.gateway.redis_client import redis_handle
from app.seed import backfill_route_security_defaults, seed_all_data
import app.models  # noqa: F401 — register SQLModel tables before create_all
import app.runtime_cache  # noqa: F401 — register shared-cache invalidation listeners

from app.demo_api.vulnshop import router as vulnshop_router
from app.gateway.proxy import router as gateway_proxy_router
from app.api.v1.auth import router as auth_router
from app.api.v1.overview import router as overview_router
from app.api.v1.traffic import router as traffic_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.policies import router as policies_router
from app.api.v1.ratelimits import router as ratelimits_router
from app.api.v1.routes import router as routes_router
from app.api.v1.blocklist import router as blocklist_router
from app.api.v1.analytics import router as analytics_router
from app.api.v1.owasp import router as owasp_router
from app.api.v1.simulator import router as simulator_router
from app.api.v1.reports import router as reports_router
from app.api.v1.settings import router as settings_router
from app.api.v1.ws import router as ws_router
from app.api.v1.deps import get_current_user


@asynccontextmanager
async def lifespan(_app: FastAPI):
    from app.api.v1.ws import ws_manager

    create_db_and_tables()
    with Session(engine) as session:
        try:
            seed_all_data(session, force_reset=False)
            backfill_route_security_defaults(session)
        except IntegrityError:
            session.rollback()
    await ws_manager.start()
    yield
    await ws_manager.stop()
    await close_http_client()


app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="Reverse-proxy API Security Gateway, OWASP API Top 10 (2023) Policy Engine, and Real-Time Threat Monitoring Control Plane.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[
        "X-Request-ID",
        "X-Gateway-Decision",
        "X-Gateway-OWASP",
        "X-Gateway-Redacted-Fields",
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
        "Retry-After",
    ],
)

# 1. Mount Intentionally Vulnerable Demo Upstream API at /demo/*
app.include_router(vulnshop_router, prefix="/demo")

# 2. Mount Management Control Plane REST API at /api/v1/*
control_plane_auth = [Depends(get_current_user)]
app.include_router(auth_router, prefix="/api/v1")
app.include_router(overview_router, prefix="/api/v1", dependencies=control_plane_auth)
app.include_router(traffic_router, prefix="/api/v1", dependencies=control_plane_auth)
app.include_router(alerts_router, prefix="/api/v1", dependencies=control_plane_auth)
app.include_router(policies_router, prefix="/api/v1", dependencies=control_plane_auth)
app.include_router(ratelimits_router, prefix="/api/v1", dependencies=control_plane_auth)
app.include_router(routes_router, prefix="/api/v1", dependencies=control_plane_auth)
app.include_router(blocklist_router, prefix="/api/v1", dependencies=control_plane_auth)
app.include_router(analytics_router, prefix="/api/v1", dependencies=control_plane_auth)
app.include_router(owasp_router, prefix="/api/v1", dependencies=control_plane_auth)
app.include_router(simulator_router, prefix="/api/v1", dependencies=control_plane_auth)
app.include_router(reports_router, prefix="/api/v1", dependencies=control_plane_auth)
app.include_router(settings_router, prefix="/api/v1", dependencies=control_plane_auth)

# 3. Mount WebSocket Realtime Hub at /ws/live
app.include_router(ws_router)

# 4. Mount Reverse-Proxy Security Gateway at /gw/{path:path}
app.include_router(gateway_proxy_router)


@app.get("/health")
def health_check():
    db_ok = check_database()
    redis_configured = bool((settings.REDIS_URL or "").strip())
    redis_ok = redis_handle.get() is not None
    status = "healthy" if db_ok else "degraded"
    return {
        "status": status,
        "service": settings.APP_NAME,
        "database": "up" if db_ok else "down",
        "redis": "up" if redis_ok else ("configured" if redis_configured else "disabled"),
        "rate_limit_backend": rate_limiter.backend_type,
    }


@app.get("/metrics")
def prometheus_metrics():
    """Lightweight Prometheus text exposition of core gateway counters (no separate stack required)."""
    from sqlmodel import select, func
    from app.models import Alert, RequestLog

    with Session(engine) as session:
        total = session.exec(select(func.count()).select_from(RequestLog)).one()
        blocked = session.exec(
            select(func.count()).select_from(RequestLog).where(RequestLog.decision.in_(["blocked", "rate_limited"]))
        ).one()
        alerts_open = session.exec(
            select(func.count()).select_from(Alert).where(Alert.status.in_(["open", "investigating"]))
        ).one()
        critical = session.exec(
            select(func.count()).select_from(Alert).where(Alert.severity == "critical")
        ).one()

    lines = [
        "# HELP sentinel_requests_total Total gateway request logs",
        "# TYPE sentinel_requests_total counter",
        f"sentinel_requests_total {total}",
        "# HELP sentinel_blocked_total Blocked or rate-limited requests",
        "# TYPE sentinel_blocked_total counter",
        f"sentinel_blocked_total {blocked}",
        "# HELP sentinel_alerts_open Open or investigating alerts",
        "# TYPE sentinel_alerts_open gauge",
        f"sentinel_alerts_open {alerts_open}",
        "# HELP sentinel_alerts_critical Critical severity alerts",
        "# TYPE sentinel_alerts_critical gauge",
        f"sentinel_alerts_critical {critical}",
        "# HELP sentinel_rate_limit_backend 1=redis 0=memory",
        "# TYPE sentinel_rate_limit_backend gauge",
        f'sentinel_rate_limit_backend{{backend="{rate_limiter.backend_type}"}} '
        f"{1 if rate_limiter.backend_type == 'redis' else 0}",
    ]
    from fastapi.responses import PlainTextResponse

    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")
