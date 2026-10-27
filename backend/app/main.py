from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session

from app.config import settings
from app.db import create_db_and_tables, engine
from app.seed import seed_all_data

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


@asynccontextmanager
async def lifespan(_app: FastAPI):
    create_db_and_tables()
    with Session(engine) as session:
        seed_all_data(session, force_reset=False)
    yield


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
app.include_router(auth_router, prefix="/api/v1")
app.include_router(overview_router, prefix="/api/v1")
app.include_router(traffic_router, prefix="/api/v1")
app.include_router(alerts_router, prefix="/api/v1")
app.include_router(policies_router, prefix="/api/v1")
app.include_router(ratelimits_router, prefix="/api/v1")
app.include_router(routes_router, prefix="/api/v1")
app.include_router(blocklist_router, prefix="/api/v1")
app.include_router(analytics_router, prefix="/api/v1")
app.include_router(owasp_router, prefix="/api/v1")
app.include_router(simulator_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")
app.include_router(settings_router, prefix="/api/v1")

# 3. Mount WebSocket Realtime Hub at /ws/live
app.include_router(ws_router)

# 4. Mount Reverse-Proxy Security Gateway at /gw/{path:path}
app.include_router(gateway_proxy_router)


@app.get("/health")
def health_check():
    return {"status": "healthy", "service": settings.APP_NAME}
