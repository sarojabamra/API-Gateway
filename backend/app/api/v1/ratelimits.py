from fastapi import APIRouter, Depends, HTTPException, Query, Request
import httpx
from pydantic import BaseModel
from sqlmodel import Session, select

from app.db import get_session
from app.models import ClientBaseline, Route, Upstream, User
from app.schemas import RateLimitBurstTestRequest
from app.api.v1.deps import get_current_user, require_roles
from app.api.v1.org_access import require_visible_project, require_visible_route
from app.gateway.ratelimit import rate_limiter

router = APIRouter(prefix="/ratelimits", tags=["Rate Limiting & Velocity Studio"])


@router.get("")
def get_rate_limits_overview(
    upstream_id: int = Query(1),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
):
    require_visible_project(session, user, upstream_id)
    routes = session.exec(
        select(Route)
        .where(Route.registered == True, Route.upstream_id == upstream_id)
        .order_by(Route.id)
    ).all()
    baselines = [
        item
        for item in session.exec(select(ClientBaseline).order_by(ClientBaseline.last_zscore.desc())).all()
        if (item.client_key or "").startswith(f"{upstream_id}:")
    ]

    return {
        "backend_engine": rate_limiter.backend_type,
        "algorithms": [
            "Redis Fixed Window Counter (60s)" if rate_limiter.backend_type == "redis" else "Fixed Window Counter (60s)",
            "Redis Token Bucket (Burst Capacity)" if rate_limiter.backend_type == "redis" else "Token Bucket (Burst Capacity)",
        ],
        "route_limits": [
            {
                "id": r.id,
                "method": r.method,
                "path_pattern": r.path_pattern,
                "description": r.description,
                "rate_limit_rpm": r.rate_limit_rpm,
                "burst_capacity": r.burst_capacity,
                "is_sensitive_flow": r.is_sensitive_flow,
                "owasp_id": "API6" if r.is_sensitive_flow else "API4",
                "hit_count": r.hit_count,
            }
            for r in routes
        ],
        "active_meters": rate_limiter.get_active_meters(),
        "client_baselines": [
            {
                "client_key": b.client_key,
                "mean_rpm": b.mean_rpm,
                "std_rpm": b.std_rpm,
                "current_rpm": b.current_rpm,
                "last_zscore": b.last_zscore,
            }
            for b in baselines[:15]
        ],
    }


class RouteRateLimitUpdate(BaseModel):
    rate_limit_rpm: int
    burst_capacity: int
    is_sensitive_flow: bool = False


@router.patch("/routes/{route_id}")
def update_route_rate_limit(
    route_id: int,
    payload: RouteRateLimitUpdate,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "analyst", "developer"])),
):
    route = require_visible_route(session, _user, session.get(Route, route_id))
    route.rate_limit_rpm = payload.rate_limit_rpm
    route.burst_capacity = payload.burst_capacity
    route.is_sensitive_flow = payload.is_sensitive_flow
    session.add(route)
    session.commit()
    session.refresh(route)
    return {
        "id": route.id,
        "path_pattern": route.path_pattern,
        "rate_limit_rpm": route.rate_limit_rpm,
        "burst_capacity": route.burst_capacity,
        "is_sensitive_flow": route.is_sensitive_flow,
    }


@router.post("/test-burst")
async def run_rate_limit_burst_test(
    payload: RateLimitBurstTestRequest,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
):
    """
    Simulates N rapid requests through /gw/{path} from a test client IP and returns
    per-request status codes and X-RateLimit-* headers so users can watch fixed-window
    and token-bucket throttling live.
    """
    from app.gateway.auth import infer_simulator_subject, mint_demo_jwt

    count = min(max(1, payload.request_count), 60)
    clean_path = payload.path.lstrip("/")
    upstream = require_visible_project(session, user, payload.upstream_id)
    gateway_path = f"/gw/{upstream.slug}/{clean_path}"
    jwt_token = mint_demo_jwt(
        sub=infer_simulator_subject(session, payload.upstream_id, path=clean_path),
        email="burst-tester@sentinel.local",
        role="user",
        session=session,
        upstream_id=payload.upstream_id,
    )["token"]

    results = []
    transport = httpx.ASGITransport(app=request.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://local-gateway") as client:
        for i in range(1, count + 1):
            headers = {
                "Authorization": f"Bearer {jwt_token}",
                "X-Simulated-Client-IP": payload.client_ip,
                "User-Agent": "SentinelGW-BurstTester/1.0",
            }
            if payload.method.upper() == "POST":
                resp = await client.post(gateway_path, json={"code": "BURST50"}, headers=headers)
            else:
                resp = await client.get(gateway_path, headers=headers)

            results.append({
                "seq": i,
                "status_code": resp.status_code,
                "decision": resp.headers.get("X-Gateway-Decision", "allowed" if resp.status_code < 400 else "rate_limited"),
                "limit": resp.headers.get("X-RateLimit-Limit", "-"),
                "remaining": resp.headers.get("X-RateLimit-Remaining", "0"),
                "reset": resp.headers.get("X-RateLimit-Reset", "-"),
                "retry_after": resp.headers.get("Retry-After", "-"),
            })

    allowed_cnt = sum(1 for r in results if r["status_code"] < 400)
    throttled_cnt = sum(1 for r in results if r["status_code"] == 429)

    return {
        "upstream_id": upstream.id,
        "project_name": upstream.name,
        "target": f"{payload.method.upper()} {gateway_path}",
        "client_ip": payload.client_ip,
        "total_sent": count,
        "allowed_count": allowed_cnt,
        "throttled_429_count": throttled_cnt,
        "results": results,
    }
