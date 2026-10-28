from fastapi import APIRouter, Depends, HTTPException, Query, Request
import httpx
from pydantic import BaseModel
from sqlmodel import Session, select

from app.db import get_session
from app.models import ClientBaseline, Route, Upstream, User
from app.schemas import RateLimitBurstTestRequest
from app.api.v1.deps import require_roles
from app.gateway.ratelimit import rate_limiter

router = APIRouter(prefix="/ratelimits", tags=["Rate Limiting & Velocity Studio"])


@router.get("")
def get_rate_limits_overview(
    upstream_id: int = Query(1),
    session: Session = Depends(get_session),
):
    routes = session.exec(
        select(Route)
        .where(Route.registered == True, Route.upstream_id == upstream_id)
        .order_by(Route.id)
    ).all()
    baselines = session.exec(select(ClientBaseline).order_by(ClientBaseline.last_zscore.desc())).all()

    return {
        "backend_engine": rate_limiter.backend_type,
        "algorithms": ["Sliding Window Counter (60s window)", "Token Bucket (Burst Capacity Control)"],
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
    route = session.get(Route, route_id)
    if not route:
        raise HTTPException(status_code=404, detail="Route not found")
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
):
    """
    Simulates N rapid requests through /gw/{path} from a test client IP and returns
    per-request status codes and X-RateLimit-* headers so users can watch token bucket
    and sliding window throttling live.
    """
    from app.gateway.auth import mint_demo_jwt

    count = min(max(1, payload.request_count), 60)
    clean_path = payload.path.lstrip("/")
    upstream = session.get(Upstream, payload.upstream_id)
    if not upstream:
        raise HTTPException(status_code=404, detail="Selected API project was not found")
    gateway_path = f"/gw/{upstream.slug}/{clean_path}"
    jwt_token = mint_demo_jwt(sub="burst-tester", role="user")["token"]

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
