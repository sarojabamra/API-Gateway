from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlmodel import Session, select
from app.db import get_session
from app.models import Route, Upstream
from pydantic import BaseModel
from app.models import User
from app.schemas import SimulatorRunRequest, SimulatorTokenValidateRequest
from app.api.v1.deps import require_roles
from app.attack_sim.scenarios import SCENARIO_CATALOG, execute_attack_scenario
from app.attack_sim.targeting import list_scenario_route_options, plan_scenario_targets
from app.gateway.auth import resolve_simulator_user_jwt
from app.gateway.pipeline import gateway_state

router = APIRouter(prefix="/simulator", tags=["Attack Simulator & Gateway Mode Switch"])


@router.get("/scenarios")
def list_attack_scenarios(
    upstream_id: int = Query(1),
    session: Session = Depends(get_session),
):
    upstream = session.get(Upstream, upstream_id)
    if not upstream:
        raise HTTPException(status_code=404, detail="Selected API project was not found")
    routes = session.exec(
        select(Route).where(Route.upstream_id == upstream_id, Route.registered == True)
    ).all()
    enriched = []
    for sc in SCENARIO_CATALOG:
        plan = plan_scenario_targets(sc["id"], routes)
        selectable = list_scenario_route_options(sc["id"], routes)
        auto_targets = []
        for role, sel in plan.selections.items():
            if sel.route is None:
                continue
            auto_targets.append(
                {
                    "role": role,
                    "route_id": sel.route.id,
                    "method": sel.route.method,
                    "path_pattern": sel.route.path_pattern,
                    "reason": sel.reason,
                }
            )
        enriched.append(
            {
                **sc,
                "applicable": plan.applicable,
                "skip_reason": plan.skip_reason,
                "auto_targets": auto_targets,
                "selectable_roles": selectable,
            }
        )
    return {
        "gateway_enabled": gateway_state.gateway_enabled,
        "upstream": {
            "id": upstream.id,
            "name": upstream.name,
            "slug": upstream.slug,
        },
        "scenarios": enriched,
    }


class GatewayToggleInput(BaseModel):
    gateway_enabled: bool


@router.post("/gateway-toggle")
def toggle_gateway_protection(
    payload: GatewayToggleInput,
    _user: User = Depends(require_roles(["admin", "analyst", "developer"])),
):
    gateway_state.gateway_enabled = payload.gateway_enabled
    return {
        "gateway_enabled": gateway_state.gateway_enabled,
        "status_text": "GATEWAY ARMED (ENFORCING OWASP POLICIES)" if gateway_state.gateway_enabled else "GATEWAY BYPASSED (UPSTREAM EXPOSED DIRECTLY)",
    }


@router.post("/validate-token")
def validate_simulator_token(
    payload: SimulatorTokenValidateRequest,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "analyst", "developer"])),
):
    if not (payload.token or "").strip():
        raise HTTPException(status_code=400, detail="Invalid JWT: token is empty")
    try:
        resolved = resolve_simulator_user_jwt(payload.token, session, payload.upstream_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "valid": True,
        "source": resolved["source"],
        "subject": resolved["subject"],
        "header": resolved["header"],
        "payload": resolved["payload"],
    }


@router.post("/run")
async def run_attack_simulation(
    payload: SimulatorRunRequest,
    request: Request,
    _user: User = Depends(require_roles(["admin", "analyst", "developer"])),
):
    try:
        return await execute_attack_scenario(
            payload.scenario_id,
            request.app,
            payload.upstream_id,
            payload.auth_token,
            payload.route_id,
            payload.route_overrides,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
