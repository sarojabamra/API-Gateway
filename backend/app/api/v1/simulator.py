from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlmodel import Session
from app.db import get_session
from app.models import Upstream
from pydantic import BaseModel
from app.models import User
from app.schemas import SimulatorRunRequest
from app.api.v1.deps import require_roles
from app.attack_sim.scenarios import SCENARIO_CATALOG, execute_attack_scenario
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
    return {
        "gateway_enabled": gateway_state.gateway_enabled,
        "upstream": {
            "id": upstream.id,
            "name": upstream.name,
            "slug": upstream.slug,
        },
        "scenarios": SCENARIO_CATALOG,
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
        "status_text": "GATEWAY ARMED (ENFORCING OWASP POLICIES)" if gateway_state.gateway_enabled else "GATEWAY BYPASSED (VULNSHOP EXPOSED DIRECTLY)",
    }


@router.post("/run")
async def run_attack_simulation(
    payload: SimulatorRunRequest,
    request: Request,
    _user: User = Depends(require_roles(["admin", "analyst", "developer"])),
):
    return await execute_attack_scenario(payload.scenario_id, request.app, payload.upstream_id)
