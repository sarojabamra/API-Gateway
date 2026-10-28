from datetime import datetime, timezone
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.db import get_session
from app.models import Policy, User, to_ist_iso
from app.schemas import PolicyCreate, PolicyUpdate
from app.api.v1.deps import require_roles

router = APIRouter(prefix="/policies", tags=["Security Policies Engine"])


@router.get("")
def list_policies(session: Session = Depends(get_session)):
    policies = session.exec(select(Policy).order_by(Policy.owasp_id, Policy.id)).all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "type": p.type,
            "scope": p.scope,
            "target_id": p.target_id,
            "owasp_id": p.owasp_id,
            "mode": p.mode,  # enforce | monitor
            "config": json.loads(p.config_json or "{}"),
            "enabled": p.enabled,
            "updated_at": to_ist_iso(p.updated_at),
        }
        for p in policies
    ]


@router.post("")
def create_policy(
    payload: PolicyCreate,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "analyst", "developer"])),
):
    pol = Policy(
        name=payload.name,
        description=payload.description,
        type=payload.type,
        scope=payload.scope,
        target_id=payload.target_id,
        owasp_id=payload.owasp_id,
        mode=payload.mode,
        config_json=json.dumps(payload.config),
        enabled=payload.enabled,
        updated_at=datetime.now(timezone.utc),
    )
    session.add(pol)
    session.commit()
    session.refresh(pol)
    return {
        "id": pol.id,
        "name": pol.name,
        "description": pol.description,
        "type": pol.type,
        "scope": pol.scope,
        "owasp_id": pol.owasp_id,
        "mode": pol.mode,
        "config": payload.config,
        "enabled": pol.enabled,
    }


@router.patch("/{policy_id}")
def update_policy(
    policy_id: int,
    payload: PolicyUpdate,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "analyst", "developer"])),
):
    pol = session.get(Policy, policy_id)
    if not pol:
        raise HTTPException(status_code=404, detail="Policy not found")
    if payload.name is not None:
        pol.name = payload.name
    if payload.description is not None:
        pol.description = payload.description
    if payload.mode is not None:
        pol.mode = payload.mode
    if payload.enabled is not None:
        pol.enabled = payload.enabled
    if payload.config is not None:
        pol.config_json = json.dumps(payload.config)
    pol.updated_at = datetime.now(timezone.utc)
    session.add(pol)
    session.commit()
    session.refresh(pol)
    return {
        "id": pol.id,
        "name": pol.name,
        "description": pol.description,
        "type": pol.type,
        "scope": pol.scope,
        "owasp_id": pol.owasp_id,
        "mode": pol.mode,
        "config": json.loads(pol.config_json or "{}"),
        "enabled": pol.enabled,
        "updated_at": to_ist_iso(pol.updated_at),
    }


@router.delete("/{policy_id}")
def delete_policy(
    policy_id: int,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin"])),
):
    pol = session.get(Policy, policy_id)
    if not pol:
        raise HTTPException(status_code=404, detail="Policy not found")
    session.delete(pol)
    session.commit()
    return {"status": "deleted", "id": policy_id}
