from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.db import get_session
from app.models import BlocklistEntry, User, to_ist_iso
from app.schemas import BlocklistCreateRequest
from app.api.v1.deps import require_roles
from app.gateway.pipeline import gateway_state

router = APIRouter(prefix="/blocklist", tags=["Blocklist & Active Defense"])


@router.get("")
def list_blocklist(session: Session = Depends(get_session)):
    entries = session.exec(select(BlocklistEntry).order_by(BlocklistEntry.created_at.desc())).all()
    return {
        "auto_block_critical": gateway_state.auto_block_critical,
        "auto_block_duration_minutes": gateway_state.auto_block_duration_minutes,
        "items": [
            {
                "id": b.id,
                "target_type": b.target_type,
                "value": b.value,
                "reason": b.reason,
                "owasp_id": b.owasp_id,
                "source": b.source,
                "created_by": b.created_by,
                "created_at": to_ist_iso(b.created_at),
                "expires_at": to_ist_iso(b.expires_at),
                "active": b.active,
            }
            for b in entries
        ],
    }


@router.post("")
def add_to_blocklist(
    payload: BlocklistCreateRequest,
    session: Session = Depends(get_session),
    user: User = Depends(require_roles(["admin", "analyst"])),
):
    existing = session.exec(
        select(BlocklistEntry).where(
            BlocklistEntry.target_type == payload.target_type,
            BlocklistEntry.value == payload.value.strip(),
            BlocklistEntry.active == True,
        )
    ).first()
    if existing:
        return {"status": "already_blocked", "id": existing.id}

    expires = (
        datetime.now(timezone.utc) + timedelta(minutes=payload.duration_minutes)
        if payload.duration_minutes
        else None
    )
    entry = BlocklistEntry(
        target_type=payload.target_type,
        value=payload.value.strip(),
        reason=payload.reason,
        owasp_id=payload.owasp_id,
        source="manual",
        created_by=user.email,
        expires_at=expires,
        active=True,
    )
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return {
        "id": entry.id,
        "target_type": entry.target_type,
        "value": entry.value,
        "reason": entry.reason,
        "owasp_id": entry.owasp_id,
        "active": entry.active,
    }


@router.delete("/{entry_id}")
def remove_from_blocklist(
    entry_id: int,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "analyst"])),
):
    entry = session.get(BlocklistEntry, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Blocklist entry not found")
    entry.active = False
    session.add(entry)
    session.commit()
    return {"status": "unblocked", "id": entry_id}


class AutoBlockConfigInput(BaseModel):
    auto_block_critical: bool
    auto_block_duration_minutes: int = 60


@router.put("/auto-config")
def update_auto_block_config(
    payload: AutoBlockConfigInput,
    _user: User = Depends(require_roles(["admin", "analyst"])),
):
    gateway_state.auto_block_critical = payload.auto_block_critical
    gateway_state.auto_block_duration_minutes = payload.auto_block_duration_minutes
    return {
        "auto_block_critical": gateway_state.auto_block_critical,
        "auto_block_duration_minutes": gateway_state.auto_block_duration_minutes,
    }
