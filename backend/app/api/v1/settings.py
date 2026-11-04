from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select
from app.db import get_session
from app.models import Organization, User, to_ist_iso
from app.api.v1.deps import VALID_ROLES, get_current_user, hash_password, require_roles
from app.gateway.pipeline import gateway_state

router = APIRouter(prefix="/settings", tags=["System Settings & RBAC User Management"])


def _org_map(session: Session) -> dict:
    return {o.id: o for o in session.exec(select(Organization)).all()}


def _active_org_admin_count(
    session: Session,
    organization_id: Optional[int],
    exclude_user_id: Optional[int] = None,
) -> int:
    if organization_id is None:
        return 0
    admins = session.exec(
        select(User).where(
            User.organization_id == organization_id,
            User.role == "admin",
            User.is_active == True,
        )
    ).all()
    return sum(1 for admin in admins if admin.id != exclude_user_id)


def _require_same_org_admin(actor: User, target: User) -> None:
    if actor.role != "admin":
        raise HTTPException(status_code=403, detail="Only organization admins can manage users")
    if not actor.organization_id or actor.organization_id != target.organization_id:
        raise HTTPException(
            status_code=403,
            detail="You can only manage users in your own organization",
        )


@router.get("")
def get_settings_and_users(
    session: Session = Depends(get_session),
    current: User = Depends(get_current_user),
):
    orgs = _org_map(session)
    current_org = orgs.get(current.organization_id) if current.organization_id else None

    if current.role == "admin" and current.organization_id:
        users = session.exec(
            select(User)
            .where(User.organization_id == current.organization_id)
            .order_by(User.id)
        ).all()
    elif current.organization_id:
        users = session.exec(
            select(User)
            .where(User.organization_id == current.organization_id)
            .order_by(User.id)
        ).all()
    else:
        users = []

    return {
        "system": {
            "gateway_enabled": gateway_state.gateway_enabled,
            "auto_block_critical": gateway_state.auto_block_critical,
            "auto_block_duration_minutes": gateway_state.auto_block_duration_minutes,
            "anomaly_zscore_threshold": gateway_state.anomaly_zscore_threshold,
            "retention_days": 30,
        },
        "organization": (
            {
                "id": current_org.id,
                "name": current_org.name,
                "slug": current_org.slug,
            }
            if current_org
            else None
        ),
        "users": [
            {
                "id": u.id,
                "email": u.email,
                "full_name": u.full_name,
                "role": u.role,
                "is_active": u.is_active,
                "organization_id": u.organization_id,
                "organization_name": orgs[u.organization_id].name if u.organization_id in orgs else None,
                "created_at": to_ist_iso(u.created_at),
                "last_login_at": to_ist_iso(u.last_login_at),
            }
            for u in users
        ],
    }


class UserCreateInput(BaseModel):
    email: str
    full_name: str
    password: str
    role: str = "viewer"


@router.post("/users")
def create_user(
    payload: UserCreateInput,
    session: Session = Depends(get_session),
    admin: User = Depends(require_roles(["admin"])),
):
    if not admin.organization_id:
        raise HTTPException(status_code=400, detail="Your account is not assigned to an organization")

    email = payload.email.lower().strip()
    full_name = payload.full_name.strip()
    role = payload.role.strip().lower()
    if role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")
    if len(full_name) < 2:
        raise HTTPException(status_code=400, detail="Enter a full name")
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    existing = session.exec(select(User).where(User.email == email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")
    u = User(
        email=email,
        full_name=full_name,
        password_hash=hash_password(payload.password),
        role=role,
        organization_id=admin.organization_id,
        is_active=True,
    )
    session.add(u)
    session.commit()
    session.refresh(u)
    org = session.get(Organization, u.organization_id)
    return {
        "id": u.id,
        "email": u.email,
        "full_name": u.full_name,
        "role": u.role,
        "is_active": u.is_active,
        "organization_id": u.organization_id,
        "organization_name": org.name if org else None,
    }


class UserRoleUpdateInput(BaseModel):
    role: str
    is_active: bool = True


@router.patch("/users/{user_id}")
def update_user_role(
    user_id: int,
    payload: UserRoleUpdateInput,
    session: Session = Depends(get_session),
    admin: User = Depends(require_roles(["admin"])),
):
    u = session.get(User, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    _require_same_org_admin(admin, u)

    role = payload.role.strip().lower()
    if role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")

    losing_admin = u.role == "admin" and (role != "admin" or not payload.is_active)
    if losing_admin and _active_org_admin_count(session, u.organization_id, exclude_user_id=u.id) == 0:
        raise HTTPException(status_code=400, detail="Cannot remove or disable the last active admin in this organization")

    u.role = role
    u.is_active = payload.is_active
    session.add(u)
    session.commit()
    session.refresh(u)
    return {
        "id": u.id,
        "email": u.email,
        "role": u.role,
        "is_active": u.is_active,
        "organization_id": u.organization_id,
        "updated_by": admin.email,
    }


@router.post("/reseed")
def reseed_demo_database(
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "analyst"])),
):
    from app.seed import seed_all_data
    seed_all_data(session, force_reset=True)
    return {"status": "reseeded", "message": "Demo database restored with fresh 24h traffic, OWASP policies, and alerts."}
