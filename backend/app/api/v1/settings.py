from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select
from app.db import get_session
from app.models import User
from app.api.v1.deps import hash_password, require_roles
from app.gateway.pipeline import gateway_state

router = APIRouter(prefix="/settings", tags=["System Settings & RBAC User Management"])

RBAC_CAPABILITIES_MATRIX = [
    {
        "role": "admin",
        "label": "Platform Administrator",
        "default_account": "admin@sentinel.local",
        "permissions": [
            "Full control over Gateway Master Switch, Users & RBAC Roles",
            "Create, edit, delete, and toggle Security Policies & JWT Secrets",
            "Incident triage, IP/User blocking, and JTI token revocation",
            "Reset or re-seed demonstration telemetry",
        ],
    },
    {
        "role": "analyst",
        "label": "SOC Security Analyst",
        "default_account": "analyst@sentinel.local",
        "permissions": [
            "Monitor Live Traffic stream, Overview KPIs, and Deep Analytics",
            "Triage Alerts, trigger AI Triage analysis, and add forensic notes",
            "Block/unblock malicious IPs, users, and revoke compromised tokens",
            "Toggle policies between Monitor (Dry-Run) and Enforce & run Attack Simulator",
        ],
    },
    {
        "role": "developer",
        "label": "API Owner / Developer",
        "default_account": "dev@sentinel.local",
        "permissions": [
            "Onboard Upstreams, register Routes, and import OpenAPI 3.0 specs",
            "Resolve or block discovered Shadow APIs (OWASP API9)",
            "Configure route rate limits, BOLA ownership checks, and API3 field redaction",
            "Mint & debug JWT tokens in the Token Tester and manage API Keys",
        ],
    },
    {
        "role": "viewer",
        "label": "Executive / Compliance Auditor",
        "default_account": "viewer@sentinel.local",
        "permissions": [
            "Read-only visibility across Dashboards, Traffic, Alerts, and OWASP Coverage",
            "Generate and export CSV/PDF Executive Security Posture Reports",
            "Zero mutation privileges (cannot alter production policies or blocklists)",
        ],
    },
]


@router.get("")
def get_settings_and_users(session: Session = Depends(get_session)):
    users = session.exec(select(User).order_by(User.id)).all()
    return {
        "system": {
            "gateway_enabled": gateway_state.gateway_enabled,
            "auto_block_critical": gateway_state.auto_block_critical,
            "auto_block_duration_minutes": gateway_state.auto_block_duration_minutes,
            "anomaly_zscore_threshold": gateway_state.anomaly_zscore_threshold,
            "retention_days": 30,
        },
        "rbac_matrix": RBAC_CAPABILITIES_MATRIX,
        "users": [
            {
                "id": u.id,
                "email": u.email,
                "full_name": u.full_name,
                "role": u.role,
                "is_active": u.is_active,
                "created_at": u.created_at.isoformat(),
                "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            }
            for u in users
        ],
    }


class UserCreateInput(BaseModel):
    email: str
    full_name: str
    password: str = "sentinel123"
    role: str = "analyst"


@router.post("/users")
def create_user(
    payload: UserCreateInput,
    session: Session = Depends(get_session),
    _admin: User = Depends(require_roles(["admin"])),
):
    existing = session.exec(select(User).where(User.email == payload.email.lower().strip())).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")
    u = User(
        email=payload.email.lower().strip(),
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    session.add(u)
    session.commit()
    session.refresh(u)
    return {"id": u.id, "email": u.email, "full_name": u.full_name, "role": u.role, "is_active": u.is_active}


class UserRoleUpdateInput(BaseModel):
    role: str
    is_active: bool = True


@router.patch("/users/{user_id}")
def update_user_role(
    user_id: int,
    payload: UserRoleUpdateInput,
    session: Session = Depends(get_session),
    _admin: User = Depends(require_roles(["admin"])),
):
    u = session.get(User, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u.role = payload.role
    u.is_active = payload.is_active
    session.add(u)
    session.commit()
    session.refresh(u)
    return {"id": u.id, "email": u.email, "role": u.role, "is_active": u.is_active}


@router.post("/reseed")
def reseed_demo_database(
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "analyst"])),
):
    from app.seed import seed_all_data
    seed_all_data(session, force_reset=True)
    return {"status": "reseeded", "message": "Demo database restored with fresh 24h traffic, OWASP policies, and alerts."}
