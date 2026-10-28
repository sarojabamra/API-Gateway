from datetime import datetime, timezone
import json
import secrets
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.db import get_session
from app.models import ApiKey, RevokedToken, Upstream, UpstreamJWTConfig, User, to_ist_iso
from app.schemas import LoginRequest, LoginResponse, TokenMintRequest, TokenTestRequest, UserOut
from app.api.v1.deps import create_dashboard_token, get_current_user, require_roles, verify_password
from app.gateway.auth import (
    get_upstream_jwt_config,
    hash_api_key,
    jwt_runtime_config,
    mint_demo_jwt,
    validate_jwt_checklist,
)

router = APIRouter(prefix="/auth", tags=["Authentication & JWT Security Settings"])


@router.post("/login", response_model=LoginResponse)
def login_dashboard(payload: LoginRequest, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.email == payload.email.strip().lower())).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is disabled")

    user.last_login_at = datetime.now(timezone.utc)
    session.add(user)
    session.commit()
    session.refresh(user)

    token = create_dashboard_token(user)
    return LoginResponse(
        access_token=token,
        user=UserOut(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            is_active=user.is_active,
        ),
    )


class QuickSwitchBody(BaseModel):
    role: str


@router.post("/quick-switch", response_model=LoginResponse)
def quick_switch_post(payload: QuickSwitchBody, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.role == payload.role)).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"No demo user found for role '{payload.role}'")
    token = create_dashboard_token(user)
    return LoginResponse(
        access_token=token,
        user=UserOut(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            is_active=user.is_active,
        ),
    )


@router.post("/quick-role-switch/{role}", response_model=LoginResponse)
def quick_role_switch(role: str, session: Session = Depends(get_session)):
    return quick_switch_post(QuickSwitchBody(role=role), session)


@router.get("/me", response_model=UserOut)
def get_me(user: User = Depends(get_current_user)):
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
    )


@router.get("/settings")
def get_auth_center_settings(session: Session = Depends(get_session)):
    keys = session.exec(select(ApiKey).order_by(ApiKey.created_at.desc())).all()
    tokens = session.exec(select(RevokedToken).order_by(RevokedToken.revoked_at.desc())).all()
    return {
        "jwt_config": {
            "allowed_algorithms": jwt_runtime_config.allowed_algorithms,
            "expected_issuer": jwt_runtime_config.issuer,
            "expected_audience": jwt_runtime_config.audience,
            "clock_skew_leeway_seconds": jwt_runtime_config.leeway_seconds,
            "require_jti": jwt_runtime_config.require_jti,
            "reject_alg_none": jwt_runtime_config.reject_alg_none,
        },
        "api_keys": [
            {
                "id": k.id,
                "name": k.name,
                "key_prefix": k.key_prefix,
                "owner_email": k.owner_email,
                "role": k.role,
                "scopes": json.loads(k.scopes_json or "[]"),
                "rate_limit_tier": k.rate_limit_tier,
                "created_at": to_ist_iso(k.created_at),
                "revoked": k.revoked,
            }
            for k in keys
        ],
        "revoked_tokens": [
            {
                "id": t.id,
                "jti": t.jti,
                "user_sub": t.user_sub,
                "reason": t.reason,
                "revoked_by": t.revoked_by,
                "revoked_at": to_ist_iso(t.revoked_at),
            }
            for t in tokens
        ],
    }


@router.get("/jwt-config")
def get_jwt_config():
    return {
        "allowed_algorithms": jwt_runtime_config.allowed_algorithms,
        "issuer": jwt_runtime_config.issuer,
        "audience": jwt_runtime_config.audience,
        "leeway_seconds": jwt_runtime_config.leeway_seconds,
        "require_jti": jwt_runtime_config.require_jti,
        "reject_alg_none": jwt_runtime_config.reject_alg_none,
        "trusted_kids": list(jwt_runtime_config.trusted_kids.keys()),
    }


class UpstreamJWTConfigInput(BaseModel):
    enabled: bool = True
    allowed_algorithms: List[str] = ["HS256"]
    verification_key: Optional[str] = None
    issuer: Optional[str] = None
    audience: Optional[str] = None
    require_jti: bool = False
    leeway_seconds: int = 10


@router.get("/upstreams/{upstream_id}/jwt-config")
def get_project_jwt_config(
    upstream_id: int,
    session: Session = Depends(get_session),
):
    upstream = session.get(Upstream, upstream_id)
    if not upstream:
        raise HTTPException(status_code=404, detail="API project not found")
    config = session.exec(
        select(UpstreamJWTConfig).where(UpstreamJWTConfig.upstream_id == upstream_id)
    ).first()
    return {
        "upstream_id": upstream_id,
        "project_name": upstream.name,
        "enabled": config.enabled if config else False,
        "allowed_algorithms": (
            json.loads(config.allowed_algorithms_json or '["HS256"]')
            if config
            else ["HS256"]
        ),
        "has_verification_key": bool(config and config.verification_key),
        "issuer": config.issuer if config else None,
        "audience": config.audience if config else None,
        "require_jti": config.require_jti if config else False,
        "leeway_seconds": config.leeway_seconds if config else 10,
    }


@router.put("/upstreams/{upstream_id}/jwt-config")
def update_project_jwt_config(
    upstream_id: int,
    payload: UpstreamJWTConfigInput,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "developer"])),
):
    upstream = session.get(Upstream, upstream_id)
    if not upstream:
        raise HTTPException(status_code=404, detail="API project not found")
    algorithms = [alg.strip() for alg in payload.allowed_algorithms if alg.strip()]
    if not algorithms or "none" in {alg.lower() for alg in algorithms}:
        raise HTTPException(status_code=400, detail="Choose at least one signed JWT algorithm; alg=none is forbidden")

    config = session.exec(
        select(UpstreamJWTConfig).where(UpstreamJWTConfig.upstream_id == upstream_id)
    ).first()
    effective_key = payload.verification_key
    if not effective_key and "RS256" in {alg.upper() for alg in algorithms}:
        effective_key = "firebase"

    if not config:
        if not effective_key:
            raise HTTPException(status_code=400, detail="JWT verification key or shared secret is required")
        config = UpstreamJWTConfig(
            upstream_id=upstream_id,
            verification_key=effective_key,
        )
    elif payload.verification_key:
        config.verification_key = payload.verification_key

    config.enabled = payload.enabled
    config.allowed_algorithms_json = json.dumps(algorithms)
    config.issuer = payload.issuer.strip() if payload.issuer else None
    config.audience = payload.audience.strip() if payload.audience else None
    config.require_jti = payload.require_jti
    config.leeway_seconds = max(0, min(payload.leeway_seconds, 300))
    config.updated_at = datetime.now(timezone.utc)
    session.add(config)
    session.commit()
    session.refresh(config)
    return get_project_jwt_config(upstream_id, session)


class JwtTestUnifiedInput(BaseModel):
    token: Optional[str] = None
    preset: Optional[str] = None
    expected_role: Optional[str] = None
    expected_scope: Optional[str] = None


@router.post("/jwt-test")
def test_or_mint_jwt(payload: JwtTestUnifiedInput, session: Session = Depends(get_session)):
    if payload.preset:
        preset_map = {
            "valid_customer": ("valid", "user-101", "customer"),
            "valid_admin": ("valid", "admin-1", "admin"),
            "alg_none": ("alg_none", "admin-1", "admin"),
            "expired": ("expired", "user-101", "customer"),
            "wrong_issuer": ("wrong_aud", "user-101", "customer"),
            "bad_signature": ("bad_sig", "admin-1", "admin"),
            "revoked_jti": ("revoked_jti", "user-102", "customer"),
        }
        mapped_preset, sub, role = preset_map.get(payload.preset, ("valid", "user-101", "customer"))
        minted = mint_demo_jwt(
            sub=sub,
            email=f"{sub}@vulnshop.demo",
            role=role,
            scopes=["read:orders", "write:orders"],
            preset=mapped_preset,
            session=session,
        )
        token_str = minted["token"]
    else:
        token_str = payload.token or ""

    res = validate_jwt_checklist(
        token=token_str,
        session=session,
        expected_role=payload.expected_role,
        expected_scope=payload.expected_scope,
    )
    checklist_dict = {}
    for st in res.get("steps", []):
        key = f"step{st.get('step')}_{st.get('name', '').lower().replace(' ', '_').replace('&', '')}"
        checklist_dict[key] = "passed" if st.get("passed") else f"failed: {st.get('detail')}"
    return {
        **res,
        "token": token_str,
        "failed_step": res.get("failure_code"),
        "error": res.get("reason"),
        "checklist": checklist_dict,
    }


@router.post("/token-test")
def test_jwt_token(payload: TokenTestRequest, session: Session = Depends(get_session)):
    return validate_jwt_checklist(
        token=payload.token,
        session=session,
        expected_role=payload.expected_role,
        expected_scope=payload.expected_scope,
        jwt_config=(
            get_upstream_jwt_config(session, payload.upstream_id)
            if payload.upstream_id is not None
            else None
        ),
    )


@router.post("/token-mint")
def mint_jwt_for_testing(payload: TokenMintRequest, session: Session = Depends(get_session)):
    minted = mint_demo_jwt(
        sub=payload.sub,
        email=payload.email,
        role=payload.role,
        scopes=payload.scopes,
        preset=payload.preset,
        session=session,
    )
    validation = validate_jwt_checklist(minted["token"], session)
    return {
        **minted,
        "validation": validation,
    }


@router.get("/api-keys")
def list_api_keys(session: Session = Depends(get_session)):
    keys = session.exec(select(ApiKey).order_by(ApiKey.created_at.desc())).all()
    return [
        {
            "id": k.id,
            "name": k.name,
            "key_prefix": k.key_prefix,
            "owner_email": k.owner_email,
            "role": k.role,
            "scopes": json.loads(k.scopes_json or "[]"),
            "rate_limit_tier": k.rate_limit_tier,
            "created_at": to_ist_iso(k.created_at),
            "revoked": k.revoked,
        }
        for k in keys
    ]


@router.get("/revoked-tokens")
def list_revoked_tokens(session: Session = Depends(get_session)):
    tokens = session.exec(select(RevokedToken).order_by(RevokedToken.revoked_at.desc())).all()
    return [
        {
            "id": t.id,
            "jti": t.jti,
            "user_sub": t.user_sub,
            "reason": t.reason,
            "revoked_by": t.revoked_by,
            "revoked_at": to_ist_iso(t.revoked_at),
        }
        for t in tokens
    ]


class ApiKeyCreateInput(BaseModel):
    name: str
    owner_email: str = "dev@sentinel.local"
    role: str = "user"
    scopes: List[str] = ["read:products", "read:orders"]
    rate_limit_tier: str = "standard"


@router.post("/api-keys")
def create_api_key(
    payload: ApiKeyCreateInput,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "developer"])),
):
    raw_secret = f"sgw_live_{secrets.token_urlsafe(18)}"
    prefix = raw_secret[:14]
    key_obj = ApiKey(
        name=payload.name,
        key_prefix=prefix,
        hashed_key=hash_api_key(raw_secret),
        owner_email=payload.owner_email,
        role=payload.role,
        scopes_json=json.dumps(payload.scopes),
        rate_limit_tier=payload.rate_limit_tier,
        revoked=False,
    )
    session.add(key_obj)
    session.commit()
    session.refresh(key_obj)
    return {
        "id": key_obj.id,
        "name": key_obj.name,
        "raw_key": raw_secret,
        "plaintext_key": raw_secret,
        "key_prefix": key_obj.key_prefix,
        "owner_email": key_obj.owner_email,
        "role": key_obj.role,
        "scopes": payload.scopes,
        "rate_limit_tier": key_obj.rate_limit_tier,
        "created_at": to_ist_iso(key_obj.created_at),
        "revoked": key_obj.revoked,
    }


@router.delete("/api-keys/{key_id}")
@router.post("/api-keys/{key_id}/revoke")
def revoke_api_key(
    key_id: int,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "analyst", "developer"])),
):
    key_obj = session.get(ApiKey, key_id)
    if not key_obj:
        raise HTTPException(status_code=404, detail="API Key not found")
    key_obj.revoked = True
    session.add(key_obj)
    session.commit()
    return {"status": "revoked", "id": key_id}


class RevokeJtiInput(BaseModel):
    jti: str
    user_sub: str = "user-101"
    reason: str = "Manual token revocation via Auth Center"


@router.post("/revoke-jti")
@router.post("/revoked-tokens")
def revoke_jti_token(
    payload: RevokeJtiInput,
    session: Session = Depends(get_session),
    user: User = Depends(require_roles(["admin", "analyst", "developer"])),
):
    existing = session.exec(select(RevokedToken).where(RevokedToken.jti == payload.jti)).first()
    if existing:
        return {"status": "already_revoked", "jti": payload.jti}
    entry = RevokedToken(
        jti=payload.jti,
        user_sub=payload.user_sub,
        reason=payload.reason,
        revoked_by=user.email,
    )
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return {"status": "revoked", "id": entry.id, "jti": entry.jti}
