from datetime import datetime, timezone
import json
import re
import secrets
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.db import get_session
from app.models import ApiKey, Organization, RevokedToken, Upstream, UpstreamJWTConfig, User, to_ist_iso
from app.schemas import (
    LoginRequest,
    LoginResponse,
    OrganizationOut,
    RegisterRequest,
    TokenMintRequest,
    TokenTestRequest,
    UserOut,
)
from app.api.v1.deps import (
    create_dashboard_token,
    get_current_user,
    hash_password,
    require_roles,
    verify_password,
)
from app.api.v1.org_access import require_visible_project
from app.gateway.auth import (
    describe_active_jwt_config,
    extract_revocation_identity,
    find_revoked_token,
    get_upstream_jwt_config,
    hash_api_key,
    mint_demo_jwt,
    project_can_mint_hs256,
    validate_jwt_checklist,
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SLUG_RE = re.compile(r"[^a-z0-9]+")

router = APIRouter(prefix="/auth", tags=["Authentication & JWT Security Settings"])


def _slugify(value: str) -> str:
    slug = SLUG_RE.sub("-", (value or "").strip().lower()).strip("-")
    return slug[:64] or "organization"


def _unique_org_slug(session: Session, base_name: str) -> str:
    base = _slugify(base_name)
    candidate = base
    suffix = 2
    while session.exec(select(Organization).where(Organization.slug == candidate)).first():
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


def _user_out(user: User, session: Optional[Session] = None) -> UserOut:
    org_name = None
    org_slug = None
    if user.organization_id and session is not None:
        org = session.get(Organization, user.organization_id)
        if org:
            org_name = org.name
            org_slug = org.slug
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        organization_id=user.organization_id,
        organization_name=org_name,
        organization_slug=org_slug,
    )


def _issue_session(user: User, session: Session) -> LoginResponse:
    return LoginResponse(access_token=create_dashboard_token(user), user=_user_out(user, session))


def _normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def _validate_credentials(email: str, full_name: str, password: str) -> None:
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Enter a valid email address")
    if len(full_name.strip()) < 2:
        raise HTTPException(status_code=400, detail="Enter your full name")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")


@router.get("/organizations", response_model=List[OrganizationOut])
def list_organizations_for_registration(session: Session = Depends(get_session)):
    orgs = session.exec(select(Organization).order_by(Organization.name)).all()
    return [OrganizationOut(id=o.id, name=o.name, slug=o.slug) for o in orgs]


@router.post("/login", response_model=LoginResponse)
def login_dashboard(payload: LoginRequest, session: Session = Depends(get_session)):
    email = _normalize_email(payload.email)
    user = session.exec(select(User).where(User.email == email)).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is disabled")

    user.last_login_at = datetime.now(timezone.utc)
    session.add(user)
    session.commit()
    session.refresh(user)
    return _issue_session(user, session)


@router.post("/register", response_model=LoginResponse)
def register_dashboard(payload: RegisterRequest, session: Session = Depends(get_session)):
    email = _normalize_email(payload.email)
    full_name = (payload.full_name or "").strip()
    _validate_credentials(email, full_name, payload.password)

    existing = session.exec(select(User).where(User.email == email)).first()
    if existing:
        raise HTTPException(status_code=409, detail="An account with this email already exists")

    mode = (payload.organization_mode or "create").strip().lower()
    if mode not in ("create", "join"):
        raise HTTPException(status_code=400, detail="Choose whether to create or join an organization")

    if mode == "create":
        org_name = (payload.organization_name or "").strip()
        if len(org_name) < 2:
            raise HTTPException(status_code=400, detail="Enter an organization name")
        org = Organization(name=org_name, slug=_unique_org_slug(session, org_name))
        session.add(org)
        session.commit()
        session.refresh(org)
        role = "admin"
        organization_id = org.id
    else:
        if not payload.organization_id:
            raise HTTPException(status_code=400, detail="Select an organization to join")
        org = session.get(Organization, payload.organization_id)
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        role = "viewer"
        organization_id = org.id

    user = User(
        email=email,
        full_name=full_name,
        password_hash=hash_password(payload.password),
        role=role,
        organization_id=organization_id,
        is_active=True,
        last_login_at=datetime.now(timezone.utc),
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return _issue_session(user, session)


@router.get("/me", response_model=UserOut)
def get_me(user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    return _user_out(user, session)


@router.get("/jwt-config")
def get_jwt_config(
    upstream_id: Optional[int] = None,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
):
    """Pinned checks for the selected project. Falls back to the built-in gateway key only when that project has none."""
    project_config = None
    if upstream_id is not None:
        upstream = require_visible_project(session, user, upstream_id)
        project_config = get_upstream_jwt_config(session, upstream.id)
    return describe_active_jwt_config(project_config)


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
    user: User = Depends(get_current_user),
):
    upstream = require_visible_project(session, user, upstream_id)
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
    user: User = Depends(require_roles(["admin", "developer"])),
):
    upstream = require_visible_project(session, user, upstream_id)
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
    return get_project_jwt_config(upstream_id, session, user)


class JwtTestUnifiedInput(BaseModel):
    token: Optional[str] = None
    preset: Optional[str] = None
    expected_role: Optional[str] = None
    expected_scope: Optional[str] = None
    upstream_id: Optional[int] = None


def _project_jwt_config_for_request(session: Session, user: User, upstream_id: Optional[int]):
    if upstream_id is None:
        return None
    upstream = require_visible_project(session, user, upstream_id)
    return get_upstream_jwt_config(session, upstream.id)


@router.post("/jwt-test")
def test_or_mint_jwt(
    payload: JwtTestUnifiedInput,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
):
    jwt_config = _project_jwt_config_for_request(session, user, payload.upstream_id)
    if payload.preset:
        preset_aliases = {
            "valid_customer": "valid_user",
            "bad_signature": "tampered_sig",
        }
        mapped_preset = preset_aliases.get(payload.preset, payload.preset)
        if mapped_preset != "alg_none" and not project_can_mint_hs256(jwt_config):
            raise HTTPException(
                status_code=400,
                detail="This project verifies RS256 tokens. Paste a real access token to test it. Preset tokens can only be minted for an HS256 shared secret.",
            )
        minted = mint_demo_jwt(
            preset=mapped_preset,
            session=session,
            jwt_config=jwt_config,
            upstream_id=payload.upstream_id,
        )
        token_str = minted["token"]
    else:
        token_str = payload.token or ""

    res = validate_jwt_checklist(
        token=token_str,
        session=session,
        expected_role=payload.expected_role,
        expected_scope=payload.expected_scope,
        jwt_config=jwt_config,
    )
    return {
        **res,
        "token": token_str,
        "failed_step": res.get("failure_code"),
        "error": res.get("reason"),
    }


@router.post("/token-test")
def test_jwt_token(
    payload: TokenTestRequest,
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    jwt_config = _project_jwt_config_for_request(session, _user, payload.upstream_id)
    return validate_jwt_checklist(
        token=payload.token,
        session=session,
        expected_role=payload.expected_role,
        expected_scope=payload.expected_scope,
        jwt_config=jwt_config,
    )


@router.post("/token-mint")
def mint_jwt_for_testing(
    payload: TokenMintRequest,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
):
    jwt_config = _project_jwt_config_for_request(session, user, payload.upstream_id)
    if payload.preset != "alg_none" and not project_can_mint_hs256(jwt_config):
        raise HTTPException(
            status_code=400,
            detail="This project verifies RS256 tokens. Paste a real access token to test it. Preset tokens can only be minted for an HS256 shared secret.",
        )
    minted = mint_demo_jwt(
        sub=payload.sub,
        email=payload.email,
        role=payload.role,
        scopes=payload.scopes,
        preset=payload.preset,
        session=session,
        jwt_config=jwt_config,
        upstream_id=payload.upstream_id,
    )
    validation = validate_jwt_checklist(minted["token"], session, jwt_config=jwt_config)
    return {
        **minted,
        "validation": validation,
    }


@router.get("/api-keys")
def list_api_keys(
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
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
def list_revoked_tokens(
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
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
        "key_prefix": key_obj.key_prefix,
        "owner_email": key_obj.owner_email,
        "role": key_obj.role,
        "scopes": payload.scopes,
        "rate_limit_tier": key_obj.rate_limit_tier,
        "created_at": to_ist_iso(key_obj.created_at),
        "revoked": key_obj.revoked,
    }


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
    user_sub: Optional[str] = None
    reason: str = "Manual token revocation via Auth Center"


@router.post("/revoked-tokens")
def revoke_jti_token(
    payload: RevokeJtiInput,
    session: Session = Depends(get_session),
    user: User = Depends(require_roles(["admin", "analyst", "developer"])),
):
    jti, extracted_sub = extract_revocation_identity(payload.jti)
    if not jti:
        raise HTTPException(status_code=400, detail="Enter a jti claim or paste the full JWT")
    existing = find_revoked_token(session, jti)
    if existing:
        return {"status": "already_revoked", "jti": jti}
    entry = RevokedToken(
        jti=jti,
        user_sub=payload.user_sub or extracted_sub,
        reason=payload.reason,
        revoked_by=user.email,
    )
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return {"status": "revoked", "id": entry.id, "jti": entry.jti}
