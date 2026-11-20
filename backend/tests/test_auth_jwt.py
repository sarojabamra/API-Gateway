import time
import uuid
import jwt
from sqlmodel import Session

from app.config import settings
from app.db import engine, create_db_and_tables
from app.gateway.auth import extract_revocation_identity, validate_jwt_checklist
from app.models import RevokedToken


def _mint(payload: dict, alg: str = "HS256", key: str | None = None, headers: dict | None = None) -> str:
    return jwt.encode(
        payload,
        key or settings.GATEWAY_JWT_SECRET,
        algorithm=alg,
        headers=headers or {"kid": "default"},
    )


def test_alg_none_rejected():
    create_db_and_tables()
    # Manually craft alg=none style token segments
    import base64
    import json

    def b64(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    token = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': 'x', 'exp': int(time.time()) + 60})}."
    with Session(engine) as session:
        result = validate_jwt_checklist(token, session)
    assert result["valid"] is False
    assert result["failure_code"] == "jwt_alg_none"


def test_future_iat_rejected():
    create_db_and_tables()
    now = int(time.time())
    token = _mint(
        {
            "sub": "user-101",
            "role": "user",
            "scopes": ["read:products"],
            "iss": settings.GATEWAY_JWT_ISSUER,
            "aud": settings.GATEWAY_JWT_AUDIENCE,
            "exp": now + 3600,
            "iat": now + 3600,
            "jti": "test-future-iat",
        }
    )
    with Session(engine) as session:
        result = validate_jwt_checklist(token, session)
    assert result["valid"] is False
    assert result["failure_code"] == "jwt_future_iat"


def test_aud_list_accepted():
    create_db_and_tables()
    now = int(time.time())
    token = _mint(
        {
            "sub": "user-101",
            "role": "user",
            "scopes": ["read:products"],
            "iss": settings.GATEWAY_JWT_ISSUER,
            "aud": [settings.GATEWAY_JWT_AUDIENCE, "other-aud"],
            "exp": now + 3600,
            "iat": now - 10,
            "jti": "test-aud-list",
        }
    )
    with Session(engine) as session:
        result = validate_jwt_checklist(token, session)
    assert result["valid"] is True


def test_revoked_jti_rejected_with_project_config():
    create_db_and_tables()
    now = int(time.time())
    secret = "project-shared-secret-not-the-demo-key"
    jwt_config = {
        "allowed_algorithms": ["HS256"],
        "verification_key": secret,
        "issuer": "https://login.example.com/realms/myapp",
        "audience": "account",
        "require_jti": True,
        "leeway_seconds": 10,
    }
    claims = {
        "sub": "user-42",
        "role": "user",
        "scopes": ["read:products"],
        "iss": "https://login.example.com/realms/myapp",
        "aud": "account",
        "exp": now + 3600,
        "iat": now - 5,
        "jti": f"keycloak-jti-{uuid.uuid4().hex}",
    }
    token = _mint(claims, key=secret, headers={"alg": "HS256", "typ": "JWT"})
    with Session(engine) as session:
        ok = validate_jwt_checklist(token, session, jwt_config=jwt_config)
        assert ok["valid"] is True
        session.add(RevokedToken(jti=claims["jti"], user_sub="user-42", reason="revoked in test"))
        session.commit()
        blocked = validate_jwt_checklist(token, session, jwt_config=jwt_config)
    assert blocked["valid"] is False
    assert blocked["failure_code"] == "jwt_revoked"


def test_full_jwt_on_blacklist_is_rejected():
    create_db_and_tables()
    now = int(time.time())
    token = _mint(
        {
            "sub": "user-42",
            "role": "user",
            "scopes": ["read:products"],
            "iss": settings.GATEWAY_JWT_ISSUER,
            "aud": settings.GATEWAY_JWT_AUDIENCE,
            "exp": now + 3600,
            "iat": now - 5,
            "jti": "pasted-token-jti",
        }
    )
    jti, sub = extract_revocation_identity(token)
    assert jti == "pasted-token-jti"
    assert sub == "user-42"
    with Session(engine) as session:
        session.add(RevokedToken(jti=token, user_sub=sub, reason="pasted the whole token"))
        session.commit()
        blocked = validate_jwt_checklist(token, session)
    assert blocked["valid"] is False
    assert blocked["failure_code"] == "jwt_revoked"


def test_project_config_rejects_demo_issuer():
    create_db_and_tables()
    now = int(time.time())
    secret = "project-shared-secret-not-the-demo-key"
    token = _mint(
        {
            "sub": "user-42",
            "role": "user",
            "scopes": ["read:products"],
            "iss": settings.GATEWAY_JWT_ISSUER,
            "aud": settings.GATEWAY_JWT_AUDIENCE,
            "exp": now + 3600,
            "iat": now - 5,
            "jti": "demo-issuer-token",
        },
        key=secret,
        headers={"alg": "HS256", "typ": "JWT"},
    )
    with Session(engine) as session:
        result = validate_jwt_checklist(
            token,
            session,
            jwt_config={
                "allowed_algorithms": ["HS256"],
                "verification_key": secret,
                "issuer": "https://login.example.com/realms/myapp",
                "audience": "account",
                "require_jti": False,
                "leeway_seconds": 10,
            },
        )
    assert result["valid"] is False
    assert result["failure_code"] == "jwt_invalid_claims"


def test_missing_scope_fails_when_expected():
    create_db_and_tables()
    now = int(time.time())
    token = _mint(
        {
            "sub": "user-101",
            "role": "user",
            "scopes": ["read:products"],
            "iss": settings.GATEWAY_JWT_ISSUER,
            "aud": settings.GATEWAY_JWT_AUDIENCE,
            "exp": now + 3600,
            "iat": now - 10,
            "jti": "test-scope-fail",
        }
    )
    with Session(engine) as session:
        result = validate_jwt_checklist(token, session, expected_scope="admin:write")
    assert result["valid"] is False
    assert result["failure_code"] == "jwt_insufficient_scope"
