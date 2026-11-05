import time
import jwt
from sqlmodel import Session

from app.config import settings
from app.db import engine, create_db_and_tables
from app.gateway.auth import validate_jwt_checklist


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
