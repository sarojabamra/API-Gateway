"""Gateway must accept X-API-Key even when a bad Authorization header is also present."""

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from app.db import engine
from app.gateway.auth import hash_api_key
from app.main import app
from app.models import ApiKey


def test_api_key_accepted_when_junk_jwt_also_present():
    raw_key = "sgw_live_fallback_test_key_aabbcc"
    with Session(engine) as session:
        existing = session.exec(select(ApiKey).where(ApiKey.name == "Fallback Test Key")).first()
        if existing:
            existing.hashed_key = hash_api_key(raw_key)
            existing.revoked = False
            session.add(existing)
        else:
            session.add(
                ApiKey(
                    name="Fallback Test Key",
                    key_prefix=raw_key[:14],
                    hashed_key=hash_api_key(raw_key),
                    owner_email="dev@sentinel.local",
                    role="user",
                    scopes_json="[]",
                    revoked=False,
                )
            )
        session.commit()

    with TestClient(app) as client:
        # Junk Bearer used to force the JWT branch and ignore a valid API key.
        res = client.get(
            "/gw/vulnshop/products",
            headers={
                "Authorization": "Bearer not.a.valid.jwt",
                "X-API-Key": raw_key,
            },
        )
        assert res.status_code == 200, res.text
        assert res.headers.get("X-Gateway-Decision") == "allowed"
