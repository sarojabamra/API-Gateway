from datetime import datetime, timedelta, timezone
from typing import List, Optional
import bcrypt
from fastapi import Depends, Header, HTTPException
import jwt
from sqlmodel import Session, select
from app.config import settings
from app.db import get_session
from app.models import User

VALID_ROLES = ("admin", "analyst", "developer", "viewer")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def create_dashboard_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "full_name": user.full_name,
        "organization_id": user.organization_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.DASHBOARD_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, settings.DASHBOARD_JWT_SECRET, algorithm=settings.DASHBOARD_JWT_ALGORITHM)


def authenticate_access_token(token: str, session: Session) -> User:
    raw = (token or "").strip()
    if not raw:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(
            raw,
            settings.DASHBOARD_JWT_SECRET,
            algorithms=[settings.DASHBOARD_JWT_ALGORITHM],
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please sign in again.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid session token")

    email = payload.get("email")
    if not email:
        raise HTTPException(status_code=401, detail="Invalid session token")

    user = session.exec(select(User).where(User.email == email)).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User inactive or not found")
    return user


def get_current_user(
    authorization: Optional[str] = Header(default=None),
    session: Session = Depends(get_session),
) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    raw = authorization.split(" ", 1)[1].strip()
    return authenticate_access_token(raw, session)


def require_roles(allowed_roles: List[str]):
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Role '{user.role}' is not authorized for this action. Required role: {', '.join(allowed_roles)}",
            )
        return user

    return dependency
