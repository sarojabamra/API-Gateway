import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
import jwt
from sqlmodel import Session, select
from app.config import settings
from app.models import ApiKey, RevokedToken


class JWTConfigRuntime:
    """Mutable runtime JWT configuration so changes in Auth Settings take effect immediately."""
    def __init__(self):
        self.allowed_algorithms: List[str] = list(settings.GATEWAY_ALLOWED_ALGORITHMS)
        self.issuer: str = settings.GATEWAY_JWT_ISSUER
        self.audience: str = settings.GATEWAY_JWT_AUDIENCE
        self.leeway_seconds: int = settings.GATEWAY_JWT_LEEWAY_SECONDS
        self.require_jti: bool = settings.GATEWAY_REQUIRE_JTI
        self.reject_alg_none: bool = True
        self.secret: str = settings.GATEWAY_JWT_SECRET
        self.trusted_kids: Dict[str, str] = {
            "vulnshop-key-2026": settings.GATEWAY_JWT_SECRET,
            "default": settings.GATEWAY_JWT_SECRET,
        }


jwt_runtime_config = JWTConfigRuntime()


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * ((4 - len(segment) % 4) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def validate_jwt_checklist(
    token: str,
    session: Session,
    expected_role: Optional[str] = None,
    expected_scope: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes the 8-point OWASP API2 JWT validation checklist and returns both:
    - overall `valid` boolean, `failure_code`, `http_status`
    - step-by-step `steps` list for the Token Tester UI and forensic logging.
    """
    steps: List[Dict[str, Any]] = []
    raw = (token or "").strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()

    parts = raw.split(".")
    if len(parts) != 3:
        steps.append({
            "step": 1,
            "name": "Token Structure & Header Parse",
            "passed": False,
            "detail": f"Malformed JWT: expected 3 dot-separated segments, got {len(parts)}",
        })
        return {
            "valid": False,
            "failure_code": "jwt_malformed",
            "reason": "Malformed JWT structure",
            "owasp_id": "API2",
            "header": {},
            "payload": {},
            "steps": steps,
        }

    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        steps.append({
            "step": 1,
            "name": "Token Structure & Header Parse",
            "passed": True,
            "detail": f"Parsed JWT header (alg={header.get('alg')}, kid={header.get('kid', 'default')})",
        })
    except Exception as exc:
        steps.append({
            "step": 1,
            "name": "Token Structure & Header Parse",
            "passed": False,
            "detail": f"Failed to base64url decode header/payload: {exc}",
        })
        return {
            "valid": False,
            "failure_code": "jwt_decode_error",
            "reason": "Invalid base64/JSON in JWT segments",
            "owasp_id": "API2",
            "header": {},
            "payload": {},
            "steps": steps,
        }

    # Step 2: Pin allowed algorithms & reject alg=none / algorithm confusion
    alg = str(header.get("alg", "")).strip()
    if alg.lower() == "none" or not parts[2]:
        steps.append({
            "step": 2,
            "name": "Algorithm Pinning & alg=none Defense",
            "passed": False,
            "detail": f"CRITICAL: Token uses unauthenticated 'alg={alg}' or empty signature segment",
        })
        return {
            "valid": False,
            "failure_code": "jwt_alg_none",
            "reason": "Rejected alg=none unsigned JWT attack",
            "owasp_id": "API2",
            "header": header,
            "payload": payload,
            "steps": steps,
        }

    if alg not in jwt_runtime_config.allowed_algorithms:
        steps.append({
            "step": 2,
            "name": "Algorithm Pinning & alg=none Defense",
            "passed": False,
            "detail": f"Algorithm '{alg}' is not in pinned allowlist {jwt_runtime_config.allowed_algorithms}",
        })
        return {
            "valid": False,
            "failure_code": "jwt_algorithm_confusion",
            "reason": f"Disallowed JWT algorithm '{alg}'",
            "owasp_id": "API2",
            "header": header,
            "payload": payload,
            "steps": steps,
        }

    steps.append({
        "step": 2,
        "name": "Algorithm Pinning & alg=none Defense",
        "passed": True,
        "detail": f"Algorithm '{alg}' matches pinned allowlist {jwt_runtime_config.allowed_algorithms}",
    })

    # Step 3: Local Key ID (kid) allowlist lookup (prevent kid SQLi / path traversal)
    kid = header.get("kid", "default")
    signing_key = jwt_runtime_config.trusted_kids.get(str(kid))
    if not signing_key:
        steps.append({
            "step": 3,
            "name": "Local Key ID (kid) Registry Lookup",
            "passed": False,
            "detail": f"Untrusted or unknown kid='{kid}' in JWT header (blocked potential kid injection)",
        })
        return {
            "valid": False,
            "failure_code": "jwt_untrusted_kid",
            "reason": f"Untrusted key identifier kid='{kid}'",
            "owasp_id": "API2",
            "header": header,
            "payload": payload,
            "steps": steps,
        }
    steps.append({
        "step": 3,
        "name": "Local Key ID (kid) Registry Lookup",
        "passed": True,
        "detail": f"Resolved kid='{kid}' from local trusted key store",
    })

    # Step 4: Cryptographic signature verification
    try:
        jwt.decode(
            raw,
            signing_key,
            algorithms=jwt_runtime_config.allowed_algorithms,
            options={
                "verify_signature": True,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
        steps.append({
            "step": 4,
            "name": "Cryptographic Signature Verification",
            "passed": True,
            "detail": "HMAC-SHA256 signature matches server secret",
        })
    except jwt.InvalidSignatureError:
        steps.append({
            "step": 4,
            "name": "Cryptographic Signature Verification",
            "passed": False,
            "detail": "CRITICAL: Signature mismatch — payload or header was tampered with",
        })
        return {
            "valid": False,
            "failure_code": "jwt_bad_signature",
            "reason": "JWT cryptographic signature verification failed",
            "owasp_id": "API2",
            "header": header,
            "payload": payload,
            "steps": steps,
        }
    except Exception as exc:
        steps.append({
            "step": 4,
            "name": "Cryptographic Signature Verification",
            "passed": False,
            "detail": f"Signature verification failed: {exc}",
        })
        return {
            "valid": False,
            "failure_code": "jwt_bad_signature",
            "reason": f"JWT signature error: {exc}",
            "owasp_id": "API2",
            "header": header,
            "payload": payload,
            "steps": steps,
        }

    # Step 5: Temporal claims (exp, nbf, iat) with clock-skew leeway
    now = int(time.time())
    leeway = jwt_runtime_config.leeway_seconds
    exp = payload.get("exp")
    nbf = payload.get("nbf")
    iat = payload.get("iat")

    if exp is None or not isinstance(exp, (int, float)):
        steps.append({
            "step": 5,
            "name": "Temporal Claims (exp, nbf, iat) & Leeway",
            "passed": False,
            "detail": "Missing required 'exp' (expiration) claim",
        })
        return {
            "valid": False,
            "failure_code": "jwt_missing_exp",
            "reason": "Missing exp claim",
            "owasp_id": "API2",
            "header": header,
            "payload": payload,
            "steps": steps,
        }

    if now > int(exp) + leeway:
        expired_ago = now - int(exp)
        steps.append({
            "step": 5,
            "name": "Temporal Claims (exp, nbf, iat) & Leeway",
            "passed": False,
            "detail": f"Token expired {expired_ago}s ago (leeway={leeway}s)",
        })
        return {
            "valid": False,
            "failure_code": "jwt_expired",
            "reason": f"Token expired {expired_ago}s ago",
            "owasp_id": "API2",
            "header": header,
            "payload": payload,
            "steps": steps,
        }

    if nbf is not None and now + leeway < int(nbf):
        steps.append({
            "step": 5,
            "name": "Temporal Claims (exp, nbf, iat) & Leeway",
            "passed": False,
            "detail": f"Token not valid before nbf={nbf} (now={now})",
        })
        return {
            "valid": False,
            "failure_code": "jwt_immature",
            "reason": "Token nbf is in the future",
            "owasp_id": "API2",
            "header": header,
            "payload": payload,
            "steps": steps,
        }

    steps.append({
        "step": 5,
        "name": "Temporal Claims (exp, nbf, iat) & Leeway",
        "passed": True,
        "detail": f"Valid temporal window (expires in {int(exp) - now}s, leeway={leeway}s, iat={iat})",
    })

    # Step 6: Issuer (iss) and Audience (aud) validation
    iss = payload.get("iss")
    aud = payload.get("aud")
    if iss != jwt_runtime_config.issuer or aud != jwt_runtime_config.audience:
        steps.append({
            "step": 6,
            "name": "Issuer (iss) & Audience (aud) Binding",
            "passed": False,
            "detail": f"Claim mismatch: got iss='{iss}', aud='{aud}' (expected iss='{jwt_runtime_config.issuer}', aud='{jwt_runtime_config.audience}')",
        })
        return {
            "valid": False,
            "failure_code": "jwt_invalid_claims",
            "reason": "Invalid issuer (iss) or audience (aud)",
            "owasp_id": "API2",
            "header": header,
            "payload": payload,
            "steps": steps,
        }

    steps.append({
        "step": 6,
        "name": "Issuer (iss) & Audience (aud) Binding",
        "passed": True,
        "detail": f"Verified iss='{iss}' and aud='{aud}'",
    })

    # Step 7: JTI presence and revocation blacklist check
    jti = payload.get("jti")
    if jwt_runtime_config.require_jti and not jti:
        steps.append({
            "step": 7,
            "name": "JTI Presence & Revocation Blacklist Check",
            "passed": False,
            "detail": "Missing required 'jti' unique token identifier",
        })
        return {
            "valid": False,
            "failure_code": "jwt_missing_jti",
            "reason": "Missing required jti claim",
            "owasp_id": "API2",
            "header": header,
            "payload": payload,
            "steps": steps,
        }

    if jti:
        revoked = session.exec(select(RevokedToken).where(RevokedToken.jti == str(jti))).first()
        if revoked:
            steps.append({
                "step": 7,
                "name": "JTI Presence & Revocation Blacklist Check",
                "passed": False,
                "detail": f"Token jti='{jti}' is on the revocation blacklist ({revoked.reason})",
            })
            return {
                "valid": False,
                "failure_code": "jwt_revoked",
                "reason": f"Token jti='{jti}' has been revoked",
                "owasp_id": "API2",
                "header": header,
                "payload": payload,
                "steps": steps,
            }

    steps.append({
        "step": 7,
        "name": "JTI Presence & Revocation Blacklist Check",
        "passed": True,
        "detail": f"Token jti='{jti}' is active and not revoked",
    })

    # Step 8: Downstream Identity & Policy Claim Extraction (sub, role, scopes)
    sub = payload.get("sub")
    role = payload.get("role", "user")
    scopes = payload.get("scopes", [])

    if expected_role and role != expected_role and role != "admin":
        steps.append({
            "step": 8,
            "name": "Downstream Identity & Role/Scope Extraction",
            "passed": False,
            "detail": f"Extracted sub='{sub}', role='{role}', but route requires role='{expected_role}' (OWASP API5)",
        })
        return {
            "valid": False,
            "failure_code": "jwt_insufficient_role",
            "reason": f"Insufficient role '{role}' (requires '{expected_role}')",
            "owasp_id": "API5",
            "header": header,
            "payload": payload,
            "steps": steps,
        }

    if expected_scope and expected_scope not in scopes and role != "admin":
        steps.append({
            "step": 8,
            "name": "Downstream Identity & Role/Scope Extraction",
            "passed": False,
            "detail": f"Missing required scope '{expected_scope}' in {scopes}",
        })
        return {
            "valid": False,
            "failure_code": "jwt_insufficient_scope",
            "reason": f"Missing required scope '{expected_scope}'",
            "owasp_id": "API5",
            "header": header,
            "payload": payload,
            "steps": steps,
        }

    steps.append({
        "step": 8,
        "name": "Downstream Identity & Role/Scope Extraction",
        "passed": True,
        "detail": f"Extracted sub='{sub}', role='{role}', scopes={scopes}",
    })

    return {
        "valid": True,
        "failure_code": None,
        "reason": "All 8 JWT security checks passed",
        "owasp_id": None,
        "header": header,
        "payload": payload,
        "steps": steps,
    }


def mint_demo_jwt(
    sub: str = "user-101",
    email: str = "alice@vulnshop.io",
    role: str = "user",
    scopes: Optional[List[str]] = None,
    preset: str = "valid_user",
    session: Optional[Session] = None,
) -> Dict[str, Any]:
    """Generates valid or intentionally malicious JWTs for the Token Tester and Attack Simulator."""
    now = int(time.time())
    if scopes is None:
        scopes = ["read:products", "read:orders", "write:orders"]

    jti = f"jti-{uuid.uuid4().hex[:10]}"
    payload: Dict[str, Any] = {
        "sub": sub,
        "email": email,
        "role": role,
        "scopes": scopes,
        "iss": jwt_runtime_config.issuer,
        "aud": jwt_runtime_config.audience,
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        "jti": jti,
    }
    headers: Dict[str, Any] = {"alg": "HS256", "typ": "JWT", "kid": "vulnshop-key-2026"}

    if preset == "valid_admin":
        payload["sub"] = "admin-999"
        payload["email"] = "admin@vulnshop.io"
        payload["role"] = "admin"
        payload["scopes"] = ["read:products", "read:orders", "write:orders", "admin:users"]
        token = jwt.encode(payload, jwt_runtime_config.secret, algorithm="HS256", headers=headers)
        return {"token": token, "preset": preset, "description": "Valid Admin JWT with full scopes"}

    if preset == "expired":
        payload["iat"] = now - 7200
        payload["nbf"] = now - 7200
        payload["exp"] = now - 1800
        token = jwt.encode(payload, jwt_runtime_config.secret, algorithm="HS256", headers=headers)
        return {"token": token, "preset": preset, "description": "Expired JWT (exp was 30 minutes ago)"}

    if preset == "alg_none":
        headers["alg"] = "none"
        payload["role"] = "admin"
        payload["sub"] = "admin-999"
        h_b64 = _b64url_encode(json.dumps(headers).encode("utf-8"))
        p_b64 = _b64url_encode(json.dumps(payload).encode("utf-8"))
        token = f"{h_b64}.{p_b64}."
        return {"token": token, "preset": preset, "description": "Forged unsigned JWT with alg=none and role=admin"}

    if preset == "tampered_sig":
        valid_token = jwt.encode(payload, jwt_runtime_config.secret, algorithm="HS256", headers=headers)
        parts = valid_token.split(".")
        # Escalate role in payload without re-signing
        tampered_payload = dict(payload, role="admin", sub="admin-999")
        parts[1] = _b64url_encode(json.dumps(tampered_payload).encode("utf-8"))
        token = ".".join(parts)
        return {"token": token, "preset": preset, "description": "Payload modified to role=admin without valid signature"}

    if preset == "wrong_issuer":
        payload["iss"] = "https://evil-idp.attacker.io"
        token = jwt.encode(payload, jwt_runtime_config.secret, algorithm="HS256", headers=headers)
        return {"token": token, "preset": preset, "description": "Signed token from untrusted issuer (iss mismatch)"}

    if preset == "revoked_jti":
        payload["jti"] = "jti-revoked-demo-token-001"
        if session is not None:
            existing = session.exec(select(RevokedToken).where(RevokedToken.jti == payload["jti"])).first()
            if not existing:
                session.add(RevokedToken(
                    jti=payload["jti"],
                    user_sub=sub,
                    reason="Compromised session token revoked by SOC",
                    revoked_by="analyst@sentinel.local",
                ))
                session.commit()
        token = jwt.encode(payload, jwt_runtime_config.secret, algorithm="HS256", headers=headers)
        return {"token": token, "preset": preset, "description": "Token with JTI on the revocation blacklist"}

    token = jwt.encode(payload, jwt_runtime_config.secret, algorithm="HS256", headers=headers)
    return {"token": token, "preset": "valid_user", "description": "Standard valid customer JWT (role=user)"}


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def verify_api_key(raw_key: str, session: Session) -> Tuple[bool, Optional[ApiKey], str]:
    """Constant-time verification of X-API-Key against stored SHA-256 hashes."""
    if not raw_key:
        return False, None, "Missing X-API-Key header"
    candidate_hash = hash_api_key(raw_key.strip())
    all_keys = session.exec(select(ApiKey)).all()
    for api_key in all_keys:
        if hmac.compare_digest(api_key.hashed_key, candidate_hash):
            if api_key.revoked:
                return False, api_key, "API key has been revoked"
            return True, api_key, "Valid API key"
    return False, None, "Invalid or unknown API key"
