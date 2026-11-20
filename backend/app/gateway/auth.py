import base64
import hashlib
import hmac
import json
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
import httpx
import jwt
from sqlmodel import Session, select
from app.config import settings
from app.models import ApiKey, RequestLog, RevokedToken, UpstreamJWTConfig

FIREBASE_GOOGLE_CERTS_URL = (
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
)
_firebase_certs_cache: Dict[str, Any] = {"fetched_at": 0.0, "certs": {}}


def _fetch_google_firebase_certs() -> Dict[str, str]:
    now = time.time()
    if _firebase_certs_cache["certs"] and (now - _firebase_certs_cache["fetched_at"] < 3600):
        return _firebase_certs_cache["certs"]
    try:
        resp = httpx.get(FIREBASE_GOOGLE_CERTS_URL, timeout=6.0)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict):
                _firebase_certs_cache["certs"] = data
                _firebase_certs_cache["fetched_at"] = now
                return data
    except Exception:
        pass
    return _firebase_certs_cache.get("certs") or {}


def _prepare_verification_key(raw_key: Any, kid: Optional[str], alg: str, iss: Optional[str] = None) -> Tuple[Any, str]:
    """
    Normalizes a user-supplied verification key or certificate for PyJWT:
    - Unescapes literal '\\n' sequences from single-line inputs or JSON strings
    - Supports pasting the entire Google x509 JSON map ({kid: cert_pem, ...})
    - Automatically fetches Google Firebase public x509 certs when alg=='RS256' and
      either the token issuer is https://securetoken.google.com/... or key is 'firebase'/'auto'
    - Extracts the RSA public key from X.509 certificates (-----BEGIN CERTIFICATE-----)
    """
    key_str = (str(raw_key) if raw_key is not None else "").strip()

    # Check if user pasted the entire Google certs JSON object {"kid1": "-----BEGIN CERTIFICATE...", ...}
    if key_str.startswith("{"):
        try:
            parsed_map = json.loads(key_str)
            if isinstance(parsed_map, dict):
                if kid and kid in parsed_map:
                    key_str = str(parsed_map[kid]).strip()
                elif parsed_map:
                    key_str = str(next(iter(parsed_map.values()))).strip()
        except Exception:
            pass

    # Replace literal \n or /n with real newlines and strip surrounding quotes
    if key_str.startswith(('"', "'")) and key_str.endswith(('"', "'")) and len(key_str) > 2:
        key_str = key_str[1:-1].strip()
    key_str = key_str.replace("\\r\\n", "\n").replace("\\n", "\n").strip()

    is_firebase_issuer = isinstance(iss, str) and iss.startswith("https://securetoken.google.com/")
    is_firebase_shortcut = key_str.lower() in ("firebase", "google", "auto", "") or "googleapis.com" in key_str

    # If the user pasted raw base64 X.509 certificate content without -----BEGIN CERTIFICATE----- headers
    # (e.g. "MIID..."), wrap it in standard PEM certificate headers automatically!
    if (
        alg.upper() == "RS256"
        and "BEGIN " not in key_str
        and (key_str.startswith("MII") or len(key_str) > 200)
    ):
        clean_b64 = "".join(key_str.split())
        key_str = f"-----BEGIN CERTIFICATE-----\n{clean_b64}\n-----END CERTIFICATE-----\n"

    # If RS256 and Firebase issuer (or user typed 'firebase' / Google URL), resolve kid from Google certs if needed
    if alg.upper() == "RS256" and (is_firebase_issuer or is_firebase_shortcut):
        if "BEGIN CERTIFICATE" not in key_str and "BEGIN PUBLIC KEY" not in key_str and "BEGIN RSA PUBLIC KEY" not in key_str:
            certs = _fetch_google_firebase_certs()
            if kid and kid in certs:
                key_str = certs[kid].replace("\\n", "\n").strip()

    if "BEGIN CERTIFICATE" in key_str:
        from cryptography.x509 import load_pem_x509_certificate
        # Normalize PEM formatting in case spaces were pasted instead of newlines inside the body
        lines = [ln.strip() for ln in key_str.splitlines() if ln.strip()]
        if len(lines) == 1:
            body = (
                key_str.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace(" ", "")
                .strip()
            )
            key_str = f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"
        try:
            cert_obj = load_pem_x509_certificate(key_str.encode("utf-8"))
            return cert_obj.public_key(), f"X.509 Certificate (kid='{kid or 'default'}')"
        except Exception:
            # If user pasted a token rotated to another Firebase kid, try fetching matching kid from Google certs
            if is_firebase_issuer and kid:
                certs = _fetch_google_firebase_certs()
                if kid in certs:
                    cert_obj = load_pem_x509_certificate(certs[kid].encode("utf-8"))
                    return cert_obj.public_key(), f"Firebase Google X.509 Certificate (kid='{kid}')"
            raise

    if "BEGIN PUBLIC KEY" in key_str or "BEGIN RSA PUBLIC KEY" in key_str:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        return load_pem_public_key(key_str.encode("utf-8")), f"RSA Public Key (kid='{kid or 'default'}')"

    return key_str, f"Shared Secret (kid='{kid or 'default'}')"


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
            "sentinel-key-2026": settings.GATEWAY_JWT_SECRET,
            "default": settings.GATEWAY_JWT_SECRET,
        }


jwt_runtime_config = JWTConfigRuntime()


def get_upstream_jwt_config(session: Session, upstream_id: int) -> Optional[Dict[str, Any]]:
    """Return strict verification settings for an upstream, or None for the built-in default."""
    stored = session.exec(
        select(UpstreamJWTConfig).where(
            UpstreamJWTConfig.upstream_id == upstream_id,
            UpstreamJWTConfig.enabled == True,
        )
    ).first()
    if not stored:
        return None
    try:
        algorithms = json.loads(stored.allowed_algorithms_json or '["HS256"]')
    except Exception:
        algorithms = ["HS256"]
    return {
        "allowed_algorithms": algorithms,
        "verification_key": stored.verification_key,
        "issuer": stored.issuer or None,
        "audience": stored.audience or None,
        "require_jti": stored.require_jti,
        "leeway_seconds": stored.leeway_seconds,
    }


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * ((4 - len(segment) % 4) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _normalize_jti(value: Any) -> str:
    return str(value or "").strip().strip('"').strip("'").strip()


def extract_revocation_identity(raw: str) -> Tuple[str, Optional[str]]:
    """Accept a raw jti or a full Bearer JWT and return (jti, sub)."""
    text = _normalize_jti(raw)
    if text.lower().startswith("bearer "):
        text = _normalize_jti(text[7:])
    parts = text.split(".")
    if len(parts) == 3 and parts[1]:
        try:
            payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
            if isinstance(payload, dict) and payload.get("jti"):
                sub = payload.get("sub")
                return _normalize_jti(payload.get("jti")), (str(sub).strip() if sub else None)
        except Exception:
            pass
    return text, None


def _stored_jti_aliases(stored: str) -> set:
    aliases = set()
    direct = _normalize_jti(stored)
    if direct:
        aliases.add(direct)
    extracted, _sub = extract_revocation_identity(stored)
    if extracted:
        aliases.add(extracted)
    return aliases


def find_revoked_token(session: Session, jti: Any) -> Optional[RevokedToken]:
    """Match a token jti against the blacklist, including rows that stored a full JWT."""
    target = _normalize_jti(jti)
    if not target:
        return None
    direct = session.exec(select(RevokedToken).where(RevokedToken.jti == target)).first()
    if direct:
        return direct
    for row in session.exec(select(RevokedToken)).all():
        if target in _stored_jti_aliases(row.jti):
            return row
    return None


def describe_active_jwt_config(jwt_config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Pinned validation view for one project, or the built-in gateway default."""
    if jwt_config:
        key = str(jwt_config.get("verification_key") or "")
        algorithms = list(jwt_config.get("allowed_algorithms") or ["HS256"])
        uses_rsa = any(str(alg).upper() == "RS256" for alg in algorithms) or "BEGIN " in key
        return {
            "source": "project",
            "allowed_algorithms": algorithms,
            "issuer": jwt_config.get("issuer") or None,
            "audience": jwt_config.get("audience") or None,
            "leeway_seconds": jwt_config.get("leeway_seconds", 10),
            "require_jti": bool(jwt_config.get("require_jti", False)),
            "reject_alg_none": True,
            "key_label": "Project RSA public key" if uses_rsa else "Project shared secret",
            "trusted_kids": ["project-verification-key"],
        }
    return {
        "source": "gateway_default",
        "allowed_algorithms": list(jwt_runtime_config.allowed_algorithms),
        "issuer": jwt_runtime_config.issuer,
        "audience": jwt_runtime_config.audience,
        "leeway_seconds": jwt_runtime_config.leeway_seconds,
        "require_jti": jwt_runtime_config.require_jti,
        "reject_alg_none": jwt_runtime_config.reject_alg_none,
        "key_label": "Built-in gateway secret",
        "trusted_kids": list(jwt_runtime_config.trusted_kids.keys()),
    }


def project_can_mint_hs256(jwt_config: Optional[Dict[str, Any]]) -> bool:
    """True when this process can sign a preset token the project verifier will accept."""
    if not jwt_config:
        return True
    key = str(jwt_config.get("verification_key") or "").strip()
    algorithms = [str(alg).upper() for alg in (jwt_config.get("allowed_algorithms") or [])]
    return bool(
        key
        and "BEGIN " not in key
        and key.lower() != "firebase"
        and (not algorithms or "HS256" in algorithms)
    )


def _fail_step(
    steps: List[Dict[str, Any]],
    step_num: int,
    name: str,
    detail: str,
    failure_code: str,
    reason: str,
    owasp_id: str = "API2",
    header: Optional[Dict[str, Any]] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    steps.append({"step": step_num, "name": name, "passed": False, "detail": detail})
    return {
        "valid": False,
        "failure_code": failure_code,
        "reason": reason,
        "owasp_id": owasp_id,
        "header": header or {},
        "payload": payload or {},
        "steps": steps,
    }


def validate_jwt_checklist(
    token: str,
    session: Session,
    expected_role: Optional[str] = None,
    expected_scope: Optional[str] = None,
    jwt_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Executes the 8-point OWASP API2 JWT validation checklist and returns both:
    - overall `valid` boolean, `failure_code`, `http_status`
    - step-by-step `steps` list for the Token Tester UI and forensic logging.
    """
    steps: List[Dict[str, Any]] = []
    allowed_algorithms = (
        list(jwt_config.get("allowed_algorithms") or ["HS256"])
        if jwt_config
        else list(jwt_runtime_config.allowed_algorithms)
    )
    expected_issuer = jwt_config.get("issuer") if jwt_config else jwt_runtime_config.issuer
    expected_audience = jwt_config.get("audience") if jwt_config else jwt_runtime_config.audience
    require_jti = bool(jwt_config.get("require_jti", False)) if jwt_config else jwt_runtime_config.require_jti
    leeway_seconds = int(jwt_config.get("leeway_seconds", 10)) if jwt_config else jwt_runtime_config.leeway_seconds
    raw = (token or "").strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()

    parts = raw.split(".")
    if len(parts) != 3:
        return _fail_step(
            steps, 1, "Token Structure & Header Parse",
            f"Malformed JWT: expected 3 dot-separated segments, got {len(parts)}",
            "jwt_malformed", "Malformed JWT structure",
        )

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
        return _fail_step(
            steps, 1, "Token Structure & Header Parse",
            f"Failed to base64url decode header/payload: {exc}",
            "jwt_decode_error", "Invalid base64/JSON in JWT segments",
        )

    # Step 2: Pin allowed algorithms & reject alg=none / algorithm confusion
    alg = str(header.get("alg", "")).strip()
    iss_claim = payload.get("iss")
    is_firebase_token = isinstance(iss_claim, str) and iss_claim.startswith("https://securetoken.google.com/")

    if alg.lower() == "none" or not parts[2]:
        return _fail_step(
            steps, 2, "Algorithm Pinning & alg=none Defense",
            f"CRITICAL: Token uses unauthenticated 'alg={alg}' or empty signature segment",
            "jwt_alg_none", "Rejected alg=none unsigned JWT attack",
            header=header, payload=payload,
        )

    effective_allowed_algorithms = list(allowed_algorithms)
    if is_firebase_token and "RS256" not in effective_allowed_algorithms:
        effective_allowed_algorithms.append("RS256")

    if alg not in effective_allowed_algorithms:
        return _fail_step(
            steps, 2, "Algorithm Pinning & alg=none Defense",
            f"Algorithm '{alg}' is not in pinned allowlist {effective_allowed_algorithms}",
            "jwt_algorithm_confusion", f"Disallowed JWT algorithm '{alg}'",
            header=header, payload=payload,
        )

    steps.append({
        "step": 2,
        "name": "Algorithm Pinning & alg=none Defense",
        "passed": True,
        "detail": f"Algorithm '{alg}' matches pinned allowlist {effective_allowed_algorithms}",
    })

    # Step 3: Local Key ID (kid) allowlist lookup (prevent kid SQLi / path traversal)
    kid = header.get("kid", "default")
    raw_signing_key = (
        jwt_config.get("verification_key")
        if jwt_config
        else jwt_runtime_config.trusted_kids.get(str(kid))
    )
    if not raw_signing_key and is_firebase_token:
        raw_signing_key = "firebase"

    if not raw_signing_key:
        return _fail_step(
            steps, 3, "Local Key ID (kid) Registry Lookup",
            f"Untrusted or unknown kid='{kid}' in JWT header (blocked potential kid injection)",
            "jwt_untrusted_kid", f"Untrusted key identifier kid='{kid}'",
            header=header, payload=payload,
        )

    try:
        signing_key, key_source_label = _prepare_verification_key(raw_signing_key, str(kid), alg, iss_claim)
    except Exception as exc:
        return _fail_step(
            steps, 3, "Local Key ID (kid) Registry Lookup",
            f"Failed to parse public key / X.509 certificate for kid='{kid}': {exc}",
            "jwt_invalid_key", f"Invalid verification key or X.509 certificate format: {exc}",
            header=header, payload=payload,
        )

    steps.append({
        "step": 3,
        "name": "Local Key ID (kid) Registry Lookup",
        "passed": True,
        "detail": f"Resolved {key_source_label} from trusted key store",
    })

    # Step 4: Cryptographic signature verification
    decode_opts = {
        "verify_signature": True,
        "verify_exp": False,
        "verify_nbf": False,
        "verify_iat": False,
        "verify_aud": False,
        "verify_iss": False,
    }
    try:
        try:
            jwt.decode(raw, signing_key, algorithms=effective_allowed_algorithms, options=decode_opts)
        except jwt.InvalidSignatureError:
            if is_firebase_token and kid:
                certs = _fetch_google_firebase_certs()
                if kid in certs:
                    from cryptography.x509 import load_pem_x509_certificate
                    fb_pub = load_pem_x509_certificate(certs[kid].encode("utf-8")).public_key()
                    jwt.decode(raw, fb_pub, algorithms=effective_allowed_algorithms, options=decode_opts)
                    key_source_label = f"Google Firebase X.509 certificate (kid='{kid}')"
                else:
                    raise
            else:
                raise
        steps.append({
            "step": 4,
            "name": "Cryptographic Signature Verification",
            "passed": True,
            "detail": f"{alg} cryptographic signature verified against {key_source_label}",
        })
    except jwt.InvalidSignatureError:
        return _fail_step(
            steps, 4, "Cryptographic Signature Verification",
            "CRITICAL: Signature mismatch — payload or header was tampered with",
            "jwt_bad_signature", "JWT cryptographic signature verification failed",
            header=header, payload=payload,
        )
    except Exception as exc:
        return _fail_step(
            steps, 4, "Cryptographic Signature Verification",
            f"Signature verification failed: {exc}",
            "jwt_bad_signature", f"JWT signature error: {exc}",
            header=header, payload=payload,
        )

    # Step 5: Temporal claims (exp, nbf, iat) with clock-skew leeway
    now = int(time.time())
    leeway = leeway_seconds
    exp = payload.get("exp")
    nbf = payload.get("nbf")
    iat = payload.get("iat")

    if exp is None or not isinstance(exp, (int, float)):
        return _fail_step(
            steps, 5, "Temporal Claims (exp, nbf, iat) & Leeway",
            "Missing required 'exp' (expiration) claim",
            "jwt_missing_exp", "Missing exp claim",
            header=header, payload=payload,
        )

    if now > int(exp) + leeway:
        expired_ago = now - int(exp)
        return _fail_step(
            steps, 5, "Temporal Claims (exp, nbf, iat) & Leeway",
            f"Token expired {expired_ago}s ago (leeway={leeway}s)",
            "jwt_expired", f"Token expired {expired_ago}s ago",
            header=header, payload=payload,
        )

    if nbf is not None and now + leeway < int(nbf):
        return _fail_step(
            steps, 5, "Temporal Claims (exp, nbf, iat) & Leeway",
            f"Token not valid before nbf={nbf} (now={now})",
            "jwt_immature", "Token nbf is in the future",
            header=header, payload=payload,
        )

    if iat is not None and isinstance(iat, (int, float)) and int(iat) > now + leeway:
        return _fail_step(
            steps, 5, "Temporal Claims (exp, nbf, iat) & Leeway",
            f"Token 'iat' is in the future (iat={iat}, now={now}, leeway={leeway}s)",
            "jwt_future_iat", "Token iat claim is in the future",
            header=header, payload=payload,
        )

    steps.append({
        "step": 5,
        "name": "Temporal Claims (exp, nbf, iat) & Leeway",
        "passed": True,
        "detail": f"Valid temporal window (expires in {int(exp) - now}s, leeway={leeway}s, iat={iat})",
    })

    # Step 6: Issuer (iss) and Audience (aud) validation
    iss = payload.get("iss")
    aud = payload.get("aud")
    if is_firebase_token and not jwt_config:
        expected_issuer = None
        expected_audience = None
        require_jti = False
    issuer_valid = not expected_issuer or iss == expected_issuer

    def _aud_matches(actual: Any, expected: Optional[str]) -> bool:
        if not expected:
            return True
        if isinstance(actual, list):
            return expected in actual
        return actual == expected

    audience_valid = _aud_matches(aud, expected_audience)
    if not issuer_valid or not audience_valid:
        return _fail_step(
            steps, 6, "Issuer (iss) & Audience (aud) Binding",
            f"Claim mismatch: got iss='{iss}', aud='{aud}' (expected iss='{expected_issuer or 'not required'}', aud='{expected_audience or 'not required'}')",
            "jwt_invalid_claims", "Invalid issuer (iss) or audience (aud)",
            header=header, payload=payload,
        )

    steps.append({
        "step": 6,
        "name": "Issuer (iss) & Audience (aud) Binding",
        "passed": True,
        "detail": (
            f"Verified configured claims (iss='{iss}', aud='{aud}')"
            if expected_issuer or expected_audience
            else "Issuer and audience are not required for this API project"
        ),
    })

    # Step 7: JTI presence and revocation blacklist check
    jti = _normalize_jti(payload.get("jti"))
    if require_jti and not jti:
        return _fail_step(
            steps, 7, "JTI Presence & Revocation Blacklist Check",
            "Missing required 'jti' unique token identifier",
            "jwt_missing_jti", "Missing required jti claim",
            header=header, payload=payload,
        )

    if jti:
        revoked = find_revoked_token(session, jti)
        if revoked:
            return _fail_step(
                steps, 7, "JTI Presence & Revocation Blacklist Check",
                f"Token jti='{jti}' is on the revocation blacklist ({revoked.reason})",
                "jwt_revoked", f"Token jti='{jti}' has been revoked",
                header=header, payload=payload,
            )

    steps.append({
        "step": 7,
        "name": "JTI Presence & Revocation Blacklist Check",
        "passed": True,
        "detail": f"Token jti='{jti}' is active and not revoked",
    })

    # Step 8: Downstream Identity & Policy Claim Extraction (sub, role, scopes)
    sub = payload.get("sub")
    role = str(payload.get("role", "user"))
    scopes = payload.get("scopes", [])

    if expected_role and role.lower() != expected_role.lower() and role.lower() != "admin":
        return _fail_step(
            steps, 8, "Downstream Identity & Role/Scope Extraction",
            f"Extracted sub='{sub}', role='{role}', but route requires role='{expected_role}' (OWASP API5)",
            "jwt_insufficient_role", f"Insufficient role '{role}' (requires '{expected_role}')",
            owasp_id="API5", header=header, payload=payload,
        )

    if expected_scope and expected_scope not in scopes and role.lower() != "admin":
        return _fail_step(
            steps, 8, "Downstream Identity & Role/Scope Extraction",
            f"Missing required scope '{expected_scope}' in {scopes}",
            "jwt_insufficient_scope", f"Missing required scope '{expected_scope}'",
            owasp_id="API5", header=header, payload=payload,
        )

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


def _simulator_signing_material(jwt_config: Optional[Dict[str, Any]] = None) -> Tuple[str, str, Optional[str], Optional[str]]:
    """
    Prefer the selected project's HS256 shared secret so simulator traffic can pass
    that project's JWT verification. Fall back to the gateway default key.
    """
    if jwt_config:
        key = str(jwt_config.get("verification_key") or "").strip()
        algorithms = [str(alg).upper() for alg in (jwt_config.get("allowed_algorithms") or [])]
        can_sign_hs256 = (
            bool(key)
            and "BEGIN " not in key
            and key.lower() != "firebase"
            and (not algorithms or "HS256" in algorithms)
        )
        if can_sign_hs256:
            issuer = str(jwt_config.get("issuer") or "").strip() or None
            audience = str(jwt_config.get("audience") or "").strip() or None
            return (key, "HS256", issuer, audience)
    return (
        jwt_runtime_config.secret,
        "HS256",
        jwt_runtime_config.issuer,
        jwt_runtime_config.audience,
    )


def infer_simulator_subject(
    session: Session,
    upstream_id: int,
    path: str = "",
) -> str:
    """
    Pick a JWT `sub` that is safe for an arbitrary connected API.

    Many backends do `int(token.sub)` to load User.id. Non-numeric subjects
    pass gateway verification and then crash the upstream with 500.
    Prefer a subject that already succeeded against this project; otherwise
    use a numeric id from the target path; otherwise default to `1`.
    """
    prior = session.exec(
        select(RequestLog.user_sub)
        .where(
            RequestLog.upstream_id == upstream_id,
            RequestLog.decision == "allowed",
            RequestLog.status_code < 400,
            RequestLog.user_sub != None,
        )
        .order_by(RequestLog.id.desc())
    ).first()
    if prior:
        candidate = str(prior).strip()
        if candidate and not candidate.startswith("apikey:"):
            return candidate

    match = re.search(r"/(\d+)(?:/|$)", "/" + (path or "").lstrip("/"))
    if match:
        return match.group(1)
    return "1"


def simulator_object_id(subject: str) -> str:
    """Numeric object id derived from a JWT subject (`user-101` → `101`)."""
    digits = re.sub(r"\D", "", subject or "")
    return digits or "1"


def _decode_unverified_jwt(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
    raw = (token or "").strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    if not raw:
        raise ValueError("Invalid JWT: token is empty")
    parts = raw.split(".")
    if len(parts) != 3:
        raise ValueError(
            f"Invalid JWT: expected 3 dot-separated segments, got {len(parts)}"
        )
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    except Exception:
        raise ValueError("Invalid JWT: header or payload could not be decoded")
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("Invalid JWT: header and payload must be JSON objects")
    return header, payload, raw


def subject_from_jwt_payload(payload: Dict[str, Any]) -> str:
    candidates: List[str] = []
    for key in ("sub", "user_id", "id", "uid", "userId"):
        value = payload.get(key)
        if value is not None and str(value).strip():
            candidates.append(str(value).strip())
    if not candidates:
        return "1"
    for candidate in candidates:
        if re.search(r"\d", candidate):
            return candidate
    return candidates[0]


def resolve_simulator_user_jwt(
    token: Optional[str],
    session: Session,
    upstream_id: int,
) -> Dict[str, Any]:
    """
    Resolve the caller JWT used by the Attack Simulator for a specific project.

    A supplied token must be a real, well-formed, non-expired JWT. When the
    project has JWT verification configured, the token must also pass that
    project's validator. An empty token falls back to a minted demo JWT.
    """
    raw_input = (token or "").strip()
    if not raw_input:
        subject = infer_simulator_subject(session, upstream_id)
        minted = mint_demo_jwt(
            sub=subject,
            email="alice@sentinel.local",
            role="user",
            preset="valid_user",
            session=session,
            upstream_id=upstream_id,
        )
        return {
            "token": minted["token"],
            "subject": subject,
            "header": {},
            "payload": {"sub": subject, "role": "user"},
            "source": "minted",
        }

    header, payload, raw = _decode_unverified_jwt(raw_input)
    alg = str(header.get("alg") or "").strip()
    signature = raw.split(".")[2]
    if alg.lower() == "none" or not signature:
        raise ValueError(
            "Invalid JWT: unsigned alg=none tokens cannot be used as the project simulation token"
        )

    exp = payload.get("exp")
    if exp is not None:
        try:
            exp_ts = int(exp)
        except (TypeError, ValueError):
            raise ValueError("Invalid JWT: exp claim is not a valid timestamp")
        if exp_ts < int(time.time()) - 10:
            raise ValueError("Invalid JWT: token has expired")

    jwt_config = get_upstream_jwt_config(session, upstream_id)
    if jwt_config:
        result = validate_jwt_checklist(raw, session, jwt_config=jwt_config)
        if not result.get("valid"):
            reason = result.get("reason") or "token failed project JWT verification"
            code = result.get("failure_code") or "jwt_invalid"
            raise ValueError(f"Invalid JWT: {reason} ({code})")
        payload = result.get("payload") or payload
        header = result.get("header") or header

    return {
        "token": raw,
        "subject": subject_from_jwt_payload(payload),
        "header": header,
        "payload": payload,
        "source": "provided",
    }


def mint_demo_jwt(
    sub: str = "user-101",
    email: str = "alice@sentinel.local",
    role: str = "user",
    scopes: Optional[List[str]] = None,
    preset: str = "valid_user",
    session: Optional[Session] = None,
    jwt_config: Optional[Dict[str, Any]] = None,
    upstream_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Generates valid or intentionally malicious JWTs for the Token Tester and Attack Simulator."""
    now = int(time.time())
    if scopes is None:
        scopes = ["read:products", "read:orders", "write:orders"]
    if jwt_config is None and session is not None and upstream_id is not None:
        jwt_config = get_upstream_jwt_config(session, upstream_id)

    signing_key, algorithm, issuer, audience = _simulator_signing_material(jwt_config)

    jti = f"jti-{uuid.uuid4().hex[:10]}"
    payload: Dict[str, Any] = {
        "sub": sub,
        "email": email,
        "role": role,
        "scopes": scopes,
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        "jti": jti,
    }
    if str(sub).isdigit():
        payload["user_id"] = int(sub)
        payload["id"] = int(sub)
    if issuer:
        payload["iss"] = issuer
    if audience:
        payload["aud"] = audience
    headers: Dict[str, Any] = {"alg": algorithm, "typ": "JWT"}
    if not jwt_config:
        headers["kid"] = "sentinel-key-2026"

    if preset == "valid_admin":
        payload["sub"] = "admin-999"
        payload["email"] = "admin@sentinel.local"
        payload["role"] = "admin"
        payload["scopes"] = ["read:products", "read:orders", "write:orders", "admin:users"]
        token = jwt.encode(payload, signing_key, algorithm=algorithm, headers=headers)
        return {"token": token, "preset": preset, "description": "Valid Admin JWT with full scopes"}

    if preset == "expired":
        payload["iat"] = now - 7200
        payload["nbf"] = now - 7200
        payload["exp"] = now - 1800
        token = jwt.encode(payload, signing_key, algorithm=algorithm, headers=headers)
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
        valid_token = jwt.encode(payload, signing_key, algorithm=algorithm, headers=headers)
        parts = valid_token.split(".")
        # Escalate role in payload without re-signing
        tampered_payload = dict(payload, role="admin", sub="admin-999")
        parts[1] = _b64url_encode(json.dumps(tampered_payload).encode("utf-8"))
        token = ".".join(parts)
        return {"token": token, "preset": preset, "description": "Payload modified to role=admin without valid signature"}

    if preset == "wrong_issuer":
        payload["iss"] = "https://evil-idp.attacker.io"
        token = jwt.encode(payload, signing_key, algorithm=algorithm, headers=headers)
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
        token = jwt.encode(payload, signing_key, algorithm=algorithm, headers=headers)
        return {"token": token, "preset": preset, "description": "Token with JTI on the revocation blacklist"}

    token = jwt.encode(payload, signing_key, algorithm=algorithm, headers=headers)
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
