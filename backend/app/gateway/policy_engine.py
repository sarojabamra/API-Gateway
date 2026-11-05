import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from sqlmodel import Session, select
from app.models import Policy, Route
from app.demo_api.vulnshop import VULNSHOP_ORDERS
from app.runtime_cache import runtime_cache

PUBLIC_AUTH_PATHS = (
    "/auth/login",
    "/auth/jwt/login",
    "/auth/register",
    "/login",
    "/register",
    "/token",
    "/oauth/token",
    "/health",
    "/api/health",
)

SENSITIVE_FLOW_KEYWORDS = (
    "checkout",
    "order",
    "coupon",
    "payment",
    "transfer",
    "booking",
    "login",
    "register",
)

ADMIN_PATH_KEYWORDS = (
    "admin",
    "internal",
    "debug",
    "actuator",
    "manage",
    "superuser",
)

# Paths/tags that are intentionally world-readable (public profile pages, share links).
PUBLIC_ROUTE_KEYWORDS = (
    "public",
    "shared",
    "share",
    "anonymous",
)

# Path segments / param names that identify a principal (JWT sub), not a resource row.
USER_PATH_SEGMENTS = frozenset(
    {"users", "user", "customers", "customer", "accounts", "account", "owners", "owner", "members", "member"}
)
USER_PARAM_NAMES = frozenset(
    {
        "user_id",
        "userid",
        "uid",
        "owner_id",
        "ownerid",
        "customer_id",
        "customerid",
        "account_id",
        "accountid",
        "member_id",
        "memberid",
    }
)
# Param name substrings that identify resource object IDs (must NOT be compared to JWT sub).
RESOURCE_PARAM_HINTS = (
    "booking",
    "order",
    "slot",
    "vehicle",
    "reservation",
    "park",
    "ticket",
    "invoice",
    "payment",
    "product",
    "item",
    "cart",
    "session",
    "spot",
    "lot",
)
RESOURCE_PATH_SEGMENTS = frozenset(
    {
        "bookings",
        "booking",
        "orders",
        "order",
        "slots",
        "slot",
        "vehicles",
        "vehicle",
        "reservations",
        "reservation",
        "tickets",
        "invoices",
        "payments",
        "products",
        "items",
        "parks",
        "spots",
        "lots",
    }
)

BOLA_MODE_EQUALS_SUB = "equals_sub"
BOLA_MODE_LEARNED_OWNER = "learned_owner"

# Learned owners from successful GETs: key -> user_sub
_LEARNED_OWNERS: Dict[str, Tuple[str, float]] = {}
_LEARNED_OWNER_TTL = 3600.0

# Per-client distinct object ID enumeration tracker for API1 pre-forward enforcement
_BOLA_ENUM_TRACKER: Dict[str, Dict[str, float]] = {}


def is_public_auth_path(path: str) -> bool:
    norm = "/" + path.strip("/").lower()
    return norm in PUBLIC_AUTH_PATHS or norm.endswith(PUBLIC_AUTH_PATHS)


def _normalize_param_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _normalize_subject(value: str) -> str:
    """Normalize JWT sub / path user ids for equality (`user-101` → `101`)."""
    text = str(value or "").strip()
    if text.lower().startswith("user-"):
        text = text[5:]
    return text


def is_user_like_param(param_name: str, path_pattern: str = "") -> bool:
    """
    True when a path/query param represents the authenticated principal
    (safe to compare against JWT sub), not an arbitrary resource row.
    """
    raw = (param_name or "").strip("{}")
    norm = _normalize_param_name(raw)
    if norm in USER_PARAM_NAMES:
        return True

    # Generic {id}/{userId} under a user collection: /users/{id}
    if norm in ("id", "userid") or raw.lower() in ("id", "userid"):
        parent = _parent_segment_for_param(path_pattern, raw)
        if parent in USER_PATH_SEGMENTS:
            return True
        if parent in RESOURCE_PATH_SEGMENTS:
            return False
        # Bare {id} with no clear parent: only treat as user when path mentions users/
        path_lower = (path_pattern or "").lower()
        if any(f"/{seg}/" in f"/{path_lower.strip('/')}/" for seg in USER_PATH_SEGMENTS):
            return True
        return False

    # Explicit resource naming wins even if "id" is embedded (bookingId, order_id)
    if any(hint in norm for hint in RESOURCE_PARAM_HINTS):
        return False
    return False


def is_resource_like_param(param_name: str, path_pattern: str = "") -> bool:
    """True when the param is a resource object id (booking, order, slot, …)."""
    if is_user_like_param(param_name, path_pattern):
        return False
    raw = (param_name or "").strip("{}")
    norm = _normalize_param_name(raw)
    if any(hint in norm for hint in RESOURCE_PARAM_HINTS):
        return True
    parent = _parent_segment_for_param(path_pattern, raw)
    if parent in RESOURCE_PATH_SEGMENTS:
        return True
    # Generic leftover id params on non-user paths are treated as resource IDs
    if norm in ("id",) or raw.lower() == "id":
        return parent not in USER_PATH_SEGMENTS
    return "{" in (path_pattern or "") and bool(raw)


def _parent_segment_for_param(path_pattern: str, param_name: str) -> str:
    """Return the static path segment immediately before `{param_name}`."""
    pattern = "/" + (path_pattern or "").strip("/")
    target = "{" + param_name.strip("{}") + "}"
    parts = [p for p in pattern.split("/") if p]
    for idx, part in enumerate(parts):
        # Support both {id} and { bookingId } style
        if part.strip() == target or part.strip("{}") == param_name.strip("{}"):
            if idx > 0:
                return parts[idx - 1].lower().strip("{}")
            return ""
    return ""


def _infer_bola_param(path_pattern: str) -> str:
    params = re.findall(r"\{([^}]+)\}", path_pattern)
    if not params:
        return "id"
    # Prefer an explicit user principal param when present
    for param in params:
        if is_user_like_param(param, path_pattern):
            return param
    for preferred in ("user_id", "order_id", "owner_id", "booking_id", "bookingId", "id"):
        if preferred in params:
            return preferred
    return params[0]


def infer_bola_mode(path_pattern: str, bola_param: Optional[str] = None) -> str:
    """
    equals_sub  — path/query id IS the user (e.g. /users/{id}); compare to JWT sub.
    learned_owner — id is a resource row (booking/order); use owner map / learned cache.
    """
    param = bola_param or _infer_bola_param(path_pattern)
    if is_user_like_param(param, path_pattern):
        return BOLA_MODE_EQUALS_SUB
    return BOLA_MODE_LEARNED_OWNER


def _is_public_content_route(
    path_pattern: str,
    op_spec: Optional[Dict[str, Any]] = None,
) -> bool:
    """True for intentionally unauthenticated / public profile-style endpoints."""
    path_lower = (path_pattern or "").lower()
    tags_lower = str((op_spec or {}).get("tags", "")).lower()
    summary_lower = str((op_spec or {}).get("summary", "")).lower()
    desc_lower = str((op_spec or {}).get("description", "")).lower()
    blob = f"{path_lower} {tags_lower} {summary_lower} {desc_lower}"
    if any(k in blob for k in PUBLIC_ROUTE_KEYWORDS):
        return True
    # OpenAPI: security: [] explicitly marks the operation as public
    if isinstance(op_spec, dict) and op_spec.get("security") == []:
        return True
    return False


def infer_route_security(
    path_pattern: str,
    op_spec: Optional[Dict[str, Any]] = None,
    root_spec: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Infers route security metadata from path conventions and optional OpenAPI operation spec."""
    path_lower = path_pattern.lower()
    tags_lower = str((op_spec or {}).get("tags", "")).lower()
    has_security = bool((op_spec or {}).get("security") or (root_spec or {}).get("security"))
    is_login_public = is_public_auth_path(path_lower)
    is_public_content = _is_public_content_route(path_pattern, op_spec)
    is_public = is_login_public or is_public_content
    is_admin = any(k in path_lower or k in tags_lower for k in ADMIN_PATH_KEYWORDS)
    has_id_param = "{" in path_pattern
    is_sensitive = any(k in path_lower for k in SENSITIVE_FLOW_KEYWORDS)
    bola_param = _infer_bola_param(path_pattern)
    bola_mode = infer_bola_mode(path_pattern, bola_param) if has_id_param else BOLA_MODE_EQUALS_SUB

    auth_required = False if is_public else (True if is_admin else (has_security or not is_public))
    # BOLA ownership is only for authenticated, non-admin object access.
    # Admin routes use BFLA (role check). Public profile pages stay readable.
    bola_enabled = bool(has_id_param and auth_required and not is_admin and not is_public_content)

    return {
        "auth_required": auth_required,
        "required_role": "admin" if is_admin else None,
        "bola_check_enabled": bola_enabled,
        "bola_owner_claim": "sub",
        "bola_owner_param": bola_param,
        "bola_mode": bola_mode,
        "is_sensitive_flow": is_sensitive,
        "rate_limit_rpm": 20 if is_sensitive else 60,
        "burst_capacity": 5 if is_sensitive else 15,
    }


def match_route_pattern(pattern: str, actual_path: str) -> Tuple[bool, Dict[str, str]]:
    """
    Matches a route pattern like '/users/{id}' against '/users/102'
    and extracts path parameters {'id': '102'}.
    """
    norm_pattern = "/" + pattern.strip("/")
    norm_path = "/" + actual_path.strip("/")

    if norm_pattern == norm_path:
        return True, {}

    regex_parts = ["^"]
    param_names: List[str] = []
    for segment in norm_pattern.strip("/").split("/"):
        if segment.startswith("{") and segment.endswith("}"):
            param_name = segment[1:-1]
            param_names.append(param_name)
            regex_parts.append(r"/([^/]+)")
        else:
            regex_parts.append("/" + re.escape(segment))
    regex_parts.append("$")
    regex = re.compile("".join(regex_parts))
    m = regex.match(norm_path)
    if not m:
        return False, {}
    params = {name: m.group(idx + 1) for idx, name in enumerate(param_names)}
    return True, params


def find_matching_route(
    session: Session,
    upstream_id: int,
    method: str,
    path: str,
) -> Tuple[Optional[Route], Dict[str, str]]:
    """
    Finds a registered Route matching (upstream_id, method, path).
    Prefers exact path matches (e.g., '/users/me') before parameterized matches ('/users/{id}').
    """
    cache_key = f"routes:{upstream_id}:registered"
    routes = runtime_cache.get(cache_key)
    if routes is None:
        routes = session.exec(
            select(Route).where(Route.upstream_id == upstream_id, Route.registered == True)
        ).all()
        runtime_cache.set(cache_key, routes)

    sorted_routes = sorted(routes, key=lambda r: ("{" in r.path_pattern, -len(r.path_pattern)))

    for route in sorted_routes:
        if route.method not in (method.upper(), "*"):
            continue
        matched, params = match_route_pattern(route.path_pattern, path)
        if matched:
            return route, params

    return None, {}


def find_shadow_route(
    session: Session,
    upstream_id: int,
    method: str,
    path: str,
) -> Optional[Route]:
    """Find an existing unregistered (shadow) route using pattern matching."""
    cache_key = f"routes:{upstream_id}:shadow"
    routes = runtime_cache.get(cache_key)
    if routes is None:
        routes = session.exec(
            select(Route).where(Route.upstream_id == upstream_id, Route.registered == False)
        ).all()
        runtime_cache.set(cache_key, routes)

    for route in routes:
        if route.method not in (method.upper(), "*", "GET"):
            continue
        matched, _ = match_route_pattern(route.path_pattern, path)
        if matched or route.path_pattern == path:
            return route
    return None


def _all_policies(session: Session) -> List[Policy]:
    all_policies = runtime_cache.get("policies:all")
    if all_policies is None:
        all_policies = session.exec(select(Policy)).all()
        runtime_cache.set("policies:all", all_policies)
    return list(all_policies)


def check_policy_mode(session: Session, policy_type: str, owasp_id: Optional[str] = None) -> Tuple[bool, str, Optional[int]]:
    """
    Checks if a given policy type or OWASP ID is enabled and whether it is in 'enforce' or 'monitor' mode.
    Returns (is_enabled, mode, policy_id).
    """
    all_policies = _all_policies(session)

    policies = [pol for pol in all_policies if pol.type == policy_type]
    if not policies and owasp_id:
        policies = [pol for pol in all_policies if pol.owasp_id == owasp_id]

    if not policies:
        return True, "enforce", None

    for pol in policies:
        if pol.enabled:
            return True, pol.mode, pol.id
    return False, "disabled", policies[0].id


def get_policy_config(
    session: Session,
    policy_type: str,
    owasp_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Returns merged config_json from the first enabled policy matching type (or owasp_id fallback).
    """
    all_policies = _all_policies(session)
    policies = [pol for pol in all_policies if pol.type == policy_type and pol.enabled]
    if not policies and owasp_id:
        policies = [pol for pol in all_policies if pol.owasp_id == owasp_id and pol.enabled]
    if not policies:
        return {}
    try:
        return json.loads(policies[0].config_json or "{}")
    except Exception:
        return {}


def resolve_bola_owner_param(
    route: Route,
    path_params: Optional[Dict[str, str]] = None,
) -> str:
    """
    Resolve which request param holds the object/user id for BOLA.

    Corrects stale inventory metadata where bola_owner_param was saved as
    generic ``id`` but the path actually uses ``{userId}`` / ``{user_id}``.
    """
    preferred = getattr(route, "bola_owner_param", None) or "id"
    path_params = path_params or {}
    preferred_norm = _normalize_param_name(preferred)

    if path_params:
        for key in path_params:
            if _normalize_param_name(key) == preferred_norm:
                return key
        # Stale config: prefer a user-like path param for equals_sub routes
        mode = resolve_bola_mode(route)
        if mode == BOLA_MODE_EQUALS_SUB:
            for key in path_params:
                if is_user_like_param(key, route.path_pattern):
                    return key
        inferred = _infer_bola_param(route.path_pattern)
        inferred_norm = _normalize_param_name(inferred)
        for key in path_params:
            if _normalize_param_name(key) == inferred_norm:
                return key

    # No live path params — still prefer an inferred name from the pattern
    pattern_params = re.findall(r"\{([^}]+)\}", route.path_pattern or "")
    if preferred_norm not in {_normalize_param_name(p) for p in pattern_params} and pattern_params:
        return _infer_bola_param(route.path_pattern)
    return preferred


def _extract_object_ids(
    route: Route,
    path_params: Dict[str, str],
    query_params: Optional[Dict[str, str]] = None,
    body_json: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """
    Collect the BOLA owner param (and case/underscore aliases).
    Avoid sweeping every id-like field so nested paths like
    /users/{userId}/bookings/{bookingId} do not compare bookingId to JWT sub.
    """
    preferred = resolve_bola_owner_param(route, path_params)
    preferred_norm = _normalize_param_name(preferred)
    candidates: List[str] = []

    for source in (path_params or {}, query_params or {}):
        for key, val in source.items():
            if val and _normalize_param_name(key) == preferred_norm:
                candidates.append(str(val))

    if isinstance(body_json, dict):
        for bk, bv in body_json.items():
            if bv is not None and _normalize_param_name(str(bk)) == preferred_norm:
                candidates.append(str(bv))

    # Deduplicate while preserving order
    seen = set()
    out: List[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _owner_cache_key(upstream_id: int, path_pattern: str, obj_id: str) -> str:
    prefix = path_pattern.split("{")[0].rstrip("/")
    return f"{upstream_id}:{prefix}:{obj_id}"


def remember_object_owner(upstream_id: int, path_pattern: str, obj_id: str, user_sub: str) -> None:
    if not user_sub or not obj_id:
        return
    _LEARNED_OWNERS[_owner_cache_key(upstream_id, path_pattern, obj_id)] = (user_sub, time.time())


def _lookup_learned_owner(upstream_id: int, path_pattern: str, obj_id: str) -> Optional[str]:
    key = _owner_cache_key(upstream_id, path_pattern, obj_id)
    entry = _LEARNED_OWNERS.get(key)
    if not entry:
        return None
    owner, ts = entry
    if time.time() - ts > _LEARNED_OWNER_TTL:
        _LEARNED_OWNERS.pop(key, None)
        return None
    return owner


def list_learned_object_ids(
    upstream_id: int,
    path_pattern: str,
    owner_sub: Optional[str] = None,
) -> List[str]:
    """
    Return object IDs previously learned for a route prefix.
    If owner_sub is set, only return IDs owned by that principal.
    """
    prefix_key = f"{upstream_id}:{path_pattern.split('{')[0].rstrip('/')}:"
    now = time.time()
    results: List[str] = []
    expired: List[str] = []
    for key, (owner, ts) in list(_LEARNED_OWNERS.items()):
        if now - ts > _LEARNED_OWNER_TTL:
            expired.append(key)
            continue
        if not key.startswith(prefix_key):
            continue
        obj_id = key[len(prefix_key) :]
        if owner_sub and owner != owner_sub:
            continue
        if obj_id:
            results.append(obj_id)
    for key in expired:
        _LEARNED_OWNERS.pop(key, None)
    return results


def resolve_bola_mode(route: Route) -> str:
    mode = (getattr(route, "bola_mode", None) or "").strip().lower()
    if mode in (BOLA_MODE_EQUALS_SUB, BOLA_MODE_LEARNED_OWNER):
        return mode
    return infer_bola_mode(route.path_pattern, getattr(route, "bola_owner_param", None))


def check_bola_ownership(
    route: Route,
    path_params: Dict[str, str],
    user_sub: Optional[str],
    user_role: Optional[str],
    query_params: Optional[Dict[str, str]] = None,
    body_json: Optional[Dict[str, Any]] = None,
    decoded_jwt: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, Optional[str]]:
    """
    OWASP API1 (Broken Object Level Authorization):

    equals_sub     — object id must match the JWT owner claim (user profile routes).
    learned_owner  — object id is a resource row; allow only when VulnShop map /
                     learned-owner cache says this principal owns it. Unknown
                     owners fail-open so first legitimate GETs can seed the cache
                     (enumeration caps still apply in the pipeline).
    """
    if not route.bola_check_enabled:
        return True, None
    # Admins are authorized via BFLA (required_role), not object-id equality.
    if (user_role or "").lower() == "admin":
        return True, None
    if (getattr(route, "required_role", None) or "").lower() == "admin":
        return True, None
    # Public / unauthenticated pages (e.g. public user profile) skip ownership.
    if getattr(route, "auth_required", True) is False:
        return True, None

    obj_ids = _extract_object_ids(route, path_params, query_params, body_json)
    if not obj_ids:
        return True, None

    claim_name = getattr(route, "bola_owner_claim", None) or "sub"
    claims = decoded_jwt or {}
    owner_claim_val = str(claims.get(claim_name) or user_sub or "")
    normalized_claim = _normalize_subject(owner_claim_val)
    mode = resolve_bola_mode(route)

    for obj_id in obj_ids:
        normalized_obj = _normalize_subject(obj_id)

        # equals_sub only: object id IS the user (e.g. /users/{id}).
        # Never apply this to resource IDs (bookingId/orderId) — that caused
        # parking-lot false ownership when booking 101 matched user-101.
        if mode == BOLA_MODE_EQUALS_SUB:
            if normalized_claim and normalized_claim == normalized_obj:
                continue

        order = VULNSHOP_ORDERS.get(obj_id)
        if order and user_sub and order.get("owner_sub") == user_sub:
            continue

        learned = _lookup_learned_owner(route.upstream_id or 1, route.path_pattern, obj_id)
        if learned and learned == user_sub:
            continue

        if mode == BOLA_MODE_LEARNED_OWNER:
            if learned and learned != user_sub:
                return (
                    False,
                    f"BOLA Violation (OWASP API1): Principal '{user_sub or 'anonymous'}' attempted unauthorized access to object ID '{obj_id}' on '{route.path_pattern}'",
                )
            if order and user_sub and order.get("owner_sub") != user_sub:
                return (
                    False,
                    f"BOLA Violation (OWASP API1): Principal '{user_sub or 'anonymous'}' attempted unauthorized access to object ID '{obj_id}' on '{route.path_pattern}'",
                )
            # Unknown owner: fail-open so the first legitimate GET can seed ownership.
            continue

        return (
            False,
            f"BOLA Violation (OWASP API1): Principal '{user_sub or 'anonymous'}' attempted unauthorized access to object ID '{obj_id}' on '{route.path_pattern}'",
        )

    return True, None


def reset_bola_enumeration(client_key: str) -> None:
    """Clear distinct-ID tracking for a client (used by Attack Simulator for deterministic runs)."""
    _BOLA_ENUM_TRACKER.pop(client_key, None)


def track_bola_enumeration(
    client_key: str,
    obj_id: str,
    max_distinct: int = 5,
    window_sec: float = 60.0,
) -> Tuple[bool, int]:
    """
    Tracks distinct object IDs per client. Returns (exceeded, distinct_count).

    Exceeded when distinct count is **strictly greater** than ``max_distinct``
    (e.g. cap=5 → the 6th new ID trips the block). The returned count is the
    running total of unique IDs in the window — not the HTTP request number.
    """
    now = time.time()
    bucket = _BOLA_ENUM_TRACKER.get(client_key, {})
    bucket = {k: t for k, t in bucket.items() if now - t <= window_sec}
    bucket[str(obj_id)] = now
    _BOLA_ENUM_TRACKER[client_key] = bucket
    count = len(bucket)
    return count > max_distinct, count
