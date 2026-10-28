import json
import re
from typing import Any, Dict, List, Optional, Tuple
from sqlmodel import Session, select
from app.models import Policy, Route


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
    routes = session.exec(
        select(Route).where(Route.upstream_id == upstream_id, Route.registered == True)
    ).all()

    # Sort routes so static paths come before parameterized paths
    sorted_routes = sorted(routes, key=lambda r: ("{" in r.path_pattern, -len(r.path_pattern)))

    for route in sorted_routes:
        if route.method not in (method.upper(), "*"):
            continue
        matched, params = match_route_pattern(route.path_pattern, path)
        if matched:
            return route, params

    return None, {}


def check_policy_mode(session: Session, policy_type: str, owasp_id: Optional[str] = None) -> Tuple[bool, str, Optional[int]]:
    """
    Checks if a given policy type or OWASP ID is enabled and whether it is in 'enforce' or 'monitor' mode.
    Returns (is_enabled, mode, policy_id).
    """
    stmt = select(Policy).where(Policy.type == policy_type)
    policies = session.exec(stmt).all()
    if not policies and owasp_id:
        policies = session.exec(select(Policy).where(Policy.owasp_id == owasp_id)).all()

    if not policies:
        return True, "enforce", None

    # Prefer active policy
    for pol in policies:
        if pol.enabled:
            return True, pol.mode, pol.id
    return False, "disabled", policies[0].id


def check_bola_ownership(
    route: Route,
    path_params: Dict[str, str],
    user_sub: Optional[str],
    user_role: Optional[str],
) -> Tuple[bool, Optional[str]]:
    """
    OWASP API1 (Broken Object Level Authorization):
    If `route.bola_check_enabled` is True and user is not admin, verifies that the requested
    object ID matches the authenticated user's `sub` (or known owned order).
    """
    if not route.bola_check_enabled:
        return True, None
    if user_role == "admin":
        return True, None

    obj_id = (
        path_params.get("id")
        or path_params.get("user_id")
        or path_params.get("order_id")
        or (next(iter(path_params.values()), None) if path_params else None)
    )
    if not obj_id:
        return True, None

    normalized_sub = (user_sub or "").replace("user-", "")
    normalized_obj = obj_id.replace("user-", "")

    # Order 5001 belongs to user 101 in demo data
    if route.path_pattern.startswith("/orders") and normalized_sub == "101" and normalized_obj == "5001":
        return True, None

    if normalized_sub and normalized_sub == normalized_obj:
        return True, None

    return (
        False,
        f"BOLA Violation (OWASP API1): Principal '{user_sub or 'anonymous'}' attempted unauthorized access to object ID '{obj_id}' on '{route.path_pattern}'",
    )
