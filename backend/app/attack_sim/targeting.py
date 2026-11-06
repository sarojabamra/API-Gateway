"""
Project-aware route selection for the Attack Simulator.

Each OWASP scenario declares what kind of endpoint it needs. We score inventory
routes from route metadata (auth, BOLA mode, sensitive, admin, path shape) and
only fall back to weak keyword matches when nothing better exists. When a
project simply has no suitable route, the scenario is marked not applicable
instead of hammering a random wrong endpoint.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from app.gateway.policy_engine import (
    BOLA_MODE_EQUALS_SUB,
    BOLA_MODE_LEARNED_OWNER,
    is_public_auth_path,
    is_resource_like_param,
    is_user_like_param,
    resolve_bola_mode,
)
from app.models import Route


@dataclass
class SelectedRoute:
    """One inventory route chosen for a scenario role."""

    role: str
    route: Optional[Route]
    score: int = 0
    reason: str = ""
    required: bool = True


@dataclass
class ScenarioTargetPlan:
    scenario_id: str
    applicable: bool
    skip_reason: Optional[str] = None
    selections: Dict[str, SelectedRoute] = field(default_factory=dict)

    def route(self, role: str) -> Optional[Route]:
        sel = self.selections.get(role)
        return sel.route if sel else None

    def reason(self, role: str) -> str:
        sel = self.selections.get(role)
        return sel.reason if sel else ""


def _path_params(pattern: str) -> List[str]:
    return re.findall(r"\{([^}]+)\}", pattern or "")


def _text(route: Route) -> str:
    return f"{route.path_pattern} {route.description or ''}".lower()


def _norm_path(route: Route) -> str:
    return "/" + (route.path_pattern or "").strip("/").lower()


def _is_admin_route(route: Route) -> bool:
    if (route.required_role or "").lower() == "admin":
        return True
    path = _norm_path(route)
    return "/admin" in path or path.startswith("/api/admin")


def _is_login_route(route: Route) -> bool:
    if route.method.upper() != "POST":
        return False
    path = _norm_path(route)
    text = _text(route)
    if any(bad in path for bad in ("register", "signup", "logout", "google", "oauth/callback", "refresh")):
        return False
    login_hints = (
        path.endswith("/login"),
        path.endswith("/auth/login"),
        path.endswith("/jwt/login"),
        path.endswith("/token"),
        "/auth/jwt/login" in path,
        "login" in text and "auth" in text,
    )
    return any(login_hints) or (is_public_auth_path(path) and "login" in path)


def _is_register_route(route: Route) -> bool:
    if route.method.upper() not in ("POST", "PUT"):
        return False
    path = _norm_path(route)
    return any(k in path for k in ("/register", "/signup", "/sign-up"))


def _is_me_profile_route(route: Route) -> bool:
    if route.method.upper() != "GET":
        return False
    path = _norm_path(route)
    return path.endswith("/me") or path.endswith("/users/me") or path.endswith("/profile")


def _is_collection_get(route: Route) -> bool:
    if route.method.upper() != "GET":
        return False
    if "{" in (route.path_pattern or ""):
        return False
    path = _norm_path(route)
    if path in ("/", "/health", "/api/health"):
        return False
    if is_public_auth_path(path):
        return False
    return True


def _best(
    routes: Sequence[Route],
    scorer,
    *,
    min_score: int = 1,
) -> Tuple[Optional[Route], int, str]:
    best_route: Optional[Route] = None
    best_score = -10_000
    best_reason = ""
    for route in routes:
        score, reason = scorer(route)
        if score > best_score:
            best_route, best_score, best_reason = route, score, reason
    if best_route is None or best_score < min_score:
        return None, best_score, best_reason or "no matching route"
    return best_route, best_score, best_reason


def _score_bola_cross_user(route: Route) -> Tuple[int, str]:
    """User 2 calling a route whose path contains a different user id."""
    if not route.bola_check_enabled or "{" not in (route.path_pattern or ""):
        return -1, "BOLA not enabled"
    if _is_admin_route(route):
        return -1, "admin route (BFLA, not BOLA)"
    if route.auth_required is False:
        return -1, "public route"
    params = _path_params(route.path_pattern)
    if not any(is_user_like_param(name, route.path_pattern) for name in params):
        return -1, "no user id on this route"
    if route.method.upper() not in ("GET", "PUT", "PATCH", "DELETE", "POST"):
        return -1, "unsupported method"
    score = 70
    if route.method.upper() == "GET":
        score += 25
    if resolve_bola_mode(route) == BOLA_MODE_EQUALS_SUB:
        score += 15
    return score, "user id on route"


def _score_bola_enum(route: Route) -> Tuple[int, str]:
    """GET resource IDs 1–6. User-id routes belong to the cross-user scenario."""
    if route.method.upper() != "GET":
        return -1, "enumeration check uses GET"
    if not route.bola_check_enabled or "{" not in (route.path_pattern or ""):
        return -1, "BOLA not enabled"
    if _is_admin_route(route):
        return -1, "admin route"
    if route.auth_required is False:
        return -1, "public route"
    params = _path_params(route.path_pattern)
    if any(is_user_like_param(name, route.path_pattern) for name in params):
        return -1, "user-id route is the cross-user check"
    if not any(is_resource_like_param(name, route.path_pattern) for name in params):
        return -1, "no resource id"
    if resolve_bola_mode(route) != BOLA_MODE_LEARNED_OWNER:
        return -1, "enumeration cap runs on learned_owner resource routes"
    return 80, "resource id for enumeration"


def _score_login(route: Route) -> Tuple[int, str]:
    if not _is_login_route(route):
        return -1, "not a login route"
    path = _norm_path(route)
    score = 50
    if path.endswith("/login") or path.endswith("/jwt/login"):
        score += 40
    if "token" in path and "login" not in path:
        score += 10
    if route.auth_required is False or is_public_auth_path(path):
        score += 15
    if route.is_sensitive_flow:
        score += 5
    return score, f"login endpoint {route.method} {route.path_pattern}"


def _score_jwt_victim(route: Route) -> Tuple[int, str]:
    """Protected route used to prove JWT alg=none / tampering is rejected."""
    if _is_admin_route(route):
        return -1, "admin (use BFLA scenario)"
    if route.auth_required is False:
        return -1, "public"
    if is_public_auth_path(_norm_path(route)):
        return -1, "auth bootstrap"
    if route.method.upper() != "GET":
        return 5, "non-GET protected"
    score = 40
    if "{" not in (route.path_pattern or ""):
        score += 20  # simpler victim path
    if _is_me_profile_route(route):
        score += 25
    if route.bola_check_enabled:
        score += 5
    return score, f"JWT-protected {route.method} {route.path_pattern}"


def _score_profile_read(route: Route) -> Tuple[int, str]:
    if route.method.upper() != "GET":
        return -1, "not GET"
    if _is_admin_route(route):
        return -1, "admin"
    path = _norm_path(route)
    score = 0
    if _is_me_profile_route(route):
        score = 90
        return score, "self profile /me"
    if route.bola_check_enabled and resolve_bola_mode(route) == BOLA_MODE_EQUALS_SUB:
        score = 70
        return score, "user object GET"
    if any(k in path for k in ("/users/", "/profile", "/account", "/customer")):
        score = 40
    if score <= 0:
        return -1, "not a profile read"
    return score, f"profile-like {route.path_pattern}"


def _score_mass_assign_write(route: Route) -> Tuple[int, str]:
    if route.method.upper() not in ("POST", "PUT", "PATCH"):
        return -1, "not a write"
    if _is_admin_route(route):
        return -1, "admin"
    if _is_login_route(route):
        return -1, "login"
    path = _norm_path(route)
    score = 10
    if _is_register_route(route):
        score += 80
        return score, "registration (mass assignment)"
    if route.request_schema_json:
        score += 25
    if any(k in path for k in ("/users", "/profile", "/account", "/register")):
        score += 20
    if "{" in (route.path_pattern or ""):
        score -= 10  # prefer create over update-by-id
    if score < 20:
        return -1, "weak write candidate"
    return score, f"write {route.method} {route.path_pattern}"


def _score_pagination(route: Route) -> Tuple[int, str]:
    if not _is_collection_get(route):
        return -1, "not a collection GET"
    path = _norm_path(route)
    score = 30
    for hint, boost in (
        ("product", 40),
        ("item", 30),
        ("booking", 25),
        ("order", 25),
        ("post", 20),
        ("board", 15),
        ("list", 15),
        ("search", 10),
        ("inventory", 20),
        ("catalog", 20),
        ("history", 15),
        ("availability", 10),
    ):
        if hint in path:
            score += boost
            break
    if route.auth_required is False:
        score += 5
    return score, f"collection GET {route.path_pattern}"


def _score_sensitive_flow(route: Route) -> Tuple[int, str]:
    if _is_login_route(route) or _is_register_route(route):
        return -1, "auth bootstrap (API2, not API6)"
    if _is_admin_route(route):
        return -1, "admin"
    path = _norm_path(route)
    score = 0
    if route.is_sensitive_flow:
        score += 50
    for hint, boost in (
        ("coupon", 40),
        ("redeem", 40),
        ("checkout", 35),
        ("payment", 35),
        ("transfer", 30),
        ("booking", 25),
        ("lock", 20),
        ("unlock", 15),
        ("order", 20),
    ):
        if hint in path or hint in _text(route):
            score += boost
    if route.method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        score += 10
    else:
        score -= 15
    if score < 40:
        return -1, "not a sensitive business flow"
    return score, f"sensitive {route.method} {route.path_pattern}"


def _score_admin(route: Route) -> Tuple[int, str]:
    if not _is_admin_route(route):
        return -1, "not admin"
    score = 50
    if route.method.upper() == "GET":
        score += 20
    if "{" not in (route.path_pattern or ""):
        score += 15  # list/dump endpoints are clearer BFLA demos
    if "user" in _text(route):
        score += 10
    return score, f"admin {route.method} {route.path_pattern}"


def _score_ssrf(route: Route) -> Tuple[int, str]:
    path = _norm_path(route)
    text = _text(route)
    # Simulator always GETs with ?url= — only select GET victims
    if route.method.upper() != "GET":
        return -1, "not GET"
    if _is_login_route(route) or _is_register_route(route) or is_public_auth_path(path):
        return -1, "auth bootstrap"
    score = 0
    if path.endswith("/fetch") or "/fetch" in path:
        score += 100
    if "preview-url" in path or path.endswith("/url"):
        score += 50
    if any(k in text for k in ("ssrf", "proxy", "webhook", "callback", "fetch url")):
        score += 40
    score += 5
    if score < 40:
        # Any GET can carry ?url= through the gateway request inspector
        if _is_me_profile_route(route) or _is_admin_route(route):
            return -1, "profile/admin are poor SSRF carriers"
        if "/auth/" in path or "/users/" in path:
            # Prefer non-identity resources when available; still allow as last resort
            return 12, f"fallback GET carrier {route.path_pattern}"
        return 15, f"fallback GET carrier {route.path_pattern}"
    return score, f"SSRF target {route.path_pattern}"


def _score_search(route: Route) -> Tuple[int, str]:
    path = _norm_path(route)
    text = _text(route)
    score = 0
    if route.method.upper() != "GET":
        return -1, "not GET"
    if _is_admin_route(route):
        return -1, "admin routes are BFLA targets, not SQLi"
    if _is_me_profile_route(route) or is_public_auth_path(path) or "/auth/" in path:
        return -1, "auth/profile routes are not search targets"
    if "search" in path or path.endswith("/q"):
        score += 80
    if any(k in text for k in ("search", "query", "filter", "find")):
        score += 30
    if _is_collection_get(route):
        score += 25  # can take ?q=
    if score < 20:
        return -1, "no search-like route"
    return score, f"search/query {route.path_pattern}"


def _score_supplier(route: Route) -> Tuple[int, str]:
    path = _norm_path(route)
    text = _text(route)
    score = 0
    if route.method.upper() != "GET":
        return -1, "not GET"
    if any(k in path for k in ("supplier", "catalog", "third-party", "thirdparty", "webhook", "integration")):
        score += 80
    if any(k in text for k in ("supplier", "catalog", "webhook", "third")):
        score += 30
    if score < 50:
        return -1, "no third-party/catalog route"
    return score, f"third-party {route.path_pattern}"


# scenario_id -> (role, scorer, min_score, required)
_SCENARIO_SELECTORS: Dict[str, List[Tuple[str, Any, int, bool]]] = {
    "bola_cross_user": [("user_route", _score_bola_cross_user, 10, True)],
    "bola_enum": [("object_route", _score_bola_enum, 10, True)],
    "brute_force": [("login", _score_login, 40, True)],
    "jwt_tamper": [("jwt_victim", _score_jwt_victim, 20, True)],
    "data_exposure": [
        ("read", _score_profile_read, 20, True),
        ("write", _score_mass_assign_write, 20, True),
    ],
    "rate_flood": [("list", _score_pagination, 20, True)],
    "coupon_scalp": [("sensitive", _score_sensitive_flow, 40, True)],
    "bfla_admin": [("admin", _score_admin, 40, True)],
    "ssrf_metadata": [("fetch", _score_ssrf, 10, True)],
    "sqli_inject": [("search", _score_search, 15, True)],
    "shadow_scan": [],  # synthetic paths; always applicable
    "unsafe_api_consume": [("supplier", _score_supplier, 50, True)],
}

ROLE_LABELS: Dict[str, str] = {
    "user_route": "User-id route",
    "object_route": "Resource object route",
    "login": "Login route",
    "jwt_victim": "JWT-protected route",
    "read": "Profile / data-read route",
    "write": "Mass-assignment write route",
    "list": "Collection / list route",
    "sensitive": "Sensitive business-flow route",
    "admin": "Admin / privileged route",
    "fetch": "SSRF carrier route",
    "search": "Search / query route",
    "supplier": "Third-party / catalog route",
    "shadow": "Shadow paths (synthetic)",
}

# Convenience: single route_id in the API maps to this role
PRIMARY_ROLE: Dict[str, str] = {
    "bola_cross_user": "user_route",
    "bola_enum": "object_route",
    "brute_force": "login",
    "jwt_tamper": "jwt_victim",
    "data_exposure": "read",
    "rate_flood": "list",
    "coupon_scalp": "sensitive",
    "bfla_admin": "admin",
    "ssrf_metadata": "fetch",
    "sqli_inject": "search",
    "unsafe_api_consume": "supplier",
}


def plan_scenario_targets(
    scenario_id: str,
    routes: Sequence[Route],
    overrides: Optional[Dict[str, int]] = None,
) -> ScenarioTargetPlan:
    """
    Pick the best inventory routes for a scenario against one project's routes.

    ``overrides`` maps role name → route id for manual selection. Manual picks
    always win over auto-scoring (as long as the route belongs to the project).
    """
    overrides = {k: int(v) for k, v in (overrides or {}).items() if v is not None}

    if scenario_id == "shadow_scan":
        return ScenarioTargetPlan(
            scenario_id=scenario_id,
            applicable=True,
            skip_reason=None,
            selections={
                "shadow": SelectedRoute(
                    role="shadow",
                    route=None,
                    score=100,
                    reason="synthetic undocumented paths (API9)",
                    required=True,
                )
            },
        )

    selectors = _SCENARIO_SELECTORS.get(scenario_id)
    if selectors is None:
        return ScenarioTargetPlan(
            scenario_id=scenario_id,
            applicable=False,
            skip_reason=f"Unknown scenario '{scenario_id}'",
        )

    registered = [r for r in routes if getattr(r, "registered", True)]
    by_id = {int(r.id): r for r in registered if r.id is not None}
    selections: Dict[str, SelectedRoute] = {}
    missing_required: List[str] = []

    for role, scorer, min_score, required in selectors:
        forced_id = overrides.get(role)
        if forced_id is not None:
            forced = by_id.get(int(forced_id))
            if forced is None:
                missing_required.append(f"{role} (manual route_id={forced_id} not in this project)")
                selections[role] = SelectedRoute(
                    role=role,
                    route=None,
                    score=-1,
                    reason=f"manual route_id={forced_id} not found",
                    required=required,
                )
                continue
            score, reason = scorer(forced)
            selections[role] = SelectedRoute(
                role=role,
                route=forced,
                score=max(score, 1),
                reason=f"manual selection · {forced.method} {forced.path_pattern}"
                + (f" (auto-score hint: {reason})" if reason else ""),
                required=required,
            )
            continue

        route, score, reason = _best(registered, scorer, min_score=min_score)
        selections[role] = SelectedRoute(
            role=role,
            route=route,
            score=score,
            reason=reason,
            required=required,
        )
        if required and route is None:
            missing_required.append(f"{role} ({reason})")

    if missing_required:
        return ScenarioTargetPlan(
            scenario_id=scenario_id,
            applicable=False,
            skip_reason=(
                "No suitable route in this project for: "
                + "; ".join(missing_required)
                + ". Pick a route manually or import matching endpoints."
            ),
            selections=selections,
        )

    return ScenarioTargetPlan(
        scenario_id=scenario_id,
        applicable=True,
        selections=selections,
    )


def list_scenario_route_options(
    scenario_id: str,
    routes: Sequence[Route],
) -> List[Dict[str, Any]]:
    """
    Build UI-friendly candidate lists per selectable role for a scenario.
    Recommended (auto) route is marked; other scored + remaining routes included
    so operators can force a manual target.
    """
    if scenario_id == "shadow_scan":
        return []

    selectors = _SCENARIO_SELECTORS.get(scenario_id) or []
    registered = [r for r in routes if getattr(r, "registered", True)]
    plan = plan_scenario_targets(scenario_id, registered)
    out: List[Dict[str, Any]] = []

    for role, scorer, min_score, _required in selectors:
        scored: List[Tuple[Route, int, str]] = []
        for route in registered:
            score, reason = scorer(route)
            scored.append((route, score, reason))
        scored.sort(key=lambda t: t[1], reverse=True)

        recommended = plan.route(role)
        recommended_id = recommended.id if recommended else None

        candidates: List[Dict[str, Any]] = []
        seen: set = set()
        # Good matches first
        for route, score, reason in scored:
            if route.id is None or score < 1:
                continue
            seen.add(route.id)
            candidates.append(
                {
                    "id": route.id,
                    "method": route.method,
                    "path_pattern": route.path_pattern,
                    "score": score,
                    "reason": reason,
                    "recommended": route.id == recommended_id,
                    "fit": "good" if score >= min_score else "weak",
                }
            )
        # Remaining project routes as manual force options
        for route, score, reason in scored:
            if route.id is None or route.id in seen:
                continue
            seen.add(route.id)
            candidates.append(
                {
                    "id": route.id,
                    "method": route.method,
                    "path_pattern": route.path_pattern,
                    "score": score,
                    "reason": reason or "manual override",
                    "recommended": False,
                    "fit": "other",
                }
            )

        out.append(
            {
                "role": role,
                "label": ROLE_LABELS.get(role, role),
                "auto_route_id": recommended_id,
                "candidates": candidates,
            }
        )
    return out


def resolve_route_overrides(
    scenario_id: str,
    route_id: Optional[int] = None,
    route_overrides: Optional[Dict[str, int]] = None,
) -> Dict[str, int]:
    """Merge single route_id (primary role) with explicit role→id overrides."""
    merged: Dict[str, int] = {}
    if route_overrides:
        for role, rid in route_overrides.items():
            if rid is not None:
                merged[str(role)] = int(rid)
    if route_id is not None and scenario_id in PRIMARY_ROLE:
        primary = PRIMARY_ROLE[scenario_id]
        merged.setdefault(primary, int(route_id))
    return merged


def describe_plan(plan: ScenarioTargetPlan) -> List[str]:
    """Human-readable selection summary for UI / step labels."""
    lines: List[str] = []
    if not plan.applicable:
        lines.append(f"skipped: {plan.skip_reason}")
        return lines
    for role, sel in plan.selections.items():
        if sel.route is None:
            lines.append(f"{role}: synthetic ({sel.reason})")
        else:
            lines.append(
                f"{role}: {sel.route.method} {sel.route.path_pattern} "
                f"[score={sel.score}; {sel.reason}]"
            )
    return lines
