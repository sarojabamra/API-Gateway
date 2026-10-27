import json
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select
import yaml

from app.db import get_session
from app.models import Policy, Route, Upstream, User
from app.schemas import OpenAPIImportRequest, RouteCreateRequest
from app.api.v1.deps import require_roles

router = APIRouter(prefix="/inventory", tags=["Protected APIs, Route Registry & Shadow APIs"])


@router.get("")
def get_inventory(session: Session = Depends(get_session)):
    upstreams = session.exec(select(Upstream)).all()
    all_routes = session.exec(select(Route).order_by(Route.id)).all()

    registered_routes = [r for r in all_routes if r.registered]
    shadow_routes = [r for r in all_routes if not r.registered]

    return {
        "upstreams": [
            {
                "id": u.id,
                "name": u.name,
                "slug": u.slug,
                "base_url": u.base_url,
                "auth_mode": u.auth_mode,
                "enabled": u.enabled,
                "created_at": u.created_at.isoformat(),
            }
            for u in upstreams
        ],
        "registered_routes": [
            {
                "id": r.id,
                "upstream_id": r.upstream_id,
                "method": r.method,
                "path_pattern": r.path_pattern,
                "description": r.description,
                "auth_required": r.auth_required,
                "required_role": r.required_role,
                "required_scopes": json.loads(r.required_scopes_json or "[]"),
                "rate_limit_rpm": r.rate_limit_rpm,
                "burst_capacity": r.burst_capacity,
                "is_sensitive_flow": r.is_sensitive_flow,
                "bola_check_enabled": r.bola_check_enabled,
                "response_redact_fields": json.loads(r.response_redact_fields_json or "[]"),
                "hit_count": r.hit_count,
                "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
            }
            for r in registered_routes
        ],
        "shadow_routes": [
            {
                "id": r.id,
                "upstream_id": r.upstream_id,
                "method": r.method,
                "path_pattern": r.path_pattern,
                "description": r.description,
                "hit_count": r.hit_count,
                "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
            }
            for r in shadow_routes
        ],
    }


class UpstreamCreateInput(BaseModel):
    name: str
    slug: str
    base_url: str
    auth_mode: str = "jwt"


@router.post("/upstreams")
def create_upstream(
    payload: UpstreamCreateInput,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "developer"])),
):
    clean_slug = payload.slug.strip().lower().replace(" ", "-")
    existing = session.exec(select(Upstream).where(Upstream.slug == clean_slug)).first()
    if existing:
        existing.name = payload.name
        existing.base_url = payload.base_url.rstrip("/")
        existing.auth_mode = payload.auth_mode
        session.add(existing)
        session.commit()
        session.refresh(existing)
        return existing

    up = Upstream(
        name=payload.name,
        slug=clean_slug,
        base_url=payload.base_url.rstrip("/"),
        auth_mode=payload.auth_mode,
        enabled=False,
    )
    session.add(up)
    session.commit()
    session.refresh(up)
    return up


@router.post("/upstreams/{upstream_id}/activate")
def activate_default_upstream(
    upstream_id: int,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "developer"])),
):
    """Sets the chosen API project as the default active upstream for /gw/* requests."""
    target = session.get(Upstream, upstream_id)
    if not target:
        raise HTTPException(status_code=404, detail="Upstream API not found")
    for u in session.exec(select(Upstream)).all():
        u.enabled = (u.id == upstream_id)
        session.add(u)
    session.commit()
    return {"status": "activated", "id": target.id, "name": target.name, "base_url": target.base_url}


@router.delete("/upstreams/{upstream_id}")
def delete_upstream(
    upstream_id: int,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "developer"])),
):
    if upstream_id == 1:
        raise HTTPException(status_code=400, detail="Cannot delete the built-in VulnShop demo API")
    target = session.get(Upstream, upstream_id)
    if not target:
        raise HTTPException(status_code=404, detail="Upstream API not found")
    was_enabled = target.enabled
    session.delete(target)
    if was_enabled:
        default_up = session.get(Upstream, 1)
        if default_up:
            default_up.enabled = True
            session.add(default_up)
    session.commit()
    return {"status": "deleted", "id": upstream_id}


@router.post("/routes")
def create_route(
    payload: RouteCreateRequest,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "developer"])),
):
    route = Route(
        upstream_id=payload.upstream_id,
        method=payload.method.upper(),
        path_pattern="/" + payload.path_pattern.lstrip("/"),
        description=payload.description,
        auth_required=payload.auth_required,
        required_role=payload.required_role,
        required_scopes_json=json.dumps(payload.required_scopes),
        rate_limit_rpm=payload.rate_limit_rpm,
        burst_capacity=payload.burst_capacity,
        is_sensitive_flow=payload.is_sensitive_flow,
        bola_check_enabled=payload.bola_check_enabled,
        response_redact_fields_json=json.dumps(payload.response_redact_fields),
        registered=True,
    )
    session.add(route)
    session.commit()
    session.refresh(route)
    return route


@router.post("/shadow/{route_id}/register")
def promote_shadow_route(
    route_id: int,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "developer"])),
):
    """One-click promotion of a discovered Shadow API (OWASP API9) into the official route inventory."""
    route = session.get(Route, route_id)
    if not route:
        raise HTTPException(status_code=404, detail="Shadow route not found")
    route.registered = True
    route.auth_required = True
    route.required_role = "admin" if "internal" in route.path_pattern or "admin" in route.path_pattern else "user"
    route.description = "Promoted from Shadow API discovery to official protected route"
    session.add(route)
    session.commit()
    return {"status": "registered", "id": route.id, "path_pattern": route.path_pattern}


@router.post("/shadow/{route_id}/block")
def block_shadow_route_permanently(
    route_id: int,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "analyst", "developer"])),
):
    """Ensures the Shadow API policy is in strict 'enforce' mode and marks the shadow route for hard rejection."""
    route = session.get(Route, route_id)
    if not route:
        raise HTTPException(status_code=404, detail="Shadow route not found")
    pol = session.exec(select(Policy).where(Policy.owasp_id == "API9")).first()
    if pol:
        pol.enabled = True
        pol.mode = "enforce"
        session.add(pol)
    route.description = f"PERMANENTLY BLOCKED Shadow Endpoint ({route.path_pattern})"
    session.add(route)
    session.commit()
    return {"status": "blocked", "id": route.id, "path_pattern": route.path_pattern}


@router.post("/import-openapi")
def import_openapi_spec(
    payload: OpenAPIImportRequest,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "developer"])),
):
    """
    Parses an OpenAPI 3.0 JSON or YAML specification and auto-registers routes
    with authentication, role requirements, and schema metadata.
    """
    raw = payload.spec_content.strip()
    try:
        if raw.startswith("{"):
            spec: Dict[str, Any] = json.loads(raw)
        else:
            spec = yaml.safe_load(raw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to parse OpenAPI JSON/YAML: {exc}")

    if not isinstance(spec, dict) or "paths" not in spec:
        raise HTTPException(status_code=400, detail="Invalid OpenAPI specification: missing 'paths' object")

    paths_obj: Dict[str, Any] = spec.get("paths", {})
    imported: List[Dict[str, Any]] = []

    for path_pattern, methods_map in paths_obj.items():
        if not isinstance(methods_map, dict):
            continue
        for method_key, op_spec in methods_map.items():
            m_upper = method_key.upper()
            if m_upper not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            if not isinstance(op_spec, dict):
                op_spec = {}

            summary = op_spec.get("summary") or op_spec.get("description") or f"Imported from OpenAPI ({m_upper} {path_pattern})"
            is_admin = "admin" in path_pattern.lower() or "admin" in str(op_spec.get("tags", "")).lower()
            has_id_param = "{" in path_pattern
            is_sensitive = any(k in path_pattern.lower() for k in ("coupon", "checkout", "order", "register", "transfer"))

            existing = session.exec(
                select(Route).where(
                    Route.upstream_id == payload.upstream_id,
                    Route.method == m_upper,
                    Route.path_pattern == path_pattern,
                )
            ).first()

            if existing:
                existing.registered = True
                existing.description = summary
                session.add(existing)
                imported.append({"method": m_upper, "path_pattern": path_pattern, "action": "updated"})
            else:
                new_route = Route(
                    upstream_id=payload.upstream_id,
                    method=m_upper,
                    path_pattern=path_pattern,
                    description=summary,
                    auth_required=not any(p in path_pattern for p in ("/auth/login", "/auth/register")),
                    required_role="admin" if is_admin else None,
                    rate_limit_rpm=20 if is_sensitive else 60,
                    burst_capacity=5 if is_sensitive else 15,
                    is_sensitive_flow=is_sensitive,
                    bola_check_enabled=has_id_param,
                    registered=True,
                )
                session.add(new_route)
                imported.append({"method": m_upper, "path_pattern": path_pattern, "action": "created"})

    session.commit()
    return {"status": "imported", "imported_count": len(imported), "routes": imported}
