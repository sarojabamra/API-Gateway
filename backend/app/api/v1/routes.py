import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import httpx
from sqlmodel import Session, select
import yaml

from app.db import get_session
from app.models import Policy, Route, Upstream, User, to_ist_iso
from app.schemas import OpenAPIImportRequest, RouteCreateRequest
from app.api.v1.deps import require_roles
from app.gateway.policy_engine import infer_route_security

router = APIRouter(prefix="/inventory", tags=["Protected APIs, Route Registry & Shadow APIs"])


def _upsert_openapi_routes(
    session: Session,
    upstream_id: int,
    spec: Dict[str, Any],
) -> List[Dict[str, Any]]:
    paths_obj: Dict[str, Any] = spec.get("paths") or {}
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

            summary = (
                op_spec.get("summary")
                or op_spec.get("description")
                or f"{m_upper} {path_pattern}"
            )
            meta = infer_route_security(path_pattern, op_spec, spec)
            existing = session.exec(
                select(Route).where(
                    Route.upstream_id == upstream_id,
                    Route.method == m_upper,
                    Route.path_pattern == path_pattern,
                )
            ).first()

            if existing:
                existing.registered = True
                existing.description = summary
                existing.auth_required = meta["auth_required"]
                existing.required_role = meta["required_role"] or existing.required_role
                existing.bola_check_enabled = meta["bola_check_enabled"]
                existing.is_sensitive_flow = meta["is_sensitive_flow"]
                session.add(existing)
                imported.append({"method": m_upper, "path_pattern": path_pattern, "action": "updated"})
            else:
                session.add(
                    Route(
                        upstream_id=upstream_id,
                        method=m_upper,
                        path_pattern=path_pattern,
                        description=summary,
                        registered=True,
                        **meta,
                    )
                )
                imported.append({"method": m_upper, "path_pattern": path_pattern, "action": "created"})

    session.commit()
    return imported


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
                "created_at": to_ist_iso(u.created_at),
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
                "last_seen_at": to_ist_iso(r.last_seen_at),
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
                "last_seen_at": to_ist_iso(r.last_seen_at),
            }
            for r in shadow_routes
        ],
    }


class UpstreamCreateInput(BaseModel):
    name: str
    slug: str
    base_url: str
    auth_mode: str = "jwt"


class UpstreamUpdateInput(BaseModel):
    name: Optional[str] = None
    slug: Optional[str] = None
    base_url: Optional[str] = None
    auth_mode: Optional[str] = None


@router.put("/upstreams/{upstream_id}")
def update_upstream(
    upstream_id: int,
    payload: UpstreamUpdateInput,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "developer"])),
):
    target = session.get(Upstream, upstream_id)
    if not target:
        raise HTTPException(status_code=404, detail="Upstream API not found")

    if payload.slug is not None:
        clean_slug = payload.slug.strip().lower().replace(" ", "-")
        if not clean_slug:
            raise HTTPException(status_code=400, detail="Slug cannot be empty")
        # Check if slug is used by another upstream
        existing = session.exec(
            select(Upstream).where(Upstream.slug == clean_slug, Upstream.id != upstream_id)
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail=f"Slug '{clean_slug}' is already taken by another project")
        target.slug = clean_slug

    if payload.name is not None:
        clean_name = payload.name.strip()
        if not clean_name:
            raise HTTPException(status_code=400, detail="Name cannot be empty")
        target.name = clean_name

    if payload.base_url is not None:
        clean_url = payload.base_url.strip().rstrip("/")
        if not clean_url:
            raise HTTPException(status_code=400, detail="Backend URL cannot be empty")
        if not clean_url.startswith(("http://", "https://")):
            clean_url = f"http://{clean_url}"
        target.base_url = clean_url

    if payload.auth_mode is not None:
        target.auth_mode = payload.auth_mode

    session.add(target)
    session.commit()
    session.refresh(target)
    return target


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
    raw = (payload.spec_content or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Please paste your OpenAPI JSON or YAML content")
    try:
        spec: Dict[str, Any] = json.loads(raw) if raw.startswith("{") else yaml.safe_load(raw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to parse OpenAPI JSON/YAML: {exc}")

    if not isinstance(spec, dict) or "paths" not in spec:
        raise HTTPException(status_code=400, detail="Invalid OpenAPI specification: missing 'paths' object")

    imported = _upsert_openapi_routes(session, payload.upstream_id, spec)
    return {"status": "imported", "imported_count": len(imported), "routes": imported}


class SwaggerSyncInput(BaseModel):
    base_url: str
    name: Optional[str] = None
    slug: Optional[str] = None
    make_default: bool = True


def _derive_slug_and_name(url: str, custom_name: Optional[str], custom_slug: Optional[str]):
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "api").replace(".", "-")
    port = f"-{parsed.port}" if parsed.port else ""
    auto_slug = (custom_slug or f"{host}{port}").strip().lower().replace(" ", "-")
    auto_name = (custom_name or f"API ({parsed.netloc or url})").strip()
    return auto_name, auto_slug


async def _discover_api_backend_from_frontend(frontend_url: str, client: httpx.AsyncClient) -> Optional[str]:
    """
    If a user enters a Next.js / React frontend URL whose /openapi.json returns a 404 HTML page,
    inspects the frontend's HTML/JS bundles or common subdomains (backend.<domain>, api.<domain>)
    to automatically discover the actual FastAPI / REST backend server URL.
    """
    try:
        r = await client.get(frontend_url, timeout=8.0)
        html = r.text or ""
        script_urls = re.findall(r'src=["\'](/_next/static/[^"\']+\.js|/assets/[^"\']+\.js)["\']', html)
        candidate_urls: List[str] = []

        for s_path in script_urls[:8]:
            js_r = await client.get(frontend_url.rstrip("/") + s_path, timeout=8.0)
            for match in re.findall(r'https?://(?:backend|api)[a-zA-Z0-9._-]+(?::\d+)?', js_r.text or ""):
                if match not in candidate_urls:
                    candidate_urls.append(match.rstrip("/"))

        parsed = urlparse(frontend_url)
        host = parsed.hostname or ""
        parts = host.split(".")
        if len(parts) >= 2:
            root_domain = ".".join(parts[-2:])
            for prefix in ("backend", "api"):
                cand = f"{parsed.scheme or 'https'}://{prefix}.{root_domain}"
                if cand not in candidate_urls and cand != frontend_url:
                    candidate_urls.append(cand)

        for cand in candidate_urls:
            try:
                spec_r = await client.get(f"{cand}/openapi.json", timeout=6.0)
                if spec_r.status_code == 200 and "paths" in (spec_r.text or ""):
                    return cand
            except Exception:
                continue
    except Exception:
        pass
    return None


@router.post("/sync-swagger-url")
async def sync_swagger_from_url(
    payload: SwaggerSyncInput,
    session: Session = Depends(get_session),
    _user: User = Depends(require_roles(["admin", "developer"])),
):
    """
    Connects any local or deployed backend URL (on any port or domain),
    fetches its OpenAPI/Swagger spec if available, registers its endpoints,
    and activates it so /gw/* and /gw/docs proxy through SentinelGW.
    """
    raw_url = payload.base_url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="Please enter a backend URL (e.g. http://127.0.0.1:8001)")

    clean_url = raw_url.rstrip("/")
    if not clean_url.startswith(("http://", "https://")):
        clean_url = f"http://{clean_url}"
    for suffix in ("/docs", "/openapi.json"):
        if clean_url.endswith(suffix):
            clean_url = clean_url[: -len(suffix)].rstrip("/")

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as probe_client:
            probe_resp = await probe_client.get(f"{clean_url}/openapi.json")
            if probe_resp.status_code != 200 or "paths" not in (probe_resp.text or ""):
                discovered = await _discover_api_backend_from_frontend(clean_url, probe_client)
                if discovered:
                    clean_url = discovered
    except Exception:
        pass

    derived_name, clean_slug = _derive_slug_and_name(clean_url, payload.name, payload.slug)

    up = session.exec(
        select(Upstream).where((Upstream.base_url == clean_url) | (Upstream.slug == clean_slug))
    ).first()
    if not up:
        up = Upstream(
            name=derived_name,
            slug=clean_slug,
            base_url=clean_url,
            auth_mode="none",
            enabled=payload.make_default,
        )
    else:
        up.name = derived_name
        up.slug = clean_slug
        up.base_url = clean_url
    session.add(up)
    session.commit()
    session.refresh(up)

    if payload.make_default:
        for other in session.exec(select(Upstream)).all():
            other.enabled = (other.id == up.id)
            session.add(other)
        session.commit()

    imported_routes: List[Dict[str, Any]] = []
    openapi_reachable = False
    openapi_error = None

    try:
        async with httpx.AsyncClient(timeout=25.0, follow_redirects=True) as client:
            resp = await client.get(f"{clean_url}/openapi.json")
            if resp.status_code == 200:
                openapi_reachable = True
                spec = resp.json()
                title = (spec.get("info") or {}).get("title")
                if title and not payload.name:
                    up.name = f"{title} ({clean_url})"
                    session.add(up)
                imported_routes = _upsert_openapi_routes(session, up.id, spec)
            else:
                openapi_error = f"Target returned HTTP {resp.status_code} on /openapi.json"
    except Exception as exc:
        openapi_error = str(exc)

    return {
        "status": "connected",
        "base_url": up.base_url,
        "upstream": {
            "id": up.id,
            "name": up.name,
            "slug": up.slug,
            "base_url": up.base_url,
            "enabled": up.enabled,
        },
        "openapi_reachable": openapi_reachable,
        "imported_count": len(imported_routes),
        "openapi_error": openapi_error,
        "gateway_swagger_url": "/gw/docs" if up.enabled else f"/gw/{up.slug}/docs",
    }

