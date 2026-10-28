import json
import re
from datetime import datetime, timezone
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from fastapi import Request, Response
import httpx
from sqlmodel import Session, select

from app.config import settings
from app.db import engine
from app.models import BlocklistEntry, RequestLog, Route, Upstream
from app.gateway.auth import get_upstream_jwt_config, validate_jwt_checklist, verify_api_key
from app.gateway.ratelimit import rate_limiter
from app.gateway.inspector import inspect_request_payload
from app.gateway.policy_engine import check_bola_ownership, check_policy_mode, find_matching_route
from app.gateway.responses import harden_response


def _build_synthesized_openapi_spec(
    upstream: Optional[Upstream],
    routes: List[Route],
    gw_prefix: str,
) -> Dict[str, Any]:
    """
    Synthesizes a complete OpenAPI 3.0.3 specification from the registered routes
    in SentinelGW's database when a connected project does not natively serve /openapi.json.
    """
    proj_name = upstream.name if upstream else "Connected API Project"
    base_url = upstream.base_url if upstream else ""
    paths: Dict[str, Any] = {}

    for r in routes:
        path_pat = r.path_pattern if r.path_pattern.startswith("/") else f"/{r.path_pattern}"
        method_lower = (r.method or "GET").lower()
        if path_pat not in paths:
            paths[path_pat] = {}

        # Extract {param} placeholders from path_pattern
        param_names = re.findall(r"\{([^}]+)\}", path_pat)
        parameters = [
            {
                "name": p_name,
                "in": "path",
                "required": True,
                "schema": {"type": "string", "default": "101"},
                "description": f"Path parameter `{p_name}`",
            }
            for p_name in param_names
        ]

        segments = [seg for seg in path_pat.split("/") if seg and not seg.startswith("{")]
        tag = segments[0].capitalize() if segments else "API Endpoints"

        op_obj: Dict[str, Any] = {
            "tags": [tag],
            "summary": r.description or f"{r.method} {path_pat}",
            "description": (
                f"Protected by SentinelGW (`{gw_prefix}{path_pat}`). "
                f"Rate limit: **{r.rate_limit_rpm} req/min** (burst {r.burst_capacity})."
            ),
            "parameters": parameters,
            "responses": {
                "200": {"description": "Successful response through SentinelGW"},
                "401": {"description": "Blocked by SentinelGW — Missing or Invalid Auth (OWASP API2)"},
                "403": {"description": "Blocked by SentinelGW — BOLA / BFLA / Payload Policy (OWASP API1/API5/API8)"},
                "429": {"description": "Rate Limited by SentinelGW (OWASP API4/API6)"},
            },
        }

        if r.auth_required:
            op_obj["security"] = [{"BearerAuth": []}, {"ApiKeyAuth": []}]

        if method_lower in ("post", "put", "patch"):
            sample_body: Dict[str, Any] = {"name": "Sample Item"}
            if "login" in path_pat.lower() or "register" in path_pat.lower() or "auth" in path_pat.lower():
                sample_body = {"email": "alice@example.com", "password": "Password123!"}
            elif "board" in path_pat.lower():
                sample_body = {"title": "Project Roadmap", "background": "blue"}
            elif "list" in path_pat.lower():
                sample_body = {"title": "In Progress", "boardId": "board-101"}
            elif "card" in path_pat.lower():
                sample_body = {"title": "Implement API Security Gateway", "listId": "list-101", "description": "Task details"}
            op_obj["requestBody"] = {
                "required": False,
                "content": {
                    "application/json": {
                        "schema": {"type": "object", "additionalProperties": True},
                        "example": sample_body,
                    }
                },
            }

        paths[path_pat][method_lower] = op_obj

    return {
        "openapi": "3.0.3",
        "info": {
            "title": f"{proj_name} — SentinelGW Protected Swagger UI",
            "version": "1.0.0",
            "description": (
                f"Auto-generated interactive OpenAPI specification for **{proj_name}** (`{base_url}`) "
                f"synthesized from SentinelGW's registered Route Inventory ({len(routes)} routes). "
                f"Every request executed here routes live through `{gw_prefix}/*`."
            ),
        },
        "servers": [
            {
                "url": gw_prefix,
                "description": f"SentinelGW Protected Proxy ({gw_prefix})",
            }
        ],
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "Paste your Firebase ID Token or Bearer JWT here",
                },
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "SentinelGW Consumer API Key",
                },
            }
        },
        "paths": paths,
    }


def _build_synthesized_swagger_html(proj_name: str, gw_prefix: str) -> str:
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link type="text/css" rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
  <link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">
  <title>{proj_name} - SentinelGW Swagger UI</title>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function() {{
      window.ui = SwaggerUIBundle({{
        url: '{gw_prefix}/openapi.json',
        dom_id: '#swagger-ui',
        layout: 'BaseLayout',
        deepLinking: true,
        showExtensions: true,
        showCommonExtensions: true,
        persistAuthorization: true
      }});
    }};
  </script>
</body>
</html>"""


class GatewayRuntimeState:
    """Global runtime switches controllable from the Dashboard / Attack Simulator."""
    def __init__(self):
        self.gateway_enabled: bool = True
        self.auto_block_critical: bool = settings.AUTO_BLOCK_CRITICAL
        self.auto_block_duration_minutes: int = settings.AUTO_BLOCK_DURATION_MINUTES
        self.anomaly_zscore_threshold: float = 3.0


gateway_state = GatewayRuntimeState()


def _rewrite_swagger_if_needed(
    norm_path: str,
    gw_prefix: str,
    body_text: str,
    headers: Dict[str, str],
    upstream: Optional[Upstream] = None,
    registered_routes: Optional[List[Route]] = None,
) -> Tuple[str, Dict[str, str], str]:
    """
    When proxying FastAPI Swagger UI (/docs, /redoc) or /openapi.json through /gw,
    rewrites the OpenAPI spec URL and injects the Gateway prefix into `servers`
    so every 'Try it out -> Execute' click in Swagger UI routes through SentinelGW!
    If the upstream does not natively serve Swagger UI (e.g., a React/Vite/Firebase SPA
    or custom backend), automatically synthesizes Swagger UI HTML and OpenAPI 3.0 JSON
    from SentinelGW's registered routes for that project.
    """
    media_type = "application/json"
    for k, v in headers.items():
        if k.lower() == "content-type":
            media_type = v.split(";")[0].strip()
            break

    clean_doc_path = norm_path.rstrip("/") or "/"
    if clean_doc_path in ("/docs", "/redoc", "/docs/oauth2-redirect"):
        media_type = "text/html"
        is_native_swagger = (
            "swagger-ui" in body_text
            or "SwaggerUIBundle" in body_text
            or "redoc" in body_text.lower()
            or "/openapi.json" in body_text
        )
        if is_native_swagger:
            rewritten = body_text.replace("url: '/openapi.json'", f"url: '{gw_prefix}/openapi.json'")
            rewritten = rewritten.replace('url: "/openapi.json"', f'url: "{gw_prefix}/openapi.json"')
            rewritten = rewritten.replace('spec-url="/openapi.json"', f'spec-url="{gw_prefix}/openapi.json"')
            rewritten = rewritten.replace("'/docs/oauth2-redirect'", f"'{gw_prefix}/docs/oauth2-redirect'")
            rewritten = rewritten.replace('"/docs/oauth2-redirect"', f'"{gw_prefix}/docs/oauth2-redirect"')
        else:
            proj_name = upstream.name if upstream else "Connected Project"
            rewritten = _build_synthesized_swagger_html(proj_name, gw_prefix)

        for k in list(headers.keys()):
            if k.lower() in ("content-security-policy", "x-frame-options"):
                del headers[k]
        headers["Content-Security-Policy"] = (
            "default-src 'self' https: data: blob:; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com blob:; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://fonts.googleapis.com; "
            "font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "img-src 'self' data: https: http:; "
            "connect-src *"
        )
        return rewritten, headers, media_type

    if clean_doc_path == "/openapi.json":
        try:
            spec = json.loads(body_text)
            if isinstance(spec, dict) and "paths" in spec:
                spec["servers"] = [
                    {
                        "url": gw_prefix,
                        "description": f"SentinelGW Protected Proxy ({gw_prefix})",
                    }
                ]
                # Swagger OAuth password flows use tokenUrl directly and do not
                # automatically prepend the OpenAPI `servers` URL. Route relative
                # login/token requests through this project's gateway prefix.
                security_schemes = (
                    (spec.get("components") or {}).get("securitySchemes") or {}
                )
                for scheme in security_schemes.values():
                    if not isinstance(scheme, dict) or scheme.get("type") != "oauth2":
                        continue
                    for flow in (scheme.get("flows") or {}).values():
                        if not isinstance(flow, dict):
                            continue
                        token_url = flow.get("tokenUrl")
                        if isinstance(token_url, str) and token_url:
                            if token_url.startswith("/"):
                                flow["tokenUrl"] = f"{gw_prefix}{token_url}"
                            elif not token_url.startswith(("http://", "https://")):
                                flow["tokenUrl"] = f"{gw_prefix}/{token_url.lstrip('/')}"
                return json.dumps(spec), headers, "application/json"
        except Exception:
            pass

        # Upstream did not return a valid OpenAPI JSON (e.g. returned SPA index.html or 404).
        # Synthesize a complete OpenAPI 3.0 spec from SentinelGW's registered routes!
        synthesized = _build_synthesized_openapi_spec(upstream, registered_routes or [], gw_prefix)
        return json.dumps(synthesized), headers, "application/json"

    return body_text, headers, media_type


def _mask_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
    masked = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl == "authorization" and len(v) > 22:
            masked[k] = v[:15] + "..." + v[-8:]
        elif kl == "x-api-key" and len(v) > 10:
            masked[k] = v[:6] + "****" + v[-4:]
        else:
            masked[k] = v
    return masked


def _is_blocked(session: Session, client_ip: str, user_sub: Optional[str], api_key_id: Optional[int]) -> Optional[BlocklistEntry]:
    now = datetime.now(timezone.utc)
    entries = session.exec(select(BlocklistEntry).where(BlocklistEntry.active == True)).all()
    for entry in entries:
        if entry.expires_at:
            exp_utc = entry.expires_at if entry.expires_at.tzinfo else entry.expires_at.replace(tzinfo=timezone.utc)
            if now > exp_utc:
                entry.active = False
                session.add(entry)
                continue
        if entry.target_type == "ip" and entry.value == client_ip:
            return entry
        if entry.target_type == "user_sub" and user_sub and entry.value == user_sub:
            return entry
        if entry.target_type == "api_key" and api_key_id and entry.value == str(api_key_id):
            return entry
    return None


async def execute_gateway_pipeline(
    request: Request,
    forward_path: str,
    local_asgi_app: Any = None,
) -> Response:
    """
    Executes the 10-stage API Security Gateway pipeline on every request to /gw/{path:path}.
    """
    t0 = time.perf_counter()
    request_id = request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:12]}"
    client_ip = (
        request.headers.get("X-Simulated-Client-IP")
        or (request.headers.get("X-Forwarded-For", "").split(",")[0].strip())
        or (request.client.host if request.client else "127.0.0.1")
    )
    method = request.method.upper()
    norm_path = "/" + forward_path.lstrip("/")
    query_string = request.url.query or ""
    raw_body_bytes = await request.body()
    body_text = raw_body_bytes.decode("utf-8", errors="replace") if raw_body_bytes else ""
    req_size = len(raw_body_bytes)
    user_agent = request.headers.get("User-Agent", "unknown")

    decision = "allowed"
    block_reason: Optional[str] = None
    matched_policy_id: Optional[int] = None
    owasp_id: Optional[str] = None
    threat_score: int = 0
    user_sub: Optional[str] = None
    user_role: Optional[str] = None
    api_key_id: Optional[int] = None
    decoded_jwt: Dict[str, Any] = {}
    rate_headers: Dict[str, str] = {}
    route_id: Optional[int] = None

    with Session(engine) as session:
        all_upstreams = session.exec(select(Upstream)).all()
        upstream = next((u for u in all_upstreams if u.enabled), all_upstreams[0] if all_upstreams else None)

        # Track whether the caller used a slug prefix (/gw/{slug}/...) so we can rewrite /docs and /openapi.json
        gw_prefix = "/gw"
        parts = [p for p in norm_path.split("/") if p]
        if parts:
            matched_by_slug = next((u for u in all_upstreams if u.slug.lower() == parts[0].lower()), None)
            if matched_by_slug:
                upstream = matched_by_slug
                gw_prefix = f"/gw/{matched_by_slug.slug}"
                norm_path = "/" + "/".join(parts[1:])

        upstream_id = upstream.id if upstream else 1
        is_swagger_doc_route = (norm_path.rstrip("/") or "/") in (
            "/docs",
            "/redoc",
            "/openapi.json",
            "/docs/oauth2-redirect",
        )

        # Look up matching route early so hit_count increments on EVERY call (even in Bypass mode or if blocked)
        matched_route, path_params = find_matching_route(session, upstream_id, method, norm_path)
        is_shadow_probe = (
            norm_path in ("/internal/debug", "/v1/users", "/admin/debug")
            or request.headers.get("X-Simulator-Shadow") == "1"
        )

        if matched_route:
            route_id = matched_route.id
            matched_route.hit_count = (matched_route.hit_count or 0) + 1
            matched_route.last_seen_at = datetime.now(timezone.utc)
            session.add(matched_route)
            session.commit()
        elif not is_swagger_doc_route and upstream_id != 1 and not is_shadow_probe:
            existing_proj_routes = session.exec(
                select(Route).where(Route.upstream_id == upstream_id, Route.registered == True)
            ).all()
            if len(existing_proj_routes) == 0:
                # If the connected project had no OpenAPI routes imported yet, auto-register normal endpoints as they are called
                matched_route = Route(
                    upstream_id=upstream_id,
                    method=method,
                    path_pattern=norm_path,
                    description=f"Auto-discovered route on {upstream.name if upstream else 'Connected API'}",
                    auth_required=False,
                    registered=True,
                    hit_count=1,
                    last_seen_at=datetime.now(timezone.utc),
                )
                session.add(matched_route)
                session.commit()
                session.refresh(matched_route)
                route_id = matched_route.id

        # Pre-extract JWT claims if present so even early stages know user_sub
        auth_header = request.headers.get("Authorization", "")
        api_key_header = request.headers.get("X-API-Key", "")

        # STAGE 2: Master Gateway Bypass Toggle (for live Attack Simulator ON/OFF comparison)
        proj_registered_routes = (
            session.exec(select(Route).where(Route.upstream_id == upstream_id, Route.registered == True)).all()
            if is_swagger_doc_route
            else []
        )

        if not gateway_state.gateway_enabled:
            resp_status, resp_headers, resp_body = await _forward_to_upstream(
                method, norm_path, query_string, dict(request.headers), raw_body_bytes, upstream, local_asgi_app, user_sub
            )
            resp_body, resp_headers, media_type = _rewrite_swagger_if_needed(
                norm_path, gw_prefix, resp_body, resp_headers, upstream, proj_registered_routes
            )
            if is_swagger_doc_route:
                resp_status = 200
            resp_headers["X-Request-ID"] = request_id
            resp_headers["X-Gateway-Mode"] = "BYPASSED-OFF"
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            await _record_and_detect(
                session=session,
                request_id=request_id,
                client_ip=client_ip,
                user_sub=user_sub,
                user_role=user_role,
                api_key_id=api_key_id,
                upstream_id=upstream_id,
                route_id=route_id,
                method=method,
                path=norm_path,
                query_params=query_string,
                request_headers=_mask_sensitive_headers(dict(request.headers)),
                request_body_preview=body_text[:1000],
                response_body_preview=resp_body[:1000],
                decoded_jwt=decoded_jwt,
                status_code=resp_status,
                latency_ms=latency_ms,
                req_size=req_size,
                resp_size=len(resp_body.encode("utf-8")),
                user_agent=user_agent,
                decision="allowed",
                block_reason="Gateway protection OFF (pass-through mode)",
                matched_policy_id=None,
                owasp_id=None,
                threat_score=0,
            )
            return Response(content=resp_body, status_code=resp_status, headers=resp_headers, media_type=media_type)

        # STAGE 3: IP, User & API Key Blocklist Check
        blocked_entry = _is_blocked(session, client_ip, user_sub, api_key_id)
        if blocked_entry:
            return await _reject_request(
                session=session,
                t0=t0,
                request_id=request_id,
                client_ip=client_ip,
                user_sub=user_sub,
                user_role=user_role,
                api_key_id=api_key_id,
                upstream_id=upstream_id,
                route_id=None,
                method=method,
                path=norm_path,
                query_string=query_string,
                req_headers=dict(request.headers),
                body_text=body_text,
                decoded_jwt=decoded_jwt,
                http_status=403,
                decision="blocked",
                block_reason=f"Blocked by active blocklist ({blocked_entry.target_type}={blocked_entry.value}): {blocked_entry.reason}",
                matched_policy_id=None,
                owasp_id=blocked_entry.owasp_id or "API2",
                threat_score=95,
                user_agent=user_agent,
                req_size=req_size,
            )

        # STAGE 4: Route Registry Lookup & Shadow API Discovery (OWASP API9)
        if not matched_route and not is_swagger_doc_route:
            # Record or increment undocumented Shadow API route (OWASP API9)
            shadow = session.exec(
                select(Route).where(
                    Route.upstream_id == upstream_id,
                    Route.path_pattern == norm_path,
                    Route.registered == False,
                )
            ).first()
            if not shadow:
                shadow = Route(
                    upstream_id=upstream_id,
                    method=method,
                    path_pattern=norm_path,
                    description="Discovered undocumented Shadow API endpoint (OWASP API9)",
                    auth_required=True,
                    registered=False,
                    hit_count=1,
                    last_seen_at=datetime.now(timezone.utc),
                )
                session.add(shadow)
                session.commit()
                session.refresh(shadow)
            else:
                shadow.hit_count = (shadow.hit_count or 0) + 1
                shadow.last_seen_at = datetime.now(timezone.utc)
                session.add(shadow)
                session.commit()

            route_id = shadow.id
            owasp_id = "API9"
            threat_score = max(threat_score, 75)
            pol_enabled, pol_mode, pol_id = check_policy_mode(session, "shadow_api", "API9")
            if pol_enabled and pol_mode == "enforce":
                return await _reject_request(
                    session=session,
                    t0=t0,
                    request_id=request_id,
                    client_ip=client_ip,
                    user_sub=user_sub,
                    user_role=user_role,
                    api_key_id=api_key_id,
                    upstream_id=upstream_id,
                    route_id=route_id,
                    method=method,
                    path=norm_path,
                    query_string=query_string,
                    req_headers=dict(request.headers),
                    body_text=body_text,
                    decoded_jwt=decoded_jwt,
                    http_status=403,
                    decision="blocked",
                    block_reason=f"Shadow API Protection (OWASP API9): Unregistered endpoint '{method} {norm_path}' is not in the API route inventory",
                    matched_policy_id=pol_id,
                    owasp_id="API9",
                    threat_score=80,
                    user_agent=user_agent,
                    req_size=req_size,
                )
            elif pol_enabled and pol_mode == "monitor":
                decision = "monitored"
                block_reason = f"[Monitor Mode] Unregistered shadow endpoint '{method} {norm_path}' accessed (OWASP API9)"
                matched_policy_id = pol_id

        # STAGE 5: Authentication — Strict JWT Checklist & API Key Validation (OWASP API2)
        is_auth_bootstrap_route = (
            norm_path in ("/auth/login", "/auth/register", "/login", "/register", "/token", "/health", "/api/health")
            or norm_path.endswith(("/auth/login", "/auth/jwt/login", "/auth/register", "/oauth/token", "/api/health"))
        )
        auth_required = matched_route.auth_required if matched_route else True
        if is_swagger_doc_route or is_auth_bootstrap_route or norm_path in ("/products", "/search"):
            auth_required = False if (is_swagger_doc_route or is_auth_bootstrap_route) else (
                matched_route.auth_required if matched_route else False
            )

        # Swagger UI's OAuth2 Password Flow modal sends `Authorization: Basic Og==` (empty client_id:client_secret)
        # when requesting a token from /auth/login. Do not treat Basic client-credential headers on login routes as Bearer JWTs.
        has_bearer_header = auth_header.strip().lower().startswith("bearer ")
        should_validate_auth = (
            not is_auth_bootstrap_route
            and not is_swagger_doc_route
            and (auth_required or api_key_header or has_bearer_header)
        )

        if should_validate_auth:
            pol_enabled, pol_mode, pol_id = check_policy_mode(session, "auth", "API2")
            if api_key_header and not auth_header:
                ok_key, key_obj, key_msg = verify_api_key(api_key_header, session)
                if not ok_key:
                    if pol_enabled and pol_mode == "enforce":
                        return await _reject_request(
                            session=session,
                            t0=t0,
                            request_id=request_id,
                            client_ip=client_ip,
                            user_sub=None,
                            user_role=None,
                            api_key_id=key_obj.id if key_obj else None,
                            upstream_id=upstream_id,
                            route_id=route_id,
                            method=method,
                            path=norm_path,
                            query_string=query_string,
                            req_headers=dict(request.headers),
                            body_text=body_text,
                            decoded_jwt={},
                            http_status=401,
                            decision="blocked",
                            block_reason=f"API Key Authentication Failed (OWASP API2): {key_msg}",
                            matched_policy_id=pol_id,
                            owasp_id="API2",
                            threat_score=75,
                            user_agent=user_agent,
                            req_size=req_size,
                        )
                else:
                    api_key_id = key_obj.id
                    user_sub = f"apikey:{key_obj.name}"
                    user_role = key_obj.role
            elif auth_header or auth_required:
                if not auth_header:
                    if pol_enabled and pol_mode == "enforce":
                        return await _reject_request(
                            session=session,
                            t0=t0,
                            request_id=request_id,
                            client_ip=client_ip,
                            user_sub=None,
                            user_role=None,
                            api_key_id=None,
                            upstream_id=upstream_id,
                            route_id=route_id,
                            method=method,
                            path=norm_path,
                            query_string=query_string,
                            req_headers=dict(request.headers),
                            body_text=body_text,
                            decoded_jwt={},
                            http_status=401,
                            decision="blocked",
                            block_reason="Missing Bearer JWT or X-API-Key on protected route (OWASP API2)",
                            matched_policy_id=pol_id,
                            owasp_id="API2",
                            threat_score=60,
                            user_agent=user_agent,
                            req_size=req_size,
                        )
                else:
                    jwt_res = validate_jwt_checklist(
                        auth_header,
                        session,
                        jwt_config=get_upstream_jwt_config(session, upstream_id),
                    )
                    decoded_jwt = {"header": jwt_res.get("header"), "payload": jwt_res.get("payload"), "steps": jwt_res.get("steps")}
                    payload_claims = jwt_res.get("payload") or {}
                    user_sub = payload_claims.get("sub")
                    user_role = payload_claims.get("role")

                    if not jwt_res["valid"]:
                        fail_code = jwt_res.get("failure_code", "jwt_invalid")
                        score = 95 if fail_code in ("jwt_alg_none", "jwt_bad_signature", "jwt_algorithm_confusion") else 75
                        if pol_enabled and pol_mode == "enforce":
                            return await _reject_request(
                                session=session,
                                t0=t0,
                                request_id=request_id,
                                client_ip=client_ip,
                                user_sub=user_sub,
                                user_role=user_role,
                                api_key_id=None,
                                upstream_id=upstream_id,
                                route_id=route_id,
                                method=method,
                                path=norm_path,
                                query_string=query_string,
                                req_headers=dict(request.headers),
                                body_text=body_text,
                                decoded_jwt=decoded_jwt,
                                http_status=401,
                                decision="blocked",
                                block_reason=f"JWT Validation Failed [{fail_code}] (OWASP API2): {jwt_res['reason']}",
                                matched_policy_id=pol_id,
                                owasp_id="API2",
                                threat_score=score,
                                user_agent=user_agent,
                                req_size=req_size,
                            )
                        elif pol_enabled and pol_mode == "monitor":
                            decision = "monitored"
                            block_reason = f"[Monitor Mode] JWT Validation Failed [{fail_code}]: {jwt_res['reason']}"
                            owasp_id = "API2"
                            threat_score = max(threat_score, score)

        # Re-check blocklist now that user_sub / api_key_id are known
        if user_sub or api_key_id:
            blocked_principal = _is_blocked(session, client_ip, user_sub, api_key_id)
            if blocked_principal:
                return await _reject_request(
                    session=session,
                    t0=t0,
                    request_id=request_id,
                    client_ip=client_ip,
                    user_sub=user_sub,
                    user_role=user_role,
                    api_key_id=api_key_id,
                    upstream_id=upstream_id,
                    route_id=route_id,
                    method=method,
                    path=norm_path,
                    query_string=query_string,
                    req_headers=dict(request.headers),
                    body_text=body_text,
                    decoded_jwt=decoded_jwt,
                    http_status=403,
                    decision="blocked",
                    block_reason=f"Principal '{blocked_principal.value}' is on the active blocklist: {blocked_principal.reason}",
                    matched_policy_id=None,
                    owasp_id=blocked_principal.owasp_id or "API2",
                    threat_score=95,
                    user_agent=user_agent,
                    req_size=req_size,
                )

        # STAGE 6: Authorization — BFLA Role/Scope Check (OWASP API5) & BOLA Ownership Check (OWASP API1)
        if matched_route:
            # 6a. Broken Function Level Authorization (API5)
            req_role = matched_route.required_role
            if req_role and req_role.lower() == "admin" and (user_role or "").lower() != "admin":
                pol_enabled, pol_mode, pol_id = check_policy_mode(session, "bfla", "API5")
                if pol_enabled and pol_mode == "enforce":
                    return await _reject_request(
                        session=session,
                        t0=t0,
                        request_id=request_id,
                        client_ip=client_ip,
                        user_sub=user_sub,
                        user_role=user_role,
                        api_key_id=api_key_id,
                        upstream_id=upstream_id,
                        route_id=route_id,
                        method=method,
                        path=norm_path,
                        query_string=query_string,
                        req_headers=dict(request.headers),
                        body_text=body_text,
                        decoded_jwt=decoded_jwt,
                        http_status=403,
                        decision="blocked",
                        block_reason=f"BFLA Violation (OWASP API5): Route '{matched_route.path_pattern}' requires role='admin', caller has role='{user_role or 'anonymous'}'",
                        matched_policy_id=pol_id,
                        owasp_id="API5",
                        threat_score=88,
                        user_agent=user_agent,
                        req_size=req_size,
                    )
                elif pol_enabled and pol_mode == "monitor":
                    decision = "monitored"
                    block_reason = f"[Monitor Mode] BFLA Violation on '{matched_route.path_pattern}' by role='{user_role}'"
                    owasp_id = "API5"
                    matched_policy_id = pol_id
                    threat_score = max(threat_score, 88)

            # 6b. Broken Object Level Authorization (API1)
            bola_ok, bola_err = check_bola_ownership(matched_route, path_params, user_sub, user_role)
            if not bola_ok:
                pol_enabled, pol_mode, pol_id = check_policy_mode(session, "bola", "API1")
                if pol_enabled and pol_mode == "enforce":
                    return await _reject_request(
                        session=session,
                        t0=t0,
                        request_id=request_id,
                        client_ip=client_ip,
                        user_sub=user_sub,
                        user_role=user_role,
                        api_key_id=api_key_id,
                        upstream_id=upstream_id,
                        route_id=route_id,
                        method=method,
                        path=norm_path,
                        query_string=query_string,
                        req_headers=dict(request.headers),
                        body_text=body_text,
                        decoded_jwt=decoded_jwt,
                        http_status=403,
                        decision="blocked",
                        block_reason=bola_err,
                        matched_policy_id=pol_id,
                        owasp_id="API1",
                        threat_score=85,
                        user_agent=user_agent,
                        req_size=req_size,
                    )
                elif pol_enabled and pol_mode == "monitor":
                    decision = "monitored"
                    block_reason = f"[Monitor Mode] {bola_err}"
                    owasp_id = "API1"
                    matched_policy_id = pol_id
                    threat_score = max(threat_score, 85)

        # STAGE 7: Rate Limiting & Sensitive Business Flow Velocity (OWASP API4 & API6)
        limit_rpm = matched_route.rate_limit_rpm if matched_route else 60
        burst_cap = matched_route.burst_capacity if matched_route else 15
        is_sensitive = matched_route.is_sensitive_flow if matched_route else False
        rl_owasp = "API6" if is_sensitive else "API4"
        rl_key = f"upstream-{upstream_id}:{client_ip}:{user_sub or 'anon'}:{matched_route.path_pattern if matched_route else norm_path}"

        if not is_swagger_doc_route:
            rl_allowed, rate_headers, rl_meta = rate_limiter.check_and_consume(
                key=rl_key,
                limit_rpm=limit_rpm,
                burst_capacity=burst_cap,
                window_seconds=60,
            )
            if not rl_allowed:
                pol_enabled, pol_mode, pol_id = check_policy_mode(session, "rate_limit", rl_owasp)
                if pol_enabled and pol_mode == "enforce":
                    return await _reject_request(
                        session=session,
                        t0=t0,
                        request_id=request_id,
                        client_ip=client_ip,
                        user_sub=user_sub,
                        user_role=user_role,
                        api_key_id=api_key_id,
                        upstream_id=upstream_id,
                        route_id=route_id,
                        method=method,
                        path=norm_path,
                        query_string=query_string,
                        req_headers=dict(request.headers),
                        body_text=body_text,
                        decoded_jwt=decoded_jwt,
                        http_status=429,
                        decision="rate_limited",
                        block_reason=f"Rate/Velocity Limit Exceeded (OWASP {rl_owasp}): {rl_meta['reason']}",
                        matched_policy_id=pol_id,
                        owasp_id=rl_owasp,
                        threat_score=70,
                        user_agent=user_agent,
                        req_size=req_size,
                        extra_headers=rate_headers,
                    )
                elif pol_enabled and pol_mode == "monitor":
                    decision = "monitored"
                    block_reason = f"[Monitor Mode] Rate Limit Exceeded: {rl_meta['reason']}"
                    owasp_id = rl_owasp
                    matched_policy_id = pol_id
                    threat_score = max(threat_score, 70)

        # STAGE 8: Payload & Signature Inspection (SSRF API7, Injection API8, Size/Limit API4, Mass Assignment API3)
        inspection = (
            {"violation": False, "threat_score": 0}
            if is_swagger_doc_route
            else inspect_request_payload(
                method=method,
                path=norm_path,
                query_string=query_string,
                headers=dict(request.headers),
                body_text=body_text,
            )
        )
        if inspection.get("violation"):
            insp_owasp = inspection["owasp_id"]
            insp_type = inspection["policy_type"]
            pol_enabled, pol_mode, pol_id = check_policy_mode(session, insp_type, insp_owasp)
            if pol_enabled and pol_mode == "enforce":
                return await _reject_request(
                    session=session,
                    t0=t0,
                    request_id=request_id,
                    client_ip=client_ip,
                    user_sub=user_sub,
                    user_role=user_role,
                    api_key_id=api_key_id,
                    upstream_id=upstream_id,
                    route_id=route_id,
                    method=method,
                    path=norm_path,
                    query_string=query_string,
                    req_headers=dict(request.headers),
                    body_text=body_text,
                    decoded_jwt=decoded_jwt,
                    http_status=inspection.get("http_status", 403),
                    decision="blocked",
                    block_reason=inspection["reason"],
                    matched_policy_id=pol_id,
                    owasp_id=insp_owasp,
                    threat_score=inspection.get("threat_score", 85),
                    user_agent=user_agent,
                    req_size=req_size,
                    extra_headers=rate_headers,
                )
            elif pol_enabled and pol_mode == "monitor":
                decision = "monitored"
                block_reason = f"[Monitor Mode] {inspection['reason']}"
                owasp_id = insp_owasp
                matched_policy_id = pol_id
                threat_score = max(threat_score, inspection.get("threat_score", 85))

        # STAGE 9: Forward to Upstream via Async HTTPX
        resp_status, upstream_headers, raw_resp_body = await _forward_to_upstream(
            method, norm_path, query_string, dict(request.headers), raw_body_bytes, upstream, local_asgi_app, user_sub
        )

        # STAGE 10: Response Hardening (API8 Headers & Error Sanitization + API3 JSON Field Redaction)
        redact_fields = ["password_hash", "ssn", "credit_card", "secret_note"]
        if matched_route and matched_route.response_redact_fields_json:
            try:
                redact_fields = json.loads(matched_route.response_redact_fields_json)
            except Exception:
                pass

        hdr_pol_enabled, hdr_pol_mode, _ = check_policy_mode(session, "header_hardening", "API8")
        red_pol_enabled, red_pol_mode, red_pol_id = check_policy_mode(session, "field_redaction", "API3")

        hardened_headers, hardened_body, redacted_fields = harden_response(
            status_code=resp_status,
            upstream_headers=upstream_headers,
            body_text=raw_resp_body,
            redact_fields=redact_fields,
            enable_header_hardening=(hdr_pol_enabled and hdr_pol_mode == "enforce"),
            enable_field_redaction=(red_pol_enabled and red_pol_mode == "enforce" and not is_swagger_doc_route),
        )
        hardened_body, hardened_headers, media_type = _rewrite_swagger_if_needed(
            norm_path, gw_prefix, hardened_body, hardened_headers, upstream, proj_registered_routes
        )
        if is_swagger_doc_route:
            resp_status = 200
        hardened_headers.update(rate_headers)
        hardened_headers["X-Request-ID"] = request_id
        hardened_headers["X-Gateway-Decision"] = decision

        if redacted_fields and not owasp_id:
            owasp_id = "API3"
            matched_policy_id = red_pol_id

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        await _record_and_detect(
            session=session,
            request_id=request_id,
            client_ip=client_ip,
            user_sub=user_sub,
            user_role=user_role,
            api_key_id=api_key_id,
            upstream_id=upstream_id,
            route_id=route_id,
            method=method,
            path=norm_path,
            query_params=query_string,
            request_headers=_mask_sensitive_headers(dict(request.headers)),
            request_body_preview=body_text[:1000],
            response_body_preview=hardened_body[:1000],
            decoded_jwt=decoded_jwt,
            status_code=resp_status,
            latency_ms=latency_ms,
            req_size=req_size,
            resp_size=len(hardened_body.encode("utf-8")),
            user_agent=user_agent,
            decision=decision,
            block_reason=block_reason or (f"Redacted excessive fields: {', '.join(redacted_fields)} (OWASP API3)" if redacted_fields else None),
            matched_policy_id=matched_policy_id,
            owasp_id=owasp_id,
            threat_score=threat_score,
        )

        return Response(
            content=hardened_body,
            status_code=resp_status,
            headers=hardened_headers,
            media_type=media_type,
        )


STRIP_PROXY_REQUEST_HEADERS = {
    "host",
    "content-length",
    "accept-encoding",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
}

_spa_firebase_config_cache: Dict[str, Dict[str, str]] = {}


async def _detect_firebase_spa_config(base_url: str, client: httpx.AsyncClient) -> Optional[Dict[str, str]]:
    """
    If a connected upstream is a static React/Vite SPA on Vercel/Netlify/Firebase Hosting
    that uses Firebase Auth & Cloud Firestore directly (with no custom REST backend),
    discovers its Firebase projectId and web apiKey from the SPA bundle so SentinelGW
    can translate REST routes (/auth/login, /auth/register, /users/{userId}/boards, etc.)
    into real Firebase IdentityToolkit & Cloud Firestore REST API calls!
    """
    if base_url in _spa_firebase_config_cache:
        return _spa_firebase_config_cache[base_url] or None

    try:
        idx_resp = await client.get(base_url + "/", timeout=8.0)
        html = idx_resp.text or ""
        script_Match = re.search(r'src=["\'](/assets/index-[^"\']+\.js)["\']', html)
        if not script_Match:
            _spa_firebase_config_cache[base_url] = {}
            return None

        js_resp = await client.get(base_url.rstrip("/") + script_Match.group(1), timeout=10.0)
        js_text = js_resp.text or ""
        proj_match = re.search(r'projectId\s*:\s*["\'`]([a-zA-Z0-9_-]+)["\'`]', js_text)
        key_match = re.search(r'apiKey\s*:\s*["\'`](AIza[0-9A-Za-z_-]{35})["\'`]', js_text)
        if proj_match and key_match:
            cfg = {"project_id": proj_match.group(1), "api_key": key_match.group(1)}
            _spa_firebase_config_cache[base_url] = cfg
            return cfg
    except Exception:
        pass

    _spa_firebase_config_cache[base_url] = {}
    return None


def _to_firestore_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    fields: Dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, bool):
            fields[k] = {"booleanValue": v}
        elif isinstance(v, int):
            fields[k] = {"integerValue": str(v)}
        elif isinstance(v, float):
            fields[k] = {"doubleValue": v}
        elif v is None:
            fields[k] = {"nullValue": None}
        else:
            fields[k] = {"stringValue": str(v)}
    return {"fields": fields}


def _from_firestore_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    name = doc.get("name", "")
    doc_id = name.split("/")[-1] if name else ""
    out: Dict[str, Any] = {"id": doc_id}
    for k, val_obj in (doc.get("fields") or {}).items():
        if not isinstance(val_obj, dict):
            continue
        for val_type, raw_val in val_obj.items():
            if val_type == "integerValue":
                try:
                    out[k] = int(raw_val)
                except Exception:
                    out[k] = raw_val
            else:
                out[k] = raw_val
    if "createTime" in doc:
        out["createdAt"] = doc["createTime"]
    if "updateTime" in doc:
        out["updatedAt"] = doc["updateTime"]
    return out


async def _bridge_firebase_spa_request(
    method: str,
    path: str,
    query_string: str,
    forward_headers: Dict[str, str],
    body_bytes: bytes,
    fb_cfg: Dict[str, str],
    client: httpx.AsyncClient,
) -> Optional[Tuple[int, Dict[str, str], str]]:
    """
    Translates REST gateway calls (/auth/register, /auth/login, /users/{uid}/boards, etc.)
    into live Firebase Auth (IdentityToolkit) and Cloud Firestore REST API calls.
    """
    api_key = fb_cfg["api_key"]
    project_id = fb_cfg["project_id"]
    clean_path = "/" + path.strip("/")
    body_json: Dict[str, Any] = {}
    if body_bytes:
        try:
            parsed = json.loads(body_bytes.decode("utf-8", errors="replace"))
            if isinstance(parsed, dict):
                body_json = parsed
        except Exception:
            pass

    # 1. Firebase Auth: POST /auth/register or POST /auth/login
    if clean_path in ("/auth/register", "/auth/login") and method == "POST":
        email = body_json.get("email") or body_json.get("username") or ""
        password = body_json.get("password") or ""
        if "@" not in str(email):
            email = f"{email}@example.com" if email else "user@example.com"

        endpoint = "accounts:signUp" if clean_path == "/auth/register" else "accounts:signInWithPassword"
        fb_auth_url = f"https://identitytoolkit.googleapis.com/v1/{endpoint}?key={api_key}"
        fb_resp = await client.post(
            fb_auth_url,
            json={"email": email, "password": password, "returnSecureToken": True},
            timeout=12.0,
        )
        data = fb_resp.json() if fb_resp.content else {}
        if fb_resp.status_code == 200 and "idToken" in data:
            normalized = {
                "status": "authenticated" if clean_path == "/auth/login" else "registered",
                "firebase_project_id": project_id,
                "userId": data.get("localId"),
                "email": data.get("email"),
                "access_token": data.get("idToken"),
                "idToken": data.get("idToken"),
                "refreshToken": data.get("refreshToken"),
                "expiresIn": data.get("expiresIn"),
            }
            return (201 if clean_path == "/auth/register" else 200), {"Content-Type": "application/json"}, json.dumps(normalized)
        err_msg = ((data.get("error") or {}).get("message") or "").upper()
        if clean_path == "/auth/login" and ("INVALID_LOGIN_CREDENTIALS" in err_msg or "INVALID_PASSWORD" in err_msg or "EMAIL_NOT_FOUND" in err_msg):
            return 401, {"Content-Type": "application/json"}, fb_resp.text
        return fb_resp.status_code, {"Content-Type": "application/json"}, fb_resp.text

    # 2. Cloud Firestore REST Bridge: /users/{userId}/{collection}[/{docId}]
    firestore_base = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
    fs_headers: Dict[str, str] = {"Content-Type": "application/json"}
    auth_hdr = next((v for k, v in forward_headers.items() if k.lower() == "authorization"), None)
    if auth_hdr:
        fs_headers["Authorization"] = auth_hdr

    parts = [p for p in clean_path.split("/") if p]
    # Support /users/{userId}/boards, /users/{userId}/lists, /users/{userId}/cards (and nested or top-level collections)
    if len(parts) >= 3 and parts[0] == "users":
        user_id = parts[1]
        collection_name = parts[2]
        item_id = parts[3] if len(parts) >= 4 else None

        # Try subcollection /users/{userId}/{collection} or top-level /{collection}
        sub_path = f"{firestore_base}/users/{user_id}/{collection_name}"
        top_path = f"{firestore_base}/{collection_name}"

        if method == "GET":
            target = f"{sub_path}/{item_id}" if item_id else sub_path
            r = await client.get(target, headers=fs_headers, timeout=12.0)
            if r.status_code == 200:
                raw = r.json()
                if item_id:
                    return 200, {"Content-Type": "application/json"}, json.dumps(_from_firestore_doc(raw))
                docs = [_from_firestore_doc(d) for d in (raw.get("documents") or [])]
                if not docs:
                    # Also check top-level collection filtered by userId
                    r_top = await client.get(top_path, headers=fs_headers, timeout=12.0)
                    if r_top.status_code == 200:
                        all_top = [_from_firestore_doc(d) for d in (r_top.json().get("documents") or [])]
                        docs = [d for d in all_top if d.get("userId") in (user_id, None) or d.get("ownerId") == user_id] or all_top
                return 200, {"Content-Type": "application/json"}, json.dumps({"userId": user_id, collection_name: docs, "count": len(docs)})
            return r.status_code, {"Content-Type": "application/json"}, r.text

        if method == "POST":
            payload_with_owner = {"userId": user_id, **body_json}
            r = await client.post(sub_path, headers=fs_headers, json=_to_firestore_fields(payload_with_owner), timeout=12.0)
            if r.status_code == 200:
                return 201, {"Content-Type": "application/json"}, json.dumps(_from_firestore_doc(r.json()))
            return r.status_code, {"Content-Type": "application/json"}, r.text

        if method in ("PATCH", "PUT") and item_id:
            payload_with_owner = {"userId": user_id, **body_json}
            r = await client.patch(f"{sub_path}/{item_id}", headers=fs_headers, json=_to_firestore_fields(payload_with_owner), timeout=12.0)
            if r.status_code == 200:
                return 200, {"Content-Type": "application/json"}, json.dumps(_from_firestore_doc(r.json()))
            return r.status_code, {"Content-Type": "application/json"}, r.text

        if method == "DELETE" and item_id:
            r = await client.delete(f"{sub_path}/{item_id}", headers=fs_headers, timeout=12.0)
            if r.status_code == 200:
                return 200, {"Content-Type": "application/json"}, json.dumps({"status": "deleted", "id": item_id})
            return r.status_code, {"Content-Type": "application/json"}, r.text

    return None


async def _forward_to_upstream(
    method: str,
    path: str,
    query_string: str,
    headers: Dict[str, str],
    body_bytes: bytes,
    upstream: Optional[Upstream],
    local_asgi_app: Any,
    user_sub: Optional[str],
) -> Tuple[int, Dict[str, str], str]:
    forward_headers = {
        k: v
        for k, v in headers.items()
        if k.lower() not in STRIP_PROXY_REQUEST_HEADERS
    }
    if user_sub:
        forward_headers["X-Gateway-User-Sub"] = user_sub

    base_url = upstream.base_url if upstream else settings.DEFAULT_UPSTREAM_URL
    full_path_with_qs = f"{path}?{query_string}" if query_string else path

    # If targeting local /demo app and ASGI reference is available, route in-process via ASGITransport
    if local_asgi_app is not None and ("127.0.0.1:8000/demo" in base_url or "localhost:8000/demo" in base_url or base_url.endswith("/demo")):
        transport = httpx.ASGITransport(app=local_asgi_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://local-gateway") as client:
            resp = await client.request(
                method=method,
                url=f"/demo{full_path_with_qs}",
                headers=forward_headers,
                content=body_bytes,
                timeout=10.0,
            )
            return resp.status_code, dict(resp.headers), resp.text

    target_url = base_url.rstrip("/") + full_path_with_qs
    try:
        async with httpx.AsyncClient(timeout=25.0, follow_redirects=True) as client:
            resp = await client.request(
                method=method,
                url=target_url,
                headers=forward_headers,
                content=body_bytes,
            )
            # If the upstream is a static SPA on Vercel/Netlify that returns 405 Method Not Allowed
            # or returns its SPA index.html shell (`content-disposition: inline; filename="index.html"`)
            # for REST API paths, check if it's a Firebase SPA and bridge to Firebase Auth / Firestore REST API!
            content_disp = (resp.headers.get("content-disposition") or "").lower()
            content_type = (resp.headers.get("content-type") or "").lower()
            is_spa_shell_fallback = (
                resp.status_code == 405
                or ('filename="index.html"' in content_disp and path not in ("/", "/index.html", "/docs"))
                or ("text/html" in content_type and "<div id=\"root\">" in resp.text and path not in ("/", "/index.html", "/docs"))
            )
            if is_spa_shell_fallback:
                fb_cfg = await _detect_firebase_spa_config(base_url.rstrip("/"), client)
                if fb_cfg:
                    bridged = await _bridge_firebase_spa_request(
                        method=method,
                        path=path,
                        query_string=query_string,
                        forward_headers=forward_headers,
                        body_bytes=body_bytes,
                        fb_cfg=fb_cfg,
                        client=client,
                    )
                    if bridged is not None:
                        return bridged
            return resp.status_code, dict(resp.headers), resp.text
    except Exception as exc:
        err_body = json.dumps({"error": "Bad Gateway", "detail": f"Upstream connection failed: {exc}"})
        return 502, {"Content-Type": "application/json"}, err_body


async def _reject_request(
    session: Session,
    t0: float,
    request_id: str,
    client_ip: str,
    user_sub: Optional[str],
    user_role: Optional[str],
    api_key_id: Optional[int],
    upstream_id: int,
    route_id: Optional[int],
    method: str,
    path: str,
    query_string: str,
    req_headers: Dict[str, str],
    body_text: str,
    decoded_jwt: Dict[str, Any],
    http_status: int,
    decision: str,
    block_reason: str,
    matched_policy_id: Optional[int],
    owasp_id: str,
    threat_score: int,
    user_agent: str,
    req_size: int,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Response:
    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    error_payload = {
        "error": "Gatekeeper Security Enforcement",
        "status": http_status,
        "decision": decision,
        "owasp_category": owasp_id,
        "reason": block_reason,
        "request_id": request_id,
    }
    resp_body = json.dumps(error_payload)
    out_headers = {
        "X-Request-ID": request_id,
        "X-Gateway-Decision": decision,
        "X-Gateway-OWASP": owasp_id,
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    }
    if extra_headers:
        out_headers.update(extra_headers)

    await _record_and_detect(
        session=session,
        request_id=request_id,
        client_ip=client_ip,
        user_sub=user_sub,
        user_role=user_role,
        api_key_id=api_key_id,
        upstream_id=upstream_id,
        route_id=route_id,
        method=method,
        path=path,
        query_params=query_string,
        request_headers=_mask_sensitive_headers(req_headers),
        request_body_preview=body_text[:1000],
        response_body_preview=resp_body,
        decoded_jwt=decoded_jwt,
        status_code=http_status,
        latency_ms=latency_ms,
        req_size=req_size,
        resp_size=len(resp_body.encode("utf-8")),
        user_agent=user_agent,
        decision=decision,
        block_reason=block_reason,
        matched_policy_id=matched_policy_id,
        owasp_id=owasp_id,
        threat_score=threat_score,
    )
    return Response(content=resp_body, status_code=http_status, headers=out_headers, media_type="application/json")


async def _record_and_detect(
    session: Session,
    request_id: str,
    client_ip: str,
    user_sub: Optional[str],
    user_role: Optional[str],
    api_key_id: Optional[int],
    upstream_id: int,
    route_id: Optional[int],
    method: str,
    path: str,
    query_params: str,
    request_headers: Dict[str, str],
    request_body_preview: str,
    response_body_preview: str,
    decoded_jwt: Dict[str, Any],
    status_code: int,
    latency_ms: float,
    req_size: int,
    resp_size: int,
    user_agent: str,
    decision: str,
    block_reason: Optional[str],
    matched_policy_id: Optional[int],
    owasp_id: Optional[str],
    threat_score: int,
):
    from app.detection.engine import process_request_event

    log_entry = RequestLog(
        ts=datetime.now(timezone.utc),
        request_id=request_id,
        client_ip=client_ip,
        user_sub=user_sub,
        user_role=user_role,
        api_key_id=api_key_id,
        upstream_id=upstream_id,
        route_id=route_id,
        method=method,
        path=path,
        query_params=query_params,
        request_headers_json=json.dumps(request_headers),
        request_body_preview=request_body_preview,
        response_body_preview=response_body_preview,
        decoded_jwt_json=json.dumps(decoded_jwt),
        status_code=status_code,
        latency_ms=latency_ms,
        req_size_bytes=req_size,
        resp_size_bytes=resp_size,
        user_agent=user_agent,
        decision=decision,
        block_reason=block_reason,
        matched_policy_id=matched_policy_id,
        owasp_id=owasp_id,
        threat_score=threat_score,
        anomaly_zscore=0.0,
    )
    session.add(log_entry)
    session.commit()
    session.refresh(log_entry)

    await process_request_event(session, log_entry)
