import json
import re
from datetime import datetime, timezone
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from fastapi import BackgroundTasks, Request, Response
from fastapi.responses import JSONResponse
import httpx
from sqlalchemy import update
from sqlmodel import Session, select

from app.config import settings
from app.db import engine
from app.gateway.http_client import get_http_client
from app.models import BlocklistEntry, RequestLog, Route, Upstream
from app.runtime_cache import runtime_cache
from app.runtime_state import gateway_state
from app.gateway.auth import get_upstream_jwt_config, validate_jwt_checklist, verify_api_key
from app.gateway.ratelimit import rate_limiter
from app.gateway.circuit_breaker import circuit_breaker
from app.gateway.inspector import (
    egress_trust_keys_for_base_url,
    inspect_egress_destination,
    inspect_request_payload,
    inspect_response_for_unsafe_urls,
    strip_unsafe_urls_from_json,
)
from app.gateway.policy_engine import (
    BOLA_MODE_LEARNED_OWNER,
    check_bola_ownership,
    check_policy_mode,
    find_matching_route,
    find_shadow_route,
    get_policy_config,
    is_public_auth_path,
    remember_object_owner,
    resolve_bola_mode,
    resolve_bola_owner_param,
    track_bola_enumeration,
)
from app.gateway.responses import harden_response


def _build_synthesized_openapi_spec(
    upstream: Optional[Upstream],
    routes: List[Route],
    gw_prefix: str,
) -> Dict[str, Any]:
    """
    Synthesizes an OpenAPI 3.0.3 specification from the registered routes
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
            sample_body: Dict[str, Any] = (
                {"email": "alice@example.com", "password": "Password123!"}
                if is_public_auth_path(path_pat)
                else {"name": "sample"}
            )
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

    def _set_content_type(target: Dict[str, str], value: str) -> None:
        # Starlette Response uses headers.setdefault("content-type", media_type), so an
        # upstream Content-Type: application/json would otherwise win over media_type=text/html
        # and Firefox would open /docs in its JSON viewer (SyntaxError on <!DOCTYPE).
        for k in list(target.keys()):
            if k.lower() == "content-type":
                del target[k]
        target["Content-Type"] = value

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
        _set_content_type(headers, "text/html; charset=utf-8")
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
                _set_content_type(headers, "application/json")
                return json.dumps(spec), headers, "application/json"
        except Exception:
            pass

        # Upstream did not return a valid OpenAPI JSON (e.g. returned SPA index.html or 404).
        # Synthesize a complete OpenAPI 3.0 spec from SentinelGW's registered routes!
        synthesized = _build_synthesized_openapi_spec(upstream, registered_routes or [], gw_prefix)
        _set_content_type(headers, "application/json")
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


def _cached_upstreams(session: Session) -> List[Upstream]:
    cached = runtime_cache.get("upstreams:all")
    if cached is not None:
        return cached
    rows = session.exec(select(Upstream)).all()
    runtime_cache.set("upstreams:all", rows)
    return rows


def _cached_active_blocklist(session: Session) -> List[BlocklistEntry]:
    cached = runtime_cache.get("blocklist:active")
    if cached is not None:
        return cached
    rows = session.exec(select(BlocklistEntry).where(BlocklistEntry.active == True)).all()
    runtime_cache.set("blocklist:active", rows)
    return rows


def _is_blocked(session: Session, client_ip: str, user_sub: Optional[str], api_key_id: Optional[int]) -> Optional[BlocklistEntry]:
    now = datetime.now(timezone.utc)
    entries = _cached_active_blocklist(session)
    for entry in entries:
        if entry.expires_at:
            exp_utc = entry.expires_at if entry.expires_at.tzinfo else entry.expires_at.replace(tzinfo=timezone.utc)
            if now > exp_utc:
                live = session.get(BlocklistEntry, entry.id)
                if live is not None:
                    live.active = False
                    session.add(live)
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
    background_tasks: Optional[BackgroundTasks] = None,
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
        all_upstreams = _cached_upstreams(session)
        parts = [p for p in norm_path.split("/") if p]
        matched_by_slug = next(
            (u for u in all_upstreams if parts and u.slug.lower() == parts[0].lower()),
            None,
        )
        if matched_by_slug is None:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "Unknown project",
                    "message": "Every gateway request needs a project path: /gw/{project-slug}/... . There is no default /gw route.",
                    "request_id": request_id,
                },
                headers={"X-Request-ID": request_id},
            )

        upstream = matched_by_slug
        gw_prefix = f"/gw/{matched_by_slug.slug}"
        norm_path = "/" + "/".join(parts[1:]) if len(parts) > 1 else "/"
        upstream_id = upstream.id
        is_swagger_doc_route = (norm_path.rstrip("/") or "/") in (
            "/docs",
            "/redoc",
            "/openapi.json",
            "/docs/oauth2-redirect",
        )

        # Look up matching route early so hit_count increments on EVERY call (even in Bypass mode or if blocked)
        matched_route, path_params = find_matching_route(session, upstream_id, method, norm_path)

        # Never auto-register unknown paths as official public routes (API5/API9 hardening).
        # Empty inventories must go through Shadow API discovery instead.
        if matched_route:
            route_id = matched_route.id

        auth_header = request.headers.get("Authorization", "")
        api_key_header = request.headers.get("X-API-Key", "")
        req_headers_dict = dict(request.headers)

        # Parse body JSON once for BOLA / inspector reuse
        body_json: Optional[Dict[str, Any]] = None
        if body_text and body_text.strip().startswith("{"):
            try:
                parsed_body = json.loads(body_text)
                if isinstance(parsed_body, dict):
                    body_json = parsed_body
            except Exception:
                body_json = None

        query_param_map: Dict[str, str] = {}
        if query_string:
            from urllib.parse import parse_qs as _parse_qs
            for qk, qv in _parse_qs(query_string, keep_blank_values=True).items():
                if qv:
                    query_param_map[qk] = qv[0]

        async def reject(
            http_status: int,
            dec: str,
            reason: str,
            owasp: str,
            score: int,
            pol_id: Optional[int] = None,
            extra_headers: Optional[Dict[str, str]] = None,
        ) -> Response:
            return await _reject_request(
                session=session,
                background_tasks=background_tasks,
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
                req_headers=req_headers_dict,
                body_text=body_text,
                decoded_jwt=decoded_jwt,
                http_status=http_status,
                decision=dec,
                block_reason=reason,
                matched_policy_id=pol_id,
                owasp_id=owasp,
                threat_score=score,
                user_agent=user_agent,
                req_size=req_size,
                extra_headers=extra_headers,
            )

        # STAGE 2: Master Gateway Bypass Toggle (for live Attack Simulator ON/OFF comparison)
        proj_registered_routes = (
            session.exec(select(Route).where(Route.upstream_id == upstream_id, Route.registered == True)).all()
            if is_swagger_doc_route
            else []
        )

        if not gateway_state.gateway_enabled:
            resp_status, resp_headers, resp_body = await _forward_to_upstream(
                method, norm_path, query_string, req_headers_dict, raw_body_bytes, upstream, local_asgi_app, user_sub
            )
            resp_body, resp_headers, media_type = _rewrite_swagger_if_needed(
                norm_path, gw_prefix, resp_body, resp_headers, upstream, proj_registered_routes
            )
            if is_swagger_doc_route:
                resp_status = 200
            resp_headers["X-Request-ID"] = request_id
            resp_headers["X-Gateway-Mode"] = "BYPASSED-OFF"
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            await _dispatch_record(
                background_tasks,
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
                request_headers=_mask_sensitive_headers(req_headers_dict),
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
            return await reject(
                403,
                "blocked",
                f"Blocked by active blocklist ({blocked_entry.target_type}={blocked_entry.value}): {blocked_entry.reason}",
                blocked_entry.owasp_id or "API2",
                95,
            )

        # STAGE 4: Route Registry Lookup & Shadow API Discovery (OWASP API9)
        if not matched_route and not is_swagger_doc_route:
            shadow = find_shadow_route(session, upstream_id, method, norm_path)
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
                runtime_cache.invalidate()
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
                return await reject(
                    403,
                    "blocked",
                    f"Shadow API Protection (OWASP API9): Unregistered endpoint '{method} {norm_path}' is not in the API route inventory",
                    "API9",
                    80,
                    pol_id,
                )
            elif pol_enabled and pol_mode == "monitor":
                decision = "monitored"
                block_reason = f"[Monitor Mode] Unregistered shadow endpoint '{method} {norm_path}' accessed (OWASP API9)"
                matched_policy_id = pol_id

        # STAGE 5: Authentication — Strict JWT Checklist & API Key Validation (OWASP API2)
        is_auth_bootstrap_route = is_public_auth_path(norm_path)
        auth_required = (
            False
            if (is_swagger_doc_route or is_auth_bootstrap_route)
            else (matched_route.auth_required if matched_route else True)
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
            # Accept either credential. Prefer a valid JWT when both are present (richer
            # claims for BOLA/BFLA); fall back to X-API-Key when JWT is missing or invalid.
            api_key_ok = False
            api_key_msg = ""
            key_obj = None
            if api_key_header:
                api_key_ok, key_obj, api_key_msg = verify_api_key(api_key_header, session)
                if key_obj is not None:
                    api_key_id = key_obj.id

            jwt_ok = False
            jwt_res = None
            if has_bearer_header:
                expected_scope = None
                if matched_route and matched_route.required_scopes_json:
                    try:
                        scopes_list = json.loads(matched_route.required_scopes_json or "[]")
                        if scopes_list:
                            expected_scope = scopes_list[0]
                    except Exception:
                        expected_scope = None
                jwt_res = validate_jwt_checklist(
                    auth_header,
                    session,
                    expected_role=matched_route.required_role if matched_route else None,
                    expected_scope=expected_scope,
                    jwt_config=get_upstream_jwt_config(session, upstream_id),
                )
                decoded_jwt = {
                    "header": jwt_res.get("header"),
                    "payload": jwt_res.get("payload"),
                    "steps": jwt_res.get("steps"),
                }
                jwt_ok = bool(jwt_res.get("valid"))

            if jwt_ok and jwt_res is not None:
                payload_claims = jwt_res.get("payload") or {}
                user_sub = payload_claims.get("sub")
                user_role = payload_claims.get("role")
            elif api_key_ok and key_obj is not None:
                user_sub = f"apikey:{key_obj.name}"
                user_role = key_obj.role
            elif has_bearer_header and jwt_res is not None and not jwt_ok and not api_key_ok:
                fail_code = jwt_res.get("failure_code", "jwt_invalid")
                score = 95 if fail_code in ("jwt_alg_none", "jwt_bad_signature", "jwt_algorithm_confusion") else 75
                if is_auth_bootstrap_route or fail_code in ("jwt_bad_signature", "jwt_expired", "jwt_revoked"):
                    auth_cfg = get_policy_config(session, "auth", "API2")
                    max_fails = int(auth_cfg.get("max_login_failures", 5))
                    fail_window = int(auth_cfg.get("login_failure_window_sec", 60))
                    lock_key = f"login-fail:{client_ip}"
                    locked, _, _ = rate_limiter.check_and_consume(
                        key=lock_key,
                        limit_rpm=max_fails,
                        burst_capacity=max_fails,
                        window_seconds=fail_window,
                    )
                    if not locked and pol_enabled and pol_mode == "enforce":
                        return await reject(
                            429,
                            "rate_limited",
                            f"Login / auth failure lockout (OWASP API2): >{max_fails} failures in {fail_window}s from {client_ip}",
                            "API2",
                            80,
                            pol_id,
                        )
                if pol_enabled and pol_mode == "enforce":
                    return await reject(
                        401,
                        "blocked",
                        f"JWT Validation Failed [{fail_code}] (OWASP API2): {jwt_res['reason']}",
                        "API2",
                        score,
                        pol_id,
                    )
                if pol_enabled and pol_mode == "monitor":
                    decision = "monitored"
                    block_reason = f"[Monitor Mode] JWT Validation Failed [{fail_code}]: {jwt_res['reason']}"
                    owasp_id = "API2"
                    threat_score = max(threat_score, score)
            elif api_key_header and not api_key_ok:
                if pol_enabled and pol_mode == "enforce":
                    return await reject(
                        401,
                        "blocked",
                        f"API Key Authentication Failed (OWASP API2): {api_key_msg}",
                        "API2",
                        75,
                        pol_id,
                    )
            elif auth_required and not has_bearer_header and not api_key_header:
                if pol_enabled and pol_mode == "enforce":
                    return await reject(
                        401,
                        "blocked",
                        "Missing Bearer JWT or X-API-Key on protected route (OWASP API2)",
                        "API2",
                        60,
                        pol_id,
                    )

        # Re-check blocklist now that user_sub / api_key_id are known
        if user_sub or api_key_id:
            blocked_principal = _is_blocked(session, client_ip, user_sub, api_key_id)
            if blocked_principal:
                return await reject(
                    403,
                    "blocked",
                    f"Principal '{blocked_principal.value}' is on the active blocklist: {blocked_principal.reason}",
                    blocked_principal.owasp_id or "API2",
                    95,
                )

        # STAGE 6: Authorization — BFLA Role/Scope Check (OWASP API5) & BOLA Ownership Check (OWASP API1)
        if matched_route:
            # 6a. Broken Function Level Authorization (API5) — role + scopes
            req_role = matched_route.required_role
            if req_role and (user_role or "").lower() not in (req_role.lower(), "admin"):
                pol_enabled, pol_mode, pol_id = check_policy_mode(session, "bfla", "API5")
                if pol_enabled and pol_mode == "enforce":
                    return await reject(
                        403,
                        "blocked",
                        f"BFLA Violation (OWASP API5): Route '{matched_route.path_pattern}' requires role='{req_role}', caller has role='{user_role or 'anonymous'}'",
                        "API5",
                        88,
                        pol_id,
                    )
                elif pol_enabled and pol_mode == "monitor":
                    decision = "monitored"
                    block_reason = f"[Monitor Mode] BFLA Violation on '{matched_route.path_pattern}' by role='{user_role}'"
                    owasp_id = "API5"
                    matched_policy_id = pol_id
                    threat_score = max(threat_score, 88)

            required_scopes: List[str] = []
            try:
                required_scopes = json.loads(matched_route.required_scopes_json or "[]")
            except Exception:
                required_scopes = []
            if required_scopes and (user_role or "").lower() != "admin":
                token_scopes = (decoded_jwt.get("payload") or {}).get("scopes") or []
                if isinstance(token_scopes, str):
                    token_scopes = [token_scopes]
                missing = [s for s in required_scopes if s not in token_scopes]
                if missing:
                    pol_enabled, pol_mode, pol_id = check_policy_mode(session, "bfla", "API5")
                    if pol_enabled and pol_mode == "enforce":
                        return await reject(
                            403,
                            "blocked",
                            f"BFLA Scope Violation (OWASP API5): Missing required scope(s) {missing} on '{matched_route.path_pattern}'",
                            "API5",
                            88,
                            pol_id,
                        )

            # 6b. Broken Object Level Authorization (API1)
            bola_ok, bola_err = check_bola_ownership(
                matched_route,
                path_params,
                user_sub,
                user_role,
                query_params=query_param_map,
                body_json=body_json,
                decoded_jwt=decoded_jwt.get("payload") or {},
            )
            if not bola_ok:
                pol_enabled, pol_mode, pol_id = check_policy_mode(session, "bola", "API1")
                if pol_enabled and pol_mode == "enforce":
                    return await reject(403, "blocked", bola_err or "BOLA Violation", "API1", 85, pol_id)
                elif pol_enabled and pol_mode == "monitor":
                    decision = "monitored"
                    block_reason = f"[Monitor Mode] {bola_err}"
                    owasp_id = "API1"
                    matched_policy_id = pol_id
                    threat_score = max(threat_score, 85)
            elif (
                matched_route.bola_check_enabled
                and path_params
                and resolve_bola_mode(matched_route) == BOLA_MODE_LEARNED_OWNER
            ):
                # Enumeration is only the resource-id simulation. User-id routes
                # (equals_sub) are the cross-user ownership check and stop at 403.
                bola_cfg = get_policy_config(session, "bola", "API1")
                max_ids = int(bola_cfg.get("max_distinct_ids_per_min", 5))
                owner_param = resolve_bola_owner_param(matched_route, path_params)
                obj_id = (
                    path_params.get(owner_param)
                    or path_params.get(getattr(matched_route, "bola_owner_param", "id") or "id")
                    or path_params.get("id")
                    or next(iter(path_params.values()), None)
                )
                if obj_id:
                    exceeded, distinct = track_bola_enumeration(
                        f"{upstream_id}:{client_ip}",
                        str(obj_id),
                        max_distinct=max_ids,
                    )
                    if exceeded:
                        pol_enabled, pol_mode, pol_id = check_policy_mode(session, "bola", "API1")
                        if pol_enabled and pol_mode == "enforce":
                            return await reject(
                                429,
                                "rate_limited",
                                f"BOLA ID enumeration blocked (OWASP API1): "
                                f"{distinct} distinct object IDs in 60s (limit={max_ids})",
                                "API1",
                                85,
                                pol_id,
                            )

        # STAGE 7: Rate Limiting & Sensitive Business Flow Velocity (OWASP API4 & API6)
        limit_rpm = matched_route.rate_limit_rpm if matched_route else 60
        burst_cap = matched_route.burst_capacity if matched_route else 15
        is_sensitive = matched_route.is_sensitive_flow if matched_route else False
        rl_owasp = "API6" if is_sensitive else "API4"
        rl_key = f"upstream-{upstream_id}:{client_ip}:{user_sub or 'anon'}:{matched_route.path_pattern if matched_route else norm_path}"

        if not is_swagger_doc_route:
            # API2: credential-stuffing / brute-force lockout on login & token endpoints
            if is_auth_bootstrap_route and method == "POST":
                auth_cfg = get_policy_config(session, "auth", "API2")
                max_fails = int(auth_cfg.get("max_login_failures", 5))
                fail_window = int(auth_cfg.get("login_failure_window_sec", 60))
                lock_key = f"login-fail:{upstream_id}:{client_ip}"
                login_ok, login_headers, login_meta = rate_limiter.check_and_consume(
                    key=lock_key,
                    limit_rpm=max_fails,
                    burst_capacity=max_fails,
                    window_seconds=fail_window,
                )
                rate_headers.update(login_headers)
                if not login_ok:
                    pol_enabled, pol_mode, pol_id = check_policy_mode(session, "auth", "API2")
                    if pol_enabled and pol_mode == "enforce":
                        return await reject(
                            429,
                            "rate_limited",
                            f"Login / credential-stuffing lockout (OWASP API2): >{max_fails} auth attempts in {fail_window}s from {client_ip}",
                            "API2",
                            80,
                            pol_id,
                            rate_headers,
                        )

            # Per-principal sensitive-flow daily/window cap (API6)
            if is_sensitive and method in ("POST", "PUT", "PATCH"):
                sens_cfg = get_policy_config(session, "rate_limit", "API6")
                sens_rpm = int(sens_cfg.get("max_rpm") or limit_rpm or 6)
                sens_burst = int(sens_cfg.get("burst") or burst_cap or 4)
                sens_key = f"sgw:sens:{upstream_id}:{user_sub or client_ip}:{matched_route.path_pattern if matched_route else norm_path}"
                sens_ok, sens_headers, sens_meta = rate_limiter.check_and_consume(
                    key=sens_key,
                    limit_rpm=sens_rpm,
                    burst_capacity=sens_burst,
                    window_seconds=60,
                )
                rate_headers.update(sens_headers)
                if not sens_ok:
                    pol_enabled, pol_mode, pol_id = check_policy_mode(session, "rate_limit", "API6")
                    if pol_enabled and pol_mode == "enforce":
                        return await reject(
                            429,
                            "rate_limited",
                            f"Sensitive business flow velocity exceeded (OWASP API6): {sens_meta.get('reason')}",
                            "API6",
                            75,
                            pol_id,
                            rate_headers,
                        )

            rl_allowed, rate_headers_main, rl_meta = rate_limiter.check_and_consume(
                key=rl_key,
                limit_rpm=limit_rpm,
                burst_capacity=burst_cap,
                window_seconds=60,
            )
            rate_headers.update(rate_headers_main)
            if not rl_allowed:
                pol_enabled, pol_mode, pol_id = check_policy_mode(session, "rate_limit", rl_owasp)
                if pol_enabled and pol_mode == "enforce":
                    return await reject(
                        429,
                        "rate_limited",
                        f"Rate/Velocity Limit Exceeded (OWASP {rl_owasp}): {rl_meta['reason']}",
                        rl_owasp,
                        70,
                        pol_id,
                        rate_headers,
                    )
                elif pol_enabled and pol_mode == "monitor":
                    decision = "monitored"
                    block_reason = f"[Monitor Mode] Rate Limit Exceeded: {rl_meta['reason']}"
                    owasp_id = rl_owasp
                    matched_policy_id = pol_id
                    threat_score = max(threat_score, 70)

        # STAGE 8: Payload & Signature Inspection (SSRF API7, Injection API8, Size/Limit API4, Mass Assignment API3)
        size_cfg = get_policy_config(session, "size_limit", "API4")
        rate_cfg = get_policy_config(session, "rate_limit", "API4")
        ssrf_cfg = get_policy_config(session, "ssrf", "API7")
        sig_cfg = get_policy_config(session, "signature", "API8")
        max_body = int(size_cfg.get("max_body_bytes") or rate_cfg.get("max_body_bytes") or 65536)
        max_page = int(size_cfg.get("max_page_limit") or rate_cfg.get("max_page_limit") or 100)

        inspection = (
            {"violation": False, "threat_score": 0}
            if is_swagger_doc_route
            else inspect_request_payload(
                path=norm_path,
                query_string=query_string,
                body_text=body_text,
                max_body_bytes=max_body,
                max_page_limit=max_page,
                request_schema_json=matched_route.request_schema_json if matched_route else None,
                headers=req_headers_dict,
                block_private_cidrs=bool(ssrf_cfg.get("block_private_cidrs", True)),
                block_metadata_ip=bool(ssrf_cfg.get("block_metadata_ip", True)),
                enable_sqli=bool(sig_cfg.get("sqli", True)),
                enable_xss=bool(sig_cfg.get("xss", True)),
                enable_path_traversal=bool(sig_cfg.get("path_traversal", True)),
                enable_cmd_injection=bool(sig_cfg.get("cmd_injection", True)),
            )
        )
        if inspection.get("violation"):
            insp_owasp = inspection["owasp_id"]
            insp_type = inspection["policy_type"]
            pol_enabled, pol_mode, pol_id = check_policy_mode(session, insp_type, insp_owasp)
            if pol_enabled and pol_mode == "enforce":
                return await reject(
                    inspection.get("http_status", 403),
                    "blocked",
                    inspection["reason"],
                    insp_owasp,
                    inspection.get("threat_score", 85),
                    pol_id,
                    rate_headers,
                )
            elif pol_enabled and pol_mode == "monitor":
                decision = "monitored"
                block_reason = f"[Monitor Mode] {inspection['reason']}"
                owasp_id = insp_owasp
                matched_policy_id = pol_id
                threat_score = max(threat_score, inspection.get("threat_score", 85))

        # STAGE 9: Circuit breaker + Forward to Upstream via Async HTTPX
        upstream_key = f"up-{upstream_id}"
        cb_ok, cb_reason = circuit_breaker.allow(upstream_key)
        if not cb_ok:
            return await reject(
                503,
                "blocked",
                f"Upstream circuit breaker open (OWASP API4): {cb_reason}",
                "API4",
                70,
            )

        resp_status, upstream_headers, raw_resp_body = await _forward_to_upstream(
            method, norm_path, query_string, req_headers_dict, raw_body_bytes, upstream, local_asgi_app, user_sub
        )
        if resp_status >= 500:
            circuit_breaker.record_failure(upstream_key)
        else:
            circuit_breaker.record_success(upstream_key)

        # STAGE 9b: OWASP API10 — unsafe consumption / third-party URL inspection on upstream responses
        if not is_swagger_doc_route and resp_status < 500:
            egress_cfg = get_policy_config(session, "egress", "API10")
            api10_hit = inspect_response_for_unsafe_urls(
                raw_resp_body,
                block_private_cidrs=bool(egress_cfg.get("block_private_cidrs", True)),
                block_metadata_ip=bool(egress_cfg.get("block_metadata_ip", True)),
            )
            if api10_hit:
                pol_enabled, pol_mode, pol_id = check_policy_mode(session, "egress", "API10")
                if pol_enabled and pol_mode == "enforce":
                    if egress_cfg.get("strip_unsafe_urls", True):
                        try:
                            parsed_resp = json.loads(raw_resp_body)
                            cleaned, stripped_paths = strip_unsafe_urls_from_json(
                                parsed_resp,
                                block_private_cidrs=bool(egress_cfg.get("block_private_cidrs", True)),
                                block_metadata_ip=bool(egress_cfg.get("block_metadata_ip", True)),
                            )
                            if stripped_paths:
                                raw_resp_body = json.dumps(cleaned)
                                owasp_id = "API10"
                                matched_policy_id = pol_id
                                threat_score = max(threat_score, 90)
                                block_reason = (
                                    block_reason
                                    or f"Stripped unsafe third-party URLs from upstream response: {', '.join(stripped_paths)} (OWASP API10)"
                                )
                        except Exception:
                            return await reject(
                                api10_hit.get("http_status", 502),
                                "blocked",
                                api10_hit["reason"],
                                "API10",
                                api10_hit.get("threat_score", 90),
                                pol_id,
                            )
                    else:
                        return await reject(
                            api10_hit.get("http_status", 502),
                            "blocked",
                            api10_hit["reason"],
                            "API10",
                            api10_hit.get("threat_score", 90),
                            pol_id,
                        )
                elif pol_enabled and pol_mode == "monitor":
                    decision = "monitored"
                    block_reason = f"[Monitor Mode] {api10_hit['reason']}"
                    owasp_id = "API10"
                    matched_policy_id = pol_id
                    threat_score = max(threat_score, 90)

        # STAGE 10: Response Hardening (API8 Headers & Error Sanitization + API3 JSON Field Redaction)
        redact_fields = ["password_hash", "ssn", "credit_card", "secret_note"]
        red_cfg = get_policy_config(session, "field_redaction", "API3")
        if red_cfg.get("redact_fields"):
            redact_fields = list(red_cfg["redact_fields"])
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
            max_response_bytes=int(settings.MAX_UPSTREAM_RESPONSE_BYTES),
        )
        hardened_body, hardened_headers, media_type = _rewrite_swagger_if_needed(
            norm_path, gw_prefix, hardened_body, hardened_headers, upstream, proj_registered_routes
        )
        if is_swagger_doc_route:
            resp_status = 200
        hardened_headers.update(rate_headers)
        hardened_headers["X-Request-ID"] = request_id
        hardened_headers["X-Gateway-Decision"] = decision

        # Learn object owners from successful GETs for future BOLA checks
        if (
            matched_route
            and matched_route.bola_check_enabled
            and method == "GET"
            and 200 <= resp_status < 300
            and user_sub
            and path_params
        ):
            owner_param = resolve_bola_owner_param(matched_route, path_params)
            obj_id = (
                path_params.get(owner_param)
                or path_params.get(getattr(matched_route, "bola_owner_param", "id") or "id")
                or path_params.get("id")
                or next(iter(path_params.values()), None)
            )
            if obj_id:
                remember_object_owner(upstream_id, matched_route.path_pattern, str(obj_id), user_sub)

        if redacted_fields and not owasp_id:
            owasp_id = "API3"
            matched_policy_id = red_pol_id

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        await _dispatch_record(
            background_tasks,
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
    # Trust only this project's configured upstream origin (e.g. localhost:8001).
    # Request-payload SSRF and redirects to other private hosts remain blocked.
    trusted_upstream = egress_trust_keys_for_base_url(base_url)
    egress_err = inspect_egress_destination(target_url, trusted_hosts=trusted_upstream)
    if egress_err:
        err_body = json.dumps({"error": "Forbidden Egress", "detail": egress_err})
        return 403, {"Content-Type": "application/json"}, err_body

    try:
        client = get_http_client()
        current_url = target_url
        resp = None
        for _hop in range(5):
            resp = await client.request(
                method=method,
                url=current_url,
                headers=forward_headers,
                content=body_bytes,
            )
            if resp.status_code not in (301, 302, 303, 307, 308):
                break
            location = resp.headers.get("location")
            if not location:
                break
            # Resolve relative redirects against current URL
            from urllib.parse import urljoin
            next_url = urljoin(current_url, location)
            # Same-origin upstream redirects are fine; cross-origin private/metadata still blocked
            pin_err = inspect_egress_destination(next_url, trusted_hosts=trusted_upstream)
            if pin_err:
                err_body = json.dumps({
                    "error": "Redirect Blocked",
                    "detail": f"Upstream redirect to restricted destination blocked (OWASP API7/API10): {pin_err}",
                })
                return 502, {"Content-Type": "application/json"}, err_body
            current_url = next_url
            if resp.status_code in (303,):
                method = "GET"
                body_bytes = b""
        assert resp is not None
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
        # Safe, non-stack message — helps diagnose Docker→host upstream misconfig
        # (e.g. Inventory base_url still pointing at 127.0.0.1 from inside a container).
        from urllib.parse import urlparse as _urlparse

        parsed_up = _urlparse(base_url if "://" in (base_url or "") else f"http://{base_url or ''}")
        up_host = parsed_up.hostname or "unknown-host"
        up_port = parsed_up.port or (443 if (parsed_up.scheme or "http").lower() == "https" else 80)
        hint = ""
        if up_host in ("127.0.0.1", "localhost"):
            hint = (
                " If SentinelGW runs in Docker, change this project's Backend URL in Inventory "
                "to http://host.docker.internal:PORT (or your host LAN IP), not 127.0.0.1."
            )
        err_body = json.dumps({
            "error": "Bad Gateway",
            "message": (
                f"Could not connect to upstream {up_host}:{up_port} "
                f"({type(exc).__name__}).{hint}"
            ),
            "detail": "Upstream connection failed",
        })
        return 502, {"Content-Type": "application/json", "X-Gateway-Upstream-Host": f"{up_host}:{up_port}"}, err_body


async def _reject_request(
    session: Session,
    background_tasks: Optional[BackgroundTasks],
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

    await _dispatch_record(
        background_tasks,
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


async def _dispatch_record(background_tasks: Optional[BackgroundTasks], **kwargs: Any) -> None:
    if background_tasks is not None:
        background_tasks.add_task(_record_and_detect_background, **kwargs)
        return
    with Session(engine) as session:
        await _record_and_detect(session=session, **kwargs)


async def _record_and_detect_background(**kwargs: Any) -> None:
    with Session(engine) as session:
        await _record_and_detect(session=session, **kwargs)


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
    if route_id:
        session.exec(
            update(Route)
            .where(Route.id == route_id)
            .values(hit_count=Route.hit_count + 1, last_seen_at=datetime.now(timezone.utc))
        )
    session.commit()
    session.refresh(log_entry)

    await process_request_event(session, log_entry)
