from datetime import datetime, timezone
import json
import time
import uuid
from typing import Any, Dict, Optional, Tuple
from fastapi import Request, Response
import httpx
from sqlmodel import Session, select

from app.config import settings
from app.db import engine
from app.models import BlocklistEntry, RequestLog, Route, Upstream
from app.gateway.auth import validate_jwt_checklist, verify_api_key
from app.gateway.ratelimit import rate_limiter
from app.gateway.inspector import inspect_request_payload
from app.gateway.policy_engine import check_bola_ownership, check_policy_mode, find_matching_route
from app.gateway.responses import harden_response


class GatewayRuntimeState:
    """Global runtime switches controllable from the Dashboard / Attack Simulator."""
    def __init__(self):
        self.gateway_enabled: bool = True
        self.auto_block_critical: bool = settings.AUTO_BLOCK_CRITICAL
        self.auto_block_duration_minutes: int = settings.AUTO_BLOCK_DURATION_MINUTES
        self.anomaly_zscore_threshold: float = 3.0


gateway_state = GatewayRuntimeState()


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

        # Allow routing to any specific registered project via /gw/{upstream_slug}/{rest_of_path}
        parts = [p for p in norm_path.split("/") if p]
        if parts:
            matched_by_slug = next((u for u in all_upstreams if u.slug.lower() == parts[0].lower()), None)
            if matched_by_slug:
                upstream = matched_by_slug
                norm_path = "/" + "/".join(parts[1:])

        upstream_id = upstream.id if upstream else 1

        # Pre-extract JWT claims if present so even early stages know user_sub
        auth_header = request.headers.get("Authorization", "")
        api_key_header = request.headers.get("X-API-Key", "")

        # STAGE 2: Master Gateway Bypass Toggle (for live Attack Simulator ON/OFF comparison)
        if not gateway_state.gateway_enabled:
            resp_status, resp_headers, resp_body = await _forward_to_upstream(
                method, norm_path, query_string, dict(request.headers), raw_body_bytes, upstream, local_asgi_app, user_sub
            )
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
            return Response(content=resp_body, status_code=resp_status, headers=resp_headers, media_type="application/json")

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
        matched_route, path_params = find_matching_route(session, upstream_id, method, norm_path)
        if matched_route:
            route_id = matched_route.id
            matched_route.hit_count = (matched_route.hit_count or 0) + 1
            matched_route.last_seen_at = datetime.now(timezone.utc)
            session.add(matched_route)
            session.commit()
        else:
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
        auth_required = matched_route.auth_required if matched_route else True
        if norm_path in ("/auth/login", "/auth/register", "/products", "/search"):
            auth_required = matched_route.auth_required if matched_route else False

        if auth_header or api_key_header or auth_required:
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
                    jwt_res = validate_jwt_checklist(auth_header, session)
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
            if req_role and req_role == "admin" and user_role != "admin":
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
        rl_key = f"{client_ip}:{user_sub or 'anon'}:{matched_route.path_pattern if matched_route else norm_path}"

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
        inspection = inspect_request_payload(
            method=method,
            path=norm_path,
            query_string=query_string,
            headers=dict(request.headers),
            body_text=body_text,
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
            enable_field_redaction=(red_pol_enabled and red_pol_mode == "enforce"),
        )
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
            media_type="application/json",
        )


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
        if k.lower() not in ("host", "content-length")
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
                timeout=5.0,
            )
            return resp.status_code, dict(resp.headers), resp.text

    target_url = base_url.rstrip("/") + full_path_with_qs
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.request(
                method=method,
                url=target_url,
                headers=forward_headers,
                content=body_bytes,
            )
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
