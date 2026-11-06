import json
import re
from typing import Any, Dict, List, Optional, Tuple
import httpx
from sqlmodel import Session, select
from app.db import engine
from app.models import Route, Upstream
from app.gateway.auth import mint_demo_jwt, resolve_simulator_user_jwt, simulator_object_id
from app.gateway.pipeline import gateway_state
from app.gateway.policy_engine import (
    BOLA_MODE_EQUALS_SUB,
    BOLA_MODE_LEARNED_OWNER,
    is_resource_like_param,
    is_user_like_param,
    reset_bola_enumeration,
    resolve_bola_mode,
)
from app.gateway.ratelimit import rate_limiter
from app.attack_sim.targeting import (
    describe_plan,
    plan_scenario_targets,
    resolve_route_overrides,
)

SCENARIO_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "bola_cross_user",
        "title": "API1: Cross-User Object Access",
        "owasp_id": "API1",
        "severity": "high",
        "target_endpoint": "Auto: route whose path contains a user id",
        "description": "Authenticates as user id 2, reads that user's own id, then requests the same route for user ids 1, 3, 4, 5, 6, and 7. No request body is invented.",
        "expected_when_on": "200 on user 2's own id, then 403 Forbidden for every other user id",
        "expected_when_off": "Upstream response for the caller's own id and for each other user id",
    },
    {
        "id": "bola_enum",
        "title": "API1: BOLA ID Enumeration Blocked",
        "owasp_id": "API1",
        "severity": "high",
        "target_endpoint": "Auto: GET resource route (booking, order, …), not a user-id route",
        "description": "Reads resource id 2 as user 2, then requests resource ids 1, 3, 4, 5, and 6. The ID past the enumeration cap must be blocked. User-id routes are not used here.",
        "expected_when_on": "200 on the caller's own object id, then 429 once ID enumeration is blocked",
        "expected_when_off": "Upstream response for the caller's own object and for every other object ID",
    },
    {
        "id": "brute_force",
        "title": "API2: Credential Stuffing & Brute-Force Login",
        "owasp_id": "API2",
        "severity": "high",
        "target_endpoint": "Auto: project's POST login / jwt/login / token route",
        "description": "Fires 6 rapid failed login attempts (JSON or form-urlencoded per OpenAPI) against this project's real login endpoint.",
        "expected_when_on": "401 Unauthorized + triggers High-severity API2 Brute-Force Login Alert",
        "expected_when_off": "Unmonitored 401 responses with verbose server headers",
    },
    {
        "id": "jwt_tamper",
        "title": "API2: JWT alg=none & Signature Tampering",
        "owasp_id": "API2",
        "severity": "critical",
        "target_endpoint": "Auto: JWT-protected non-admin GET for this project",
        "description": "Sends unsigned alg=none and signature-tampered JWTs to a protected route selected from this project's inventory.",
        "expected_when_on": "401 Unauthorized (8-point JWT validator catches `jwt_alg_none` & `jwt_bad_signature` + raises Critical API2 Alert)",
        "expected_when_off": "200 OK — upstream accepts forged request without token verification",
    },
    {
        "id": "data_exposure",
        "title": "API3: Excessive Data Exposure & Mass Assignment",
        "owasp_id": "API3",
        "severity": "high",
        "target_endpoint": "Auto: profile/me read + register/write route",
        "description": "1) Profile/me redaction check. 2–3) Mass assignment against this project's register or schema-backed write route.",
        "expected_when_on": "Sensitive fields redacted; top-level and nested Mass Assignment blocked with 403",
        "expected_when_off": "Raw bcrypt hashes/SSN leaked; admin self-registration and nested privilege escalation succeed",
    },
    {
        "id": "rate_flood",
        "title": "API4: Unbounded Pagination Flood",
        "owasp_id": "API4",
        "severity": "medium",
        "target_endpoint": "Auto: collection GET (products/bookings/posts/…)",
        "description": "Requests unbounded pagination (`?limit=50000`) on this project's best list/collection endpoint.",
        "expected_when_on": "400 Bad Request on unbounded pagination (API4 size/pagination guard)",
        "expected_when_off": "200 OK with thousands of unthrottled product records",
    },
    {
        "id": "coupon_scalp",
        "title": "API6: Sensitive Coupon Velocity Scalping",
        "owasp_id": "API6",
        "severity": "high",
        "target_endpoint": "Auto: sensitive business flow (coupon/booking/payment/…)",
        "description": "Floods this project's sensitive-flow route (coupon, booking, payment, lock, …) — not login/register.",
        "expected_when_on": "429 Too Many Requests with Retry-After on coupon flood (API6 velocity)",
        "expected_when_off": "200 OK on all coupon redemptions (promo pool drained)",
    },
    {
        "id": "bfla_admin",
        "title": "API5: Broken Function Level Authorization (BFLA)",
        "owasp_id": "API5",
        "severity": "high",
        "target_endpoint": "Auto: required_role=admin route for this project",
        "description": "Uses a customer JWT to call this project's admin route (BFLA). Skipped if the project has no admin endpoints.",
        "expected_when_on": "403 Forbidden (BFLA role policy enforces `role == admin` + raises High API5 Alert)",
        "expected_when_off": "200 OK — dumps the entire user database and AWS IAM secrets to a regular user",
    },
    {
        "id": "ssrf_metadata",
        "title": "API7: Cloud Metadata Server-Side Request Forgery (SSRF)",
        "owasp_id": "API7",
        "severity": "critical",
        "target_endpoint": "Auto: /fetch or GET carrier with ?url=",
        "description": "Injects cloud-metadata and loopback URLs via ?url= on /fetch when present, else another safe GET carrier.",
        "expected_when_on": "403 Forbidden (SSRF inspector blocks private/link-local metadata IP + raises Critical API7 Alert)",
        "expected_when_off": "200 OK — leaks temporary AWS IAM SecretAccessKey and internal Redis cluster state",
    },
    {
        "id": "sqli_inject",
        "title": "API8: SQL Injection Signature Probe",
        "owasp_id": "API8",
        "severity": "high",
        "target_endpoint": "Auto: search/query or collection GET with ?q=",
        "description": "Injects SQLi payloads into this project's search route, or a collection GET via ?q=.",
        "expected_when_on": "403 Forbidden on SQLi signature (API8 normalized inspector)",
        "expected_when_off": "200 OK — dumps database rows via SQLi",
    },
    {
        "id": "shadow_scan",
        "title": "API9: Shadow / Undocumented Endpoint Scan",
        "owasp_id": "API9",
        "severity": "high",
        "target_endpoint": "GET /gw/internal/debug, /.env, /actuator/env",
        "description": "Probes undocumented debug and config endpoints outside the OpenAPI inventory.",
        "expected_when_on": "403 Forbidden on unregistered Shadow Endpoints (API9)",
        "expected_when_off": "200 OK — exposes production secrets from /internal/debug",
    },
    {
        "id": "unsafe_api_consume",
        "title": "API10: Unsafe Third-Party API Consumption",
        "owasp_id": "API10",
        "severity": "high",
        "target_endpoint": "Auto: supplier/catalog/third-party GET",
        "description": "Fetches this project's supplier/catalog/integration route for unsafe third-party URL consumption (API10).",
        "expected_when_on": "Unsafe URLs stripped or blocked (API10 egress/response inspector)",
        "expected_when_off": "200 OK — raw metadata webhook URLs passed through to the client",
    },
]


async def execute_attack_scenario(
    scenario_id: str,
    asgi_app: Any,
    upstream_id: int = 1,
    auth_token: Optional[str] = None,
    route_id: Optional[int] = None,
    route_overrides: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """
    Executes a scripted OWASP attack scenario (or 'all') through /gw/*
    and returns rich step-by-step HTTP request/response logs for the Attack Simulator UI.

    ``route_id`` / ``route_overrides`` let the operator manually pick inventory
    routes instead of relying solely on auto-targeting.
    """
    if scenario_id == "all":
        combined_steps = []
        project_name = f"Project {upstream_id}"
        for sc in SCENARIO_CATALOG:
            res = await execute_attack_scenario(
                sc["id"], asgi_app, upstream_id, auth_token, route_id=None, route_overrides=None
            )
            combined_steps.extend(res["steps"])
            project_name = res.get("project_name") or project_name
        blocked = sum(1 for s in combined_steps if s.get("blocked_by_gateway"))
        return {
            "scenario_id": "all",
            "title": "Full OWASP API Top 10 Attack Suite",
            "upstream_id": upstream_id,
            "project_name": project_name,
            "gateway_enabled": gateway_state.gateway_enabled,
            "total_requests": len(combined_steps),
            "blocked_count": blocked,
            "passed_through_count": len(combined_steps) - blocked,
            "steps": combined_steps,
        }

    # Legacy alias: sqli_shadow -> run both new scenarios
    if scenario_id == "sqli_shadow":
        a = await execute_attack_scenario(
            "sqli_inject", asgi_app, upstream_id, auth_token, route_id, route_overrides
        )
        b = await execute_attack_scenario(
            "shadow_scan", asgi_app, upstream_id, auth_token, None, None
        )
        steps = a["steps"] + b["steps"]
        blocked = sum(1 for s in steps if s.get("blocked_by_gateway"))
        return {
            **a,
            "scenario_id": "sqli_shadow",
            "title": "API8 & API9: SQL Injection & Shadow Debug Endpoint Scan",
            "owasp_id": "API8",
            "total_requests": len(steps),
            "blocked_count": blocked,
            "passed_through_count": len(steps) - blocked,
            "steps": steps,
        }

    with Session(engine) as session:
        upstream = session.get(Upstream, upstream_id)
        if not upstream:
            raise ValueError(f"Selected API project {upstream_id} was not found")
        routes = session.exec(
            select(Route).where(
                Route.upstream_id == upstream_id,
                Route.registered == True,
            )
        ).all()
        resolved = resolve_simulator_user_jwt(auth_token, session, upstream_id)
        subject = resolved["subject"]
        user_jwt = resolved["token"]
        user_two_jwt = mint_demo_jwt(
            sub="2",
            email="user2@sentinel.local",
            role="user",
            session=session,
            upstream_id=upstream_id,
        )["token"]
        alg_none_jwt = mint_demo_jwt(
            sub=subject, preset="alg_none", session=session, upstream_id=upstream_id
        )["token"]
        tampered_jwt = mint_demo_jwt(
            sub=subject, preset="tampered_sig", session=session, upstream_id=upstream_id
        )["token"]

    own_id = simulator_object_id(subject)
    overrides = resolve_route_overrides(scenario_id, route_id, route_overrides)
    plan = plan_scenario_targets(scenario_id, routes, overrides=overrides)

    prefix = f"/gw/{upstream.slug}"

    def gateway_url(path: str, query: str = "") -> str:
        clean = "/" + path.lstrip("/")
        return f"{prefix}{clean}{query}"

    def sim_headers(
        attacker_ip: str,
        token: str = user_jwt,
        user_agent: str = "SentinelGW-AttackSimulator/1.0",
    ) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "X-Simulated-Client-IP": attacker_ip,
            "User-Agent": user_agent,
        }

    def _path_params(pattern: str) -> List[str]:
        return re.findall(r"\{([^}]+)\}", pattern or "")

    def concrete(
        route: Route | None,
        value: str = "",
        fallback: str = "/",
        resource_id: Optional[str] = None,
    ) -> str:
        """
        Fill path templates without treating resource IDs as user IDs.
        User-like params get `value` (JWT-derived). Resource params get
        `resource_id` (or a stable placeholder), never the caller subject.
        """
        pattern = route.path_pattern if route else fallback
        params = _path_params(pattern)
        if not params:
            return pattern
        mode = resolve_bola_mode(route) if route else BOLA_MODE_EQUALS_SUB
        result = pattern
        for param in params:
            if is_user_like_param(param, pattern):
                fill = value or own_id
            elif is_resource_like_param(param, pattern) or mode == BOLA_MODE_LEARNED_OWNER:
                fill = resource_id or "1"
            else:
                fill = value or own_id
            result = result.replace("{" + param + "}", fill)
        return result

    # Bind selected routes from the project-aware plan
    bola_user_route = plan.route("user_route")
    bola_object_route = plan.route("object_route")
    login_route = plan.route("login")
    jwt_victim_route = plan.route("jwt_victim")
    read_route = plan.route("read")
    write_route = plan.route("write")
    list_route = plan.route("list")
    rate_route = plan.route("sensitive")
    admin_route = plan.route("admin")
    fetch_route = plan.route("fetch")
    search_route = plan.route("search")
    supplier_route = plan.route("supplier")

    ip_prefix = f"198.18.{(upstream_id % 240) + 1}"

    meta = next((s for s in SCENARIO_CATALOG if s["id"] == scenario_id), SCENARIO_CATALOG[0])
    target_summary = describe_plan(plan)

    if not plan.applicable:
        skip_step = {
            "request": f"SKIP {scenario_id} — no suitable route in '{upstream.name}'",
            "owasp_id": meta["owasp_id"],
            "status_code": 0,
            "decision": "not_applicable",
            "blocked_by_gateway": False,
            "request_id": "-",
            "server_header": "-",
            "response_preview": plan.skip_reason or "Scenario not applicable to this project",
            "target_selection": target_summary,
        }
        return {
            "scenario_id": scenario_id,
            "title": meta["title"],
            "upstream_id": upstream.id,
            "project_name": upstream.name,
            "project_slug": upstream.slug,
            "owasp_id": meta["owasp_id"],
            "gateway_enabled": gateway_state.gateway_enabled,
            "applicable": False,
            "skip_reason": plan.skip_reason,
            "target_selection": target_summary,
            "total_requests": 0,
            "blocked_count": 0,
            "passed_through_count": 0,
            "steps": [skip_step],
        }

    transport = httpx.ASGITransport(app=asgi_app)
    steps: List[Dict[str, Any]] = []

    async with httpx.AsyncClient(transport=transport, base_url="http://local-gateway") as client:
        if scenario_id == "bola_cross_user":
            attacker_ip = f"{ip_prefix}.2"
            bola_method = bola_user_route.method.upper() if bola_user_route else "GET"
            # Own id first, so the run shows one allowed request, then the other user ids.
            for target_user_id, kind in (
                ("2", "own user id"),
                ("1", "other user id"),
                ("3", "other user id"),
                ("4", "other user id"),
                ("5", "other user id"),
                ("6", "other user id"),
                ("7", "other user id"),
            ):
                target_path = concrete(bola_user_route, target_user_id, f"/users/{target_user_id}")
                resp = await client.request(
                    bola_method,
                    gateway_url(target_path),
                    headers=sim_headers(
                        attacker_ip,
                        token=user_two_jwt,
                        user_agent="SentinelGW-AttackSimulator/1.0",
                    ),
                )
                steps.append(
                    _format_step(
                        f"{bola_method} {gateway_url(target_path)} [caller=user 2, {kind}={target_user_id} | {plan.reason('user_route')}]",
                        "API1",
                        resp,
                    )
                )

        elif scenario_id == "bola_enum":
            attacker_ip = f"{ip_prefix}.101"
            reset_bola_enumeration(f"{upstream_id}:{attacker_ip}")
            bola_method = bola_object_route.method.upper() if bola_object_route else "GET"
            object_pattern = bola_object_route.path_pattern if bola_object_route else ""
            object_params = _path_params(object_pattern)
            resource_param = next(
                (name for name in object_params if is_resource_like_param(name, object_pattern)),
                object_params[0] if object_params else "id",
            )
            # Own object first. The cap is 5 distinct IDs, so the sixth ID must be blocked.
            for object_id, kind in (
                ("2", "own object id"),
                ("1", "other object id"),
                ("3", "other object id"),
                ("4", "other object id"),
                ("5", "other object id"),
                ("6", "other object id"),
            ):
                target_path = concrete(
                    bola_object_route,
                    "2",
                    f"/orders/{object_id}",
                    resource_id=object_id,
                )
                resp = await client.request(
                    bola_method,
                    gateway_url(target_path),
                    headers=sim_headers(
                        attacker_ip,
                        token=user_two_jwt,
                        user_agent="SentinelGW-AttackSimulator/1.0",
                    ),
                )
                steps.append(
                    _format_step(
                        f"{bola_method} {gateway_url(target_path)} [caller=user 2, {kind}={object_id} | {plan.reason('object_route')}]",
                        "API1",
                        resp,
                    )
                )

        elif scenario_id == "brute_force":
            attacker_ip = f"{ip_prefix}.42"
            rate_limiter.reset_key(f"login-fail:{upstream_id}:{attacker_ip}")
            rate_limiter.reset_key(f"login-fail:{attacker_ip}")
            login_path = concrete(login_route, own_id, "/auth/login")
            usernames = [
                "alice_mercer",
                "bob_chen",
                "charlie_davis",
                "root_admin",
                "finance_lead",
                "devops_admin",
            ]
            for idx, uname in enumerate(usernames):
                login_req = _resolve_login_request(
                    upstream, login_route, uname, f"wrongPass!{idx}"
                )
                headers = sim_headers(attacker_ip, user_agent="Hydra-CredentialStuffer/9.4")
                post_kwargs: Dict[str, Any] = {"headers": headers}
                if "data" in login_req:
                    post_kwargs["data"] = login_req["data"]
                else:
                    post_kwargs["json"] = login_req["json"]
                resp = await client.post(gateway_url(login_path), **post_kwargs)
                steps.append(
                    _format_step(
                        f"POST {gateway_url(login_path)} (user={uname}, {login_req['content_type']})",
                        "API2",
                        resp,
                    )
                )

        elif scenario_id == "jwt_tamper":
            attacker_ip = f"{ip_prefix}.202"
            victim_path = concrete(jwt_victim_route, own_id, "/users/me")
            victim_method = jwt_victim_route.method.upper() if jwt_victim_route else "GET"
            r1 = await client.request(
                victim_method,
                gateway_url(victim_path),
                headers=sim_headers(attacker_ip, token=alg_none_jwt, user_agent="JWT-Tool-Exploiter/1.3"),
            )
            steps.append(
                _format_step(
                    f"{victim_method} {gateway_url(victim_path)} [alg=none | {plan.reason('jwt_victim')}]",
                    "API2",
                    r1,
                )
            )
            r2 = await client.request(
                victim_method,
                gateway_url(victim_path),
                headers=sim_headers(attacker_ip, token=tampered_jwt, user_agent="JWT-Tool-Exploiter/1.3"),
            )
            steps.append(
                _format_step(
                    f"{victim_method} {gateway_url(victim_path)} [tampered role=admin]",
                    "API2",
                    r2,
                )
            )

        elif scenario_id == "data_exposure":
            attacker_ip = f"{ip_prefix}.150"
            read_path = concrete(read_route, own_id, "/users/me")
            write_path = concrete(write_route, own_id, "/auth/register")
            write_method = write_route.method.upper() if write_route else "POST"
            r1 = await client.get(gateway_url(read_path), headers=sim_headers(attacker_ip))
            steps.append(
                _format_step(
                    f"GET {gateway_url(read_path)} [redaction | {plan.reason('read')}]",
                    "API3",
                    r1,
                )
            )
            r2 = await client.request(
                write_method,
                gateway_url(write_path),
                json={
                    "username": "evil_escalator",
                    "email": "evil@attacker.io",
                    "password": "hacked",
                    "role": "admin",
                    "is_admin": True,
                },
                headers=sim_headers(attacker_ip),
            )
            steps.append(
                _format_step(
                    f"{write_method} {gateway_url(write_path)} [mass assignment | {plan.reason('write')}]",
                    "API3",
                    r2,
                )
            )
            r3 = await client.request(
                write_method,
                gateway_url(write_path),
                json={
                    "username": "nested_evil",
                    "email": "nested@attacker.io",
                    "password": "hacked",
                    "profile": {"role": "admin", "is_admin": True},
                },
                headers=sim_headers(attacker_ip),
            )
            steps.append(
                _format_step(
                    f"{write_method} {gateway_url(write_path)} [nested mass assignment]",
                    "API3",
                    r3,
                )
            )

        elif scenario_id == "rate_flood":
            attacker_ip = f"{ip_prefix}.88"
            list_path = concrete(list_route, own_id, "/products")
            r_page = await client.get(
                gateway_url(list_path, "?limit=50000"),
                headers=sim_headers(attacker_ip),
            )
            steps.append(
                _format_step(
                    f"GET {gateway_url(list_path, '?limit=50000')} [pagination | {plan.reason('list')}]",
                    "API4",
                    r_page,
                )
            )

        elif scenario_id == "coupon_scalp":
            attacker_ip = f"{ip_prefix}.89"
            rate_path = concrete(rate_route, own_id, "/coupons/redeem")
            rate_pattern = rate_route.path_pattern if rate_route else rate_path
            rate_limiter.reset_key(
                f"upstream-{upstream_id}:{attacker_ip}:{subject}:{rate_pattern}"
            )
            rate_limiter.reset_key(
                f"sgw:sens:{upstream_id}:{subject}:{rate_pattern}"
            )
            method = rate_route.method.upper() if rate_route else "POST"
            for i in range(1, 19):
                headers = sim_headers(attacker_ip, user_agent="SentinelGW-VelocityTester/4.0")
                if method in ("POST", "PUT", "PATCH"):
                    response = await client.request(
                        method,
                        gateway_url(rate_path),
                        json={"test_sequence": i, "code": f"SECURITY-TEST-{i}"},
                        headers=headers,
                    )
                else:
                    response = await client.get(gateway_url(rate_path), headers=headers)
                steps.append(
                    _format_step(
                        f"{method} {gateway_url(rate_path)} (attempt #{i} | {plan.reason('sensitive')})",
                        "API6",
                        response,
                    )
                )

        elif scenario_id == "bfla_admin":
            attacker_ip = f"{ip_prefix}.55"
            admin_path = concrete(admin_route, own_id, "/admin/users")
            admin_method = admin_route.method.upper() if admin_route else "GET"
            for i in range(1, 3):
                resp = await client.request(
                    admin_method,
                    gateway_url(admin_path),
                    headers=sim_headers(attacker_ip, user_agent="PrivilegeScanner/1.0"),
                )
                steps.append(
                    _format_step(
                        f"{admin_method} {gateway_url(admin_path)} [user token #{i} | {plan.reason('admin')}]",
                        "API5",
                        resp,
                    )
                )

        elif scenario_id == "ssrf_metadata":
            attacker_ip = f"{ip_prefix}.199"
            fetch_path = concrete(fetch_route, own_id, "/fetch")
            r1 = await client.get(
                gateway_url(
                    fetch_path,
                    "?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                ),
                headers=sim_headers(attacker_ip),
            )
            steps.append(
                _format_step(
                    f"GET {gateway_url(fetch_path)}?url=169.254.169.254 [{plan.reason('fetch')}]",
                    "API7",
                    r1,
                )
            )
            r2 = await client.get(
                gateway_url(fetch_path, "?url=http://127.0.0.1:6379/info"),
                headers=sim_headers(attacker_ip),
            )
            steps.append(
                _format_step(
                    f"GET {gateway_url(fetch_path)}?url=127.0.0.1:6379 [loopback SSRF]",
                    "API7",
                    r2,
                )
            )

        elif scenario_id == "sqli_inject":
            attacker_ip = f"{ip_prefix}.250"
            search_path = concrete(search_route, own_id, "/search")
            r1 = await client.get(
                gateway_url(
                    search_path,
                    "?q=' UNION SELECT username, password_hash FROM users --",
                ),
                headers=sim_headers(attacker_ip, user_agent="sqlmap/1.8"),
            )
            steps.append(
                _format_step(
                    f"GET {gateway_url(search_path)}?q=UNION SELECT [{plan.reason('search')}]",
                    "API8",
                    r1,
                )
            )
            r2 = await client.get(
                gateway_url(search_path, "?q=1' union/**/select null,null--"),
                headers=sim_headers(attacker_ip, user_agent="sqlmap/1.8"),
            )
            steps.append(
                _format_step(
                    f"GET {gateway_url(search_path)}?q=obfuscated SQLi",
                    "API8",
                    r2,
                )
            )

        elif scenario_id == "shadow_scan":
            attacker_ip = f"{ip_prefix}.251"
            for shadow_path in ("/internal/debug", "/.env", "/actuator/env"):
                resp = await client.get(
                    gateway_url(shadow_path),
                    headers={
                        **sim_headers(attacker_ip, user_agent="Nuclei-ShadowScanner/3.1"),
                        "X-Simulator-Shadow": "1",
                    },
                )
                steps.append(
                    _format_step(
                        f"GET {gateway_url(shadow_path)} [undocumented shadow API]",
                        "API9",
                        resp,
                    )
                )

        elif scenario_id == "unsafe_api_consume":
            attacker_ip = f"{ip_prefix}.210"
            supplier_path = concrete(supplier_route, own_id, "/supplier/catalog")
            resp = await client.get(
                gateway_url(supplier_path),
                headers=sim_headers(attacker_ip, user_agent="SupplierSyncBot/1.0"),
            )
            steps.append(
                _format_step(
                    f"GET {gateway_url(supplier_path)} [{plan.reason('supplier')}]",
                    "API10",
                    resp,
                )
            )

        else:
            raise ValueError(f"Unknown scenario_id: {scenario_id}")

    blocked = sum(1 for s in steps if s.get("blocked_by_gateway"))
    return {
        "scenario_id": scenario_id,
        "title": meta["title"],
        "upstream_id": upstream.id,
        "project_name": upstream.name,
        "project_slug": upstream.slug,
        "owasp_id": meta["owasp_id"],
        "gateway_enabled": gateway_state.gateway_enabled,
        "applicable": True,
        "target_selection": target_summary,
        "total_requests": len(steps),
        "blocked_count": blocked,
        "passed_through_count": len(steps) - blocked,
        "steps": steps,
    }


def _format_step(label: str, owasp_id: str, resp: httpx.Response) -> Dict[str, Any]:
    try:
        parsed_body = resp.json()
        preview = json.dumps(parsed_body, indent=2)[:650]
    except Exception:
        preview = resp.text[:650]

    redacted_hdr = resp.headers.get("X-Gateway-Redacted-Fields")
    decision = resp.headers.get("X-Gateway-Decision", "upstream_response")
    if redacted_hdr and resp.status_code == 200:
        decision = f"allowed (API3 redacted: {redacted_hdr})"

    protected = decision in ("blocked", "rate_limited")
    if "REDACTED BY GATEWAY" in preview or "STRIPPED BY GATEWAY API10" in preview:
        protected = True

    return {
        "request": label,
        "owasp_id": owasp_id,
        "status_code": resp.status_code,
        "decision": decision,
        "blocked_by_gateway": protected,
        "request_id": resp.headers.get("X-Request-ID", "-"),
        "server_header": resp.headers.get("Server", "[Stripped by Gateway API8]"),
        "response_preview": preview,
    }


def _resolve_login_request(
    upstream: Optional[Upstream],
    login_route: Optional[Route],
    username: str,
    password: str,
) -> Dict[str, Any]:
    """
    Build a login request matching the project's OpenAPI body contract.

    Parking-style OAuth2 password flows expect
    ``application/x-www-form-urlencoded`` with ``username``/``password``
    (optional ``grant_type=password``). VulnShop expects JSON. Sending the
    wrong content type yields FastAPI 422s that never look like auth failures.
    """
    content_type = "application/json"
    schema: Dict[str, Any] = {}
    if login_route and login_route.request_schema_json:
        try:
            loaded = json.loads(login_route.request_schema_json)
            if isinstance(loaded, dict):
                schema = loaded
        except Exception:
            schema = {}

    if upstream and upstream.openapi_spec_json and login_route:
        try:
            spec = json.loads(upstream.openapi_spec_json)
            path_item = (spec.get("paths") or {}).get(login_route.path_pattern) or {}
            op = path_item.get("post") or path_item.get("POST") or {}
            content = ((op.get("requestBody") or {}).get("content")) or {}
            if "application/x-www-form-urlencoded" in content:
                content_type = "application/x-www-form-urlencoded"
                media = content.get("application/x-www-form-urlencoded") or {}
                media_schema = media.get("schema")
                if isinstance(media_schema, dict) and media_schema.get("$ref"):
                    ref = media_schema["$ref"]
                    name = ref.rsplit("/", 1)[-1]
                    schema = ((spec.get("components") or {}).get("schemas") or {}).get(name) or schema
                elif isinstance(media_schema, dict):
                    schema = media_schema
            elif "multipart/form-data" in content:
                content_type = "multipart/form-data"
            elif "application/json" in content:
                content_type = "application/json"
        except Exception:
            pass

    props = schema.get("properties") or {}
    user_field = "username"
    for candidate in ("username", "email", "user", "login", "user_name"):
        if candidate in props:
            user_field = candidate
            break

    body: Dict[str, Any] = {user_field: username, "password": password}
    if "grant_type" in props:
        body["grant_type"] = "password"

    # Heuristic: OAuth2 password body schemas are almost always form-encoded
    title = str(schema.get("title") or "").lower()
    if content_type == "application/json" and (
        "grant_type" in props or "body_login" in title or "form" in title
    ):
        content_type = "application/x-www-form-urlencoded"

    if content_type in ("application/x-www-form-urlencoded", "multipart/form-data"):
        return {"data": body, "content_type": content_type}
    return {"json": body, "content_type": "application/json"}
