import json
import re
from typing import Any, Dict, List
import httpx
from sqlmodel import Session, select
from app.db import engine
from app.models import Route, Upstream
from app.gateway.auth import infer_simulator_subject, mint_demo_jwt, simulator_object_id
from app.gateway.pipeline import gateway_state
from app.gateway.ratelimit import rate_limiter

SCENARIO_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "bola_enum",
        "title": "API1: BOLA Object ID Enumeration",
        "owasp_id": "API1",
        "severity": "high",
        "target_endpoint": "GET /gw/users/{101..108}",
        "description": "Authenticates as Alice (user-101) and iterates across other customers' user IDs (102..108) to harvest PII, SSNs, and credit cards.",
        "expected_when_on": "403 Forbidden (BOLA ownership rule blocks access to other user IDs + raises API1 enumeration alert)",
        "expected_when_off": "200 OK — leaks full customer records including password hashes, SSNs, and credit cards",
    },
    {
        "id": "brute_force",
        "title": "API2: Credential Stuffing & Brute-Force Login",
        "owasp_id": "API2",
        "severity": "high",
        "target_endpoint": "POST /gw/auth/login",
        "description": "Fires 6 rapid failed login attempts with credential stuffing payloads from attacker IP 203.0.113.42.",
        "expected_when_on": "401 Unauthorized + triggers High-severity API2 Brute-Force Login Alert",
        "expected_when_off": "Unmonitored 401 responses with verbose server headers",
    },
    {
        "id": "jwt_tamper",
        "title": "API2: JWT alg=none & Signature Tampering",
        "owasp_id": "API2",
        "severity": "critical",
        "target_endpoint": "GET /gw/orders/5001",
        "description": "Sends both an unsigned `alg: none` JWT and a payload-tampered JWT (`role=admin`) without valid HMAC signature.",
        "expected_when_on": "401 Unauthorized (8-point JWT validator catches `jwt_alg_none` & `jwt_bad_signature` + raises Critical API2 Alert)",
        "expected_when_off": "200 OK — upstream accepts forged request without token verification",
    },
    {
        "id": "data_exposure",
        "title": "API3: Excessive Data Exposure & Mass Assignment",
        "owasp_id": "API3",
        "severity": "high",
        "target_endpoint": "GET /gw/users/me & POST /gw/auth/register",
        "description": "1) Calls `/gw/users/me` to inspect if `password_hash`, `ssn`, and `credit_card` are redacted. 2) Attempts Mass Assignment `role='admin'` on `/gw/auth/register`.",
        "expected_when_on": "Sensitive response fields replaced with `[REDACTED BY GATEWAY API3 POLICY]`; Mass Assignment blocked with 403",
        "expected_when_off": "Raw bcrypt `password_hash`, `ssn`, and `credit_card` leaked in plaintext JSON; admin self-registration succeeds",
    },
    {
        "id": "rate_flood",
        "title": "API4 & API6: Coupon Bot Velocity & Pagination Flood",
        "owasp_id": "API6",
        "severity": "high",
        "target_endpoint": "POST /gw/coupons/redeem & GET /gw/products?limit=50000",
        "description": "Floods the sensitive coupon redemption flow with rapid automated requests and requests `?limit=50000` products.",
        "expected_when_on": "429 Too Many Requests with `Retry-After` headers on coupon flood; 400 Bad Request on unbounded pagination",
        "expected_when_off": "200 OK on all coupon redemptions (promo pool drained) and 2,500+ unthrottled product records returned",
    },
    {
        "id": "bfla_admin",
        "title": "API5: Broken Function Level Authorization (BFLA)",
        "owasp_id": "API5",
        "severity": "high",
        "target_endpoint": "GET /gw/admin/users",
        "description": "Uses a standard customer JWT (`role=user`) to invoke the privileged `/gw/admin/users` administrative endpoint.",
        "expected_when_on": "403 Forbidden (BFLA role policy enforces `role == admin` + raises High API5 Alert)",
        "expected_when_off": "200 OK — dumps the entire user database and AWS IAM secrets to a regular user",
    },
    {
        "id": "ssrf_metadata",
        "title": "API7: Cloud Metadata Server-Side Request Forgery (SSRF)",
        "owasp_id": "API7",
        "severity": "critical",
        "target_endpoint": "GET /gw/fetch?url=http://169.254.169.254/latest/meta-data/iam/...",
        "description": "Supplies AWS EC2 Instance Metadata URL (`169.254.169.254`) and internal Redis loopback URL (`http://127.0.0.1:6379`) to `/gw/fetch`.",
        "expected_when_on": "403 Forbidden (SSRF inspector blocks private/link-local metadata IP + raises Critical API7 Alert)",
        "expected_when_off": "200 OK — leaks temporary AWS IAM `SecretAccessKey` and internal Redis cluster state",
    },
    {
        "id": "sqli_shadow",
        "title": "API8 & API9: SQL Injection & Shadow Debug Endpoint Scan",
        "owasp_id": "API8",
        "severity": "high",
        "target_endpoint": "GET /gw/search?q=' UNION SELECT... & GET /gw/internal/debug",
        "description": "Injects `' UNION SELECT username, password_hash FROM users --` into `/gw/search` and probes undocumented `/gw/internal/debug`.",
        "expected_when_on": "403 Forbidden on both SQLi signature (API8) and undocumented Shadow Endpoint (API9)",
        "expected_when_off": "200 OK — dumps database rows via SQLi and exposes production Stripe/PostgreSQL secrets from `/internal/debug`",
    },
]


async def execute_attack_scenario(
    scenario_id: str,
    asgi_app: Any,
    upstream_id: int = 1,
) -> Dict[str, Any]:
    """
    Executes one of the 8 scripted OWASP attack scenarios (or 'all') through /gw/*
    and returns rich step-by-step HTTP request/response logs for the Attack Simulator UI.
    """
    if scenario_id == "all":
        combined_steps = []
        for sc in SCENARIO_CATALOG:
            res = await execute_attack_scenario(sc["id"], asgi_app, upstream_id)
            combined_steps.extend(res["steps"])
        blocked = sum(1 for s in combined_steps if s.get("blocked_by_gateway"))
        return {
            "scenario_id": "all",
            "title": "Full 8-Scenario OWASP API Top 10 Attack Suite",
            "upstream_id": upstream_id,
            "project_name": res["project_name"] if SCENARIO_CATALOG else f"Project {upstream_id}",
            "gateway_enabled": gateway_state.gateway_enabled,
            "total_requests": len(combined_steps),
            "blocked_count": blocked,
            "passed_through_count": len(combined_steps) - blocked,
            "steps": combined_steps,
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
        subject = infer_simulator_subject(session, upstream_id)
        user_jwt = mint_demo_jwt(
            sub=subject,
            email="alice@sentinel.local",
            role="user",
            preset="valid_user",
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
    neighbor_ids = [str(int(own_id) + offset) for offset in range(1, 7)] + ["999"]

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

    def choose_route(
        keywords: tuple[str, ...] = (),
        methods: tuple[str, ...] = (),
        parameterized: bool = False,
        prefer_admin: bool = False,
    ) -> Route | None:
        candidates = [
            route for route in routes
            if (not methods or route.method.upper() in methods)
            and (not parameterized or "{" in route.path_pattern)
        ]
        if not candidates:
            candidates = [
                route for route in routes
                if not methods or route.method.upper() in methods
            ]
        if not candidates:
            candidates = routes
        if not candidates:
            return None

        def score(route: Route) -> int:
            text = f"{route.path_pattern} {route.description}".lower()
            value = sum(10 for keyword in keywords if keyword in text)
            if prefer_admin and (route.required_role == "admin" or "admin" in text):
                value += 30
            if parameterized and "{" in route.path_pattern:
                value += 20
            return value

        return max(candidates, key=score)

    def concrete(route: Route | None, value: str = "", fallback: str = "/") -> str:
        pattern = route.path_pattern if route else fallback
        return re.sub(r"\{[^}]+\}", value or own_id, pattern)

    bola_route = next(
        (
            route for route in routes
            if "{" in route.path_pattern
            and route.bola_check_enabled
            and route.required_role != "admin"
        ),
        None,
    ) or choose_route(("user", "order", "account", "item"), (), True)
    login_route = choose_route(("login", "auth", "token", "session"), ("POST",))
    read_route = choose_route(("profile", "user", "account", "customer"), ("GET",))
    write_route = choose_route(("register", "user", "profile", "account"), ("POST", "PUT", "PATCH"))
    rate_route = next((route for route in routes if route.is_sensitive_flow), None) or choose_route(
        ("checkout", "order", "coupon", "payment", "search"), ("POST", "GET")
    )
    admin_route = choose_route(("admin", "audit", "manage", "internal"), (), prefer_admin=True)
    generic_get = choose_route((), ("GET",)) or (routes[0] if routes else None)

    targets = {
        "bola": concrete(bola_route, neighbor_ids[0], f"/users/{neighbor_ids[0]}"),
        "login": concrete(login_route, own_id, "/auth/login"),
        "read": concrete(read_route, own_id, "/users/me"),
        "write": concrete(write_route, own_id, "/auth/register"),
        "rate": concrete(rate_route, own_id, "/products"),
        "admin": concrete(admin_route, own_id, "/admin/users"),
        "generic": concrete(generic_get, own_id, "/search"),
        "shadow": "/sentinel-security-test/undocumented-probe",
    }
    # Keep simulated offenders isolated per API project so one project's auto-block
    # does not change another project's test results.
    ip_prefix = f"198.18.{(upstream_id % 240) + 1}"

    transport = httpx.ASGITransport(app=asgi_app)
    steps: List[Dict[str, Any]] = []

    async with httpx.AsyncClient(transport=transport, base_url="http://local-gateway") as client:
        if scenario_id == "bola_enum":
            attacker_ip = f"{ip_prefix}.101"
            for target_id in [own_id, *neighbor_ids]:
                target_path = concrete(bola_route, target_id, targets["bola"])
                bola_method = bola_route.method.upper() if bola_route else "GET"
                resp = await client.request(
                    bola_method,
                    gateway_url(target_path),
                    headers=sim_headers(attacker_ip, user_agent="BOLA-ScraperBot/2.1"),
                )
                steps.append(_format_step(f"{bola_method} {gateway_url(target_path)}", "API1", resp))

        elif scenario_id == "brute_force":
            attacker_ip = f"{ip_prefix}.42"
            usernames = ["alice_mercer", "bob_chen", "charlie_davis", "root_admin", "finance_lead", "devops_admin"]
            for idx, uname in enumerate(usernames):
                resp = await client.post(
                    gateway_url(targets["login"]),
                    json={"username": uname, "password": f"wrongPass!{idx}"},
                    headers=sim_headers(attacker_ip, user_agent="Hydra-CredentialStuffer/9.4"),
                )
                steps.append(_format_step(f"POST {gateway_url(targets['login'])} (user={uname})", "API2", resp))

        elif scenario_id == "jwt_tamper":
            attacker_ip = f"{ip_prefix}.202"
            r1 = await client.get(
                gateway_url(targets["generic"]),
                headers=sim_headers(attacker_ip, token=alg_none_jwt, user_agent="JWT-Tool-Exploiter/1.3"),
            )
            steps.append(_format_step(f"GET {gateway_url(targets['generic'])} [alg=none Forged JWT]", "API2", r1))

            r2 = await client.get(
                gateway_url(targets["generic"]),
                headers=sim_headers(attacker_ip, token=tampered_jwt, user_agent="JWT-Tool-Exploiter/1.3"),
            )
            steps.append(_format_step(f"GET {gateway_url(targets['generic'])} [Tampered Signature role=admin]", "API2", r2))

        elif scenario_id == "data_exposure":
            attacker_ip = f"{ip_prefix}.150"
            r1 = await client.get(
                gateway_url(targets["read"]),
                headers=sim_headers(attacker_ip),
            )
            steps.append(_format_step(f"GET {gateway_url(targets['read'])} [Check API3 Response Field Redaction]", "API3", r1))

            write_method = write_route.method.upper() if write_route else "POST"
            r2 = await client.request(
                write_method,
                gateway_url(targets["write"]),
                json={
                    "username": "evil_escalator",
                    "email": "evil@attacker.io",
                    "password": "hacked",
                    "role": "admin",
                    "is_admin": True,
                },
                headers=sim_headers(attacker_ip),
            )
            steps.append(_format_step(f"{write_method} {gateway_url(targets['write'])} [Mass Assignment is_admin=true]", "API3", r2))

        elif scenario_id == "rate_flood":
            attacker_ip = f"{ip_prefix}.88"
            rate_limiter.reset_key(
                f"upstream-{upstream_id}:{attacker_ip}:{subject}:"
                f"{rate_route.path_pattern if rate_route else targets['rate']}"
            )
            for i in range(1, 19):
                method = rate_route.method.upper() if rate_route else "GET"
                headers = sim_headers(attacker_ip, user_agent="SentinelGW-VelocityTester/4.0")
                if method in ("POST", "PUT", "PATCH"):
                    response = await client.request(
                        method,
                        gateway_url(targets["rate"]),
                        json={"test_sequence": i, "code": f"SECURITY-TEST-{i}"},
                        headers=headers,
                    )
                else:
                    response = await client.get(gateway_url(targets["rate"]), headers=headers)
                steps.append(_format_step(f"{method} {gateway_url(targets['rate'])} (attempt #{i})", "API6", response))

            r_page = await client.get(
                gateway_url(targets["generic"], "?limit=50000"),
                headers=sim_headers(attacker_ip),
            )
            steps.append(_format_step(f"GET {gateway_url(targets['generic'], '?limit=50000')} [Unbounded Pagination]", "API4", r_page))

        elif scenario_id == "bfla_admin":
            attacker_ip = f"{ip_prefix}.55"
            for i in range(1, 3):
                admin_method = admin_route.method.upper() if admin_route else "GET"
                resp = await client.request(
                    admin_method,
                    gateway_url(targets["admin"]),
                    headers=sim_headers(attacker_ip, user_agent="PrivilegeScanner/1.0"),
                )
                steps.append(_format_step(f"{admin_method} {gateway_url(targets['admin'])} [Normal User Token #{i}]", "API5", resp))

        elif scenario_id == "ssrf_metadata":
            attacker_ip = f"{ip_prefix}.199"
            r1 = await client.get(
                gateway_url(targets["generic"], "?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
                headers=sim_headers(attacker_ip),
            )
            steps.append(_format_step(f"GET {gateway_url(targets['generic'])}?url=169.254.169.254 [AWS Metadata SSRF]", "API7", r1))

            r2 = await client.get(
                gateway_url(targets["generic"], "?url=http://127.0.0.1:6379/info"),
                headers=sim_headers(attacker_ip),
            )
            steps.append(_format_step(f"GET {gateway_url(targets['generic'])}?url=127.0.0.1:6379 [Loopback Redis SSRF]", "API7", r2))

        elif scenario_id == "sqli_shadow":
            attacker_ip = f"{ip_prefix}.250"
            r1 = await client.get(
                gateway_url(targets["generic"], "?q=' UNION SELECT username, password_hash FROM users --"),
                headers=sim_headers(attacker_ip, user_agent="sqlmap/1.8"),
            )
            steps.append(_format_step(f"GET {gateway_url(targets['generic'])}?q=' UNION SELECT ... [SQLi Payload]", "API8", r1))

            r2 = await client.get(
                gateway_url(targets["shadow"]),
                headers={
                    **sim_headers(attacker_ip, user_agent="Nuclei-ShadowScanner/3.1"),
                    "X-Simulator-Shadow": "1",
                },
            )
            steps.append(_format_step(f"GET {gateway_url(targets['shadow'])} [Undocumented Shadow API]", "API9", r2))

    meta = next((s for s in SCENARIO_CATALOG if s["id"] == scenario_id), SCENARIO_CATALOG[0])
    blocked = sum(1 for s in steps if s.get("blocked_by_gateway"))
    return {
        "scenario_id": scenario_id,
        "title": meta["title"],
        "upstream_id": upstream.id,
        "project_name": upstream.name,
        "project_slug": upstream.slug,
        "owasp_id": meta["owasp_id"],
        "gateway_enabled": gateway_state.gateway_enabled,
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

    return {
        "request": label,
        "owasp_id": owasp_id,
        "status_code": resp.status_code,
        "decision": decision,
        "blocked_by_gateway": decision in ("blocked", "rate_limited"),
        "request_id": resp.headers.get("X-Request-ID", "-"),
        "server_header": resp.headers.get("Server", "[Stripped by Gateway API8]"),
        "response_preview": preview,
    }
