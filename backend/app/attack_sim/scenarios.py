import json
from typing import Any, Dict, List
import httpx
from app.gateway.auth import mint_demo_jwt
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


async def execute_attack_scenario(scenario_id: str, asgi_app: Any) -> Dict[str, Any]:
    """
    Executes one of the 8 scripted OWASP attack scenarios (or 'all') through /gw/*
    and returns rich step-by-step HTTP request/response logs for the Attack Simulator UI.
    """
    if scenario_id == "all":
        combined_steps = []
        for sc in SCENARIO_CATALOG:
            res = await execute_attack_scenario(sc["id"], asgi_app)
            combined_steps.extend(res["steps"])
        blocked = sum(1 for s in combined_steps if s["status_code"] in (400, 401, 403, 413, 429))
        return {
            "scenario_id": "all",
            "title": "Full 8-Scenario OWASP API Top 10 Attack Suite",
            "gateway_enabled": gateway_state.gateway_enabled,
            "total_requests": len(combined_steps),
            "blocked_count": blocked,
            "passed_through_count": len(combined_steps) - blocked,
            "steps": combined_steps,
        }

    user_jwt = mint_demo_jwt(sub="user-101", email="alice@vulnshop.io", role="user", preset="valid_user")["token"]
    alg_none_jwt = mint_demo_jwt(preset="alg_none")["token"]
    tampered_jwt = mint_demo_jwt(preset="tampered_sig")["token"]

    transport = httpx.ASGITransport(app=asgi_app)
    steps: List[Dict[str, Any]] = []

    async with httpx.AsyncClient(transport=transport, base_url="http://local-gateway") as client:
        if scenario_id == "bola_enum":
            attacker_ip = "198.51.100.101"
            for target_id in ["101", "102", "103", "104", "105", "106", "999"]:
                resp = await client.get(
                    f"/gw/users/{target_id}",
                    headers={
                        "Authorization": f"Bearer {user_jwt}",
                        "X-Simulated-Client-IP": attacker_ip,
                        "User-Agent": "BOLA-ScraperBot/2.1",
                    },
                )
                steps.append(_format_step(f"GET /gw/users/{target_id}", "API1", resp))

        elif scenario_id == "brute_force":
            attacker_ip = "203.0.113.42"
            usernames = ["alice_mercer", "bob_chen", "charlie_davis", "root_admin", "finance_lead", "devops_admin"]
            for idx, uname in enumerate(usernames):
                resp = await client.post(
                    "/gw/auth/login",
                    json={"username": uname, "password": f"wrongPass!{idx}"},
                    headers={
                        "X-Simulated-Client-IP": attacker_ip,
                        "User-Agent": "Hydra-CredentialStuffer/9.4",
                    },
                )
                steps.append(_format_step(f"POST /gw/auth/login (user={uname})", "API2", resp))

        elif scenario_id == "jwt_tamper":
            attacker_ip = "198.51.100.202"
            r1 = await client.get(
                "/gw/orders/5001",
                headers={
                    "Authorization": f"Bearer {alg_none_jwt}",
                    "X-Simulated-Client-IP": attacker_ip,
                    "User-Agent": "JWT-Tool-Exploiter/1.3",
                },
            )
            steps.append(_format_step("GET /gw/orders/5001 [alg=none Forged JWT]", "API2", r1))

            r2 = await client.get(
                "/gw/orders/5003",
                headers={
                    "Authorization": f"Bearer {tampered_jwt}",
                    "X-Simulated-Client-IP": attacker_ip,
                    "User-Agent": "JWT-Tool-Exploiter/1.3",
                },
            )
            steps.append(_format_step("GET /gw/orders/5003 [Tampered Signature role=admin]", "API2", r2))

        elif scenario_id == "data_exposure":
            attacker_ip = "198.51.100.150"
            r1 = await client.get(
                "/gw/users/me",
                headers={
                    "Authorization": f"Bearer {user_jwt}",
                    "X-Simulated-Client-IP": attacker_ip,
                },
            )
            steps.append(_format_step("GET /gw/users/me [Check API3 Response Field Redaction]", "API3", r1))

            r2 = await client.post(
                "/gw/auth/register",
                json={
                    "username": "evil_escalator",
                    "email": "evil@attacker.io",
                    "password": "hacked",
                    "role": "admin",
                },
                headers={"X-Simulated-Client-IP": attacker_ip},
            )
            steps.append(_format_step("POST /gw/auth/register [Mass Assignment role='admin']", "API3", r2))

        elif scenario_id == "rate_flood":
            attacker_ip = "203.0.113.88"
            rate_limiter.reset_key(f"{attacker_ip}:user-101:/coupons/redeem")
            for i in range(1, 9):
                r_coup = await client.post(
                    "/gw/coupons/redeem",
                    json={"code": f"PROMO50-{i}"},
                    headers={
                        "Authorization": f"Bearer {user_jwt}",
                        "X-Simulated-Client-IP": attacker_ip,
                        "User-Agent": "CouponScalperBot/4.0",
                    },
                )
                steps.append(_format_step(f"POST /gw/coupons/redeem (attempt #{i})", "API6", r_coup))

            r_page = await client.get(
                "/gw/products?limit=50000",
                headers={"X-Simulated-Client-IP": attacker_ip},
            )
            steps.append(_format_step("GET /gw/products?limit=50000 [Unbounded Pagination]", "API4", r_page))

        elif scenario_id == "bfla_admin":
            attacker_ip = "198.51.100.55"
            for i in range(1, 3):
                resp = await client.get(
                    "/gw/admin/users",
                    headers={
                        "Authorization": f"Bearer {user_jwt}",
                        "X-Simulated-Client-IP": attacker_ip,
                        "User-Agent": "PrivilegeScanner/1.0",
                    },
                )
                steps.append(_format_step(f"GET /gw/admin/users [Normal User Token #{i}]", "API5", resp))

        elif scenario_id == "ssrf_metadata":
            attacker_ip = "203.0.113.199"
            r1 = await client.get(
                "/gw/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                headers={
                    "Authorization": f"Bearer {user_jwt}",
                    "X-Simulated-Client-IP": attacker_ip,
                },
            )
            steps.append(_format_step("GET /gw/fetch?url=http://169.254.169.254/... [AWS Metadata SSRF]", "API7", r1))

            r2 = await client.get(
                "/gw/fetch?url=http://127.0.0.1:6379/info",
                headers={
                    "Authorization": f"Bearer {user_jwt}",
                    "X-Simulated-Client-IP": attacker_ip,
                },
            )
            steps.append(_format_step("GET /gw/fetch?url=http://127.0.0.1:6379/info [Loopback Redis SSRF]", "API7", r2))

        elif scenario_id == "sqli_shadow":
            attacker_ip = "203.0.113.250"
            r1 = await client.get(
                "/gw/search?q=' UNION SELECT username, password_hash FROM users --",
                headers={"X-Simulated-Client-IP": attacker_ip, "User-Agent": "sqlmap/1.8"},
            )
            steps.append(_format_step("GET /gw/search?q=' UNION SELECT ... [SQLi Payload]", "API8", r1))

            r2 = await client.get(
                "/gw/internal/debug",
                headers={"X-Simulated-Client-IP": attacker_ip, "User-Agent": "Nuclei-ShadowScanner/3.1"},
            )
            steps.append(_format_step("GET /gw/internal/debug [Undocumented Shadow API]", "API9", r2))

    meta = next((s for s in SCENARIO_CATALOG if s["id"] == scenario_id), SCENARIO_CATALOG[0])
    blocked = sum(1 for s in steps if s["status_code"] in (400, 401, 403, 413, 429))
    return {
        "scenario_id": scenario_id,
        "title": meta["title"],
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
    decision = resp.headers.get("X-Gateway-Decision", "allowed" if resp.status_code < 400 else "blocked")
    if redacted_hdr and resp.status_code == 200:
        decision = f"allowed (API3 redacted: {redacted_hdr})"

    return {
        "request": label,
        "owasp_id": owasp_id,
        "status_code": resp.status_code,
        "decision": decision,
        "request_id": resp.headers.get("X-Request-ID", "-"),
        "server_header": resp.headers.get("Server", "[Stripped by Gateway API8]"),
        "response_preview": preview,
    }
