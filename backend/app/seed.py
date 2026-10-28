from datetime import datetime, timedelta, timezone
import json
import random
import uuid
from sqlmodel import Session, delete, select

from app.api.v1.deps import hash_password
from app.gateway.auth import hash_api_key
from app.models import (
    Alert,
    ApiKey,
    BlocklistEntry,
    ClientBaseline,
    Policy,
    RequestLog,
    RevokedToken,
    Route,
    Upstream,
    UpstreamJWTConfig,
    User,
)


def backfill_route_security_defaults(session: Session) -> None:
    """Apply safe inferred defaults to routes imported before metadata inference existed."""
    changed = False
    for route in session.exec(select(Route).where(Route.registered == True)).all():
        route_changed = False
        path_lower = route.path_pattern.lower()
        if "admin" in path_lower and route.required_role is None:
            route.required_role = "admin"
            route.auth_required = True
            route_changed = True
        if "{" in route.path_pattern and not route.bola_check_enabled:
            route.bola_check_enabled = True
            route_changed = True
        if any(
            key in path_lower
            for key in ("checkout", "order", "coupon", "payment", "transfer", "booking", "login")
        ) and not route.is_sensitive_flow:
            route.is_sensitive_flow = True
            route.rate_limit_rpm = min(route.rate_limit_rpm, 20)
            route.burst_capacity = min(route.burst_capacity, 5)
            route_changed = True
        if route_changed:
            session.add(route)
            changed = True
    if changed:
        session.commit()


def seed_all_data(session: Session, force_reset: bool = False) -> None:
    if not force_reset:
        existing_user = session.exec(select(User)).first()
        if existing_user:
            return

    if force_reset:
        for model in (
            Alert,
            RequestLog,
            BlocklistEntry,
            RevokedToken,
            ClientBaseline,
            ApiKey,
            Policy,
            Route,
            UpstreamJWTConfig,
            Upstream,
            User,
        ):
            session.exec(delete(model))
        session.commit()

    now = datetime.now(timezone.utc)

    # 1. Seed RBAC Users (4 distinct personas)
    default_pw = hash_password("sentinel123")
    users = [
        User(
            email="admin@sentinel.local",
            full_name="Elena Rostova (Platform Admin)",
            password_hash=default_pw,
            role="admin",
            is_active=True,
            last_login_at=now - timedelta(minutes=12),
        ),
        User(
            email="analyst@sentinel.local",
            full_name="Marcus Vance (SOC Lead Analyst)",
            password_hash=default_pw,
            role="analyst",
            is_active=True,
            last_login_at=now - timedelta(minutes=4),
        ),
        User(
            email="dev@sentinel.local",
            full_name="Priya Nair (API Owner & Architect)",
            password_hash=default_pw,
            role="developer",
            is_active=True,
            last_login_at=now - timedelta(hours=2),
        ),
        User(
            email="viewer@sentinel.local",
            full_name="David Sterling (Compliance Auditor)",
            password_hash=default_pw,
            role="viewer",
            is_active=True,
            last_login_at=now - timedelta(hours=6),
        ),
    ]
    for u in users:
        session.add(u)
    session.commit()

    # 2. Seed Protected Upstream (VulnShop Demo API)
    upstream = Upstream(
        name="VulnShop E-Commerce Core API",
        slug="vulnshop",
        base_url="http://127.0.0.1:8000/demo",
        auth_mode="both",
        enabled=True,
    )
    session.add(upstream)
    session.commit()
    session.refresh(upstream)

    # 3. Seed Registered Routes & Discovered Shadow Routes (OWASP API9)
    routes = [
        Route(
            upstream_id=upstream.id,
            method="POST",
            path_pattern="/auth/login",
            description="Customer & admin authentication endpoint issuing signed HS256 JWTs",
            auth_required=False,
            required_role=None,
            rate_limit_rpm=20,
            burst_capacity=8,
            is_sensitive_flow=True,
            bola_check_enabled=False,
            registered=True,
            hit_count=94,
            last_seen_at=now - timedelta(minutes=2),
        ),
        Route(
            upstream_id=upstream.id,
            method="POST",
            path_pattern="/auth/register",
            description="Customer registration endpoint (protected against API3 Mass Assignment)",
            auth_required=False,
            required_role=None,
            rate_limit_rpm=15,
            burst_capacity=5,
            is_sensitive_flow=True,
            bola_check_enabled=False,
            registered=True,
            hit_count=28,
            last_seen_at=now - timedelta(minutes=18),
        ),
        Route(
            upstream_id=upstream.id,
            method="GET",
            path_pattern="/users/me",
            description="Current user profile (protected by API3 response property redaction)",
            auth_required=True,
            required_role=None,
            rate_limit_rpm=60,
            burst_capacity=15,
            is_sensitive_flow=False,
            bola_check_enabled=False,
            registered=True,
            hit_count=62,
            last_seen_at=now - timedelta(minutes=5),
        ),
        Route(
            upstream_id=upstream.id,
            method="GET",
            path_pattern="/users/{id}",
            description="Fetch user profile by ID (protected by API1 BOLA sub=={id} ownership check)",
            auth_required=True,
            required_role=None,
            rate_limit_rpm=30,
            burst_capacity=10,
            is_sensitive_flow=False,
            bola_check_enabled=True,
            registered=True,
            hit_count=85,
            last_seen_at=now - timedelta(minutes=1),
        ),
        Route(
            upstream_id=upstream.id,
            method="GET",
            path_pattern="/admin/users",
            description="Administrative user directory dump (protected by API5 BFLA role=admin policy)",
            auth_required=True,
            required_role="admin",
            rate_limit_rpm=20,
            burst_capacity=5,
            is_sensitive_flow=False,
            bola_check_enabled=False,
            registered=True,
            hit_count=19,
            last_seen_at=now - timedelta(minutes=7),
        ),
        Route(
            upstream_id=upstream.id,
            method="POST",
            path_pattern="/orders",
            description="Create customer order (protected against API3 mass assignment & API6 bot velocity)",
            auth_required=True,
            required_role=None,
            rate_limit_rpm=25,
            burst_capacity=8,
            is_sensitive_flow=True,
            bola_check_enabled=False,
            registered=True,
            hit_count=51,
            last_seen_at=now - timedelta(minutes=9),
        ),
        Route(
            upstream_id=upstream.id,
            method="GET",
            path_pattern="/orders/{id}",
            description="Order detail lookup (protected by API1 BOLA ownership verification)",
            auth_required=True,
            required_role=None,
            rate_limit_rpm=40,
            burst_capacity=12,
            is_sensitive_flow=False,
            bola_check_enabled=True,
            registered=True,
            hit_count=44,
            last_seen_at=now - timedelta(minutes=11),
        ),
        Route(
            upstream_id=upstream.id,
            method="POST",
            path_pattern="/coupons/redeem",
            description="Promotional coupon redemption flow (strict API6 velocity & token bucket cap)",
            auth_required=True,
            required_role=None,
            rate_limit_rpm=6,
            burst_capacity=4,
            is_sensitive_flow=True,
            bola_check_enabled=False,
            registered=True,
            hit_count=39,
            last_seen_at=now - timedelta(minutes=3),
        ),
        Route(
            upstream_id=upstream.id,
            method="GET",
            path_pattern="/fetch",
            description="Remote supplier catalog fetcher (protected by API7 SSRF private/metadata blocker)",
            auth_required=True,
            required_role=None,
            rate_limit_rpm=20,
            burst_capacity=6,
            is_sensitive_flow=False,
            bola_check_enabled=False,
            registered=True,
            hit_count=22,
            last_seen_at=now - timedelta(minutes=6),
        ),
        Route(
            upstream_id=upstream.id,
            method="GET",
            path_pattern="/search",
            description="Product catalog search (protected by API8 SQLi/XSS/Traversal signature inspector)",
            auth_required=False,
            required_role=None,
            rate_limit_rpm=60,
            burst_capacity=20,
            is_sensitive_flow=False,
            bola_check_enabled=False,
            registered=True,
            hit_count=118,
            last_seen_at=now - timedelta(minutes=1),
        ),
        Route(
            upstream_id=upstream.id,
            method="GET",
            path_pattern="/products",
            description="Paginated product listing (protected by API4 max ?limit=100 pagination cap)",
            auth_required=False,
            required_role=None,
            rate_limit_rpm=60,
            burst_capacity=20,
            is_sensitive_flow=False,
            bola_check_enabled=False,
            registered=True,
            hit_count=145,
            last_seen_at=now - timedelta(minutes=1),
        ),
        # Shadow APIs (registered=False -> OWASP API9)
        Route(
            upstream_id=upstream.id,
            method="GET",
            path_pattern="/internal/debug",
            description="Discovered undocumented Shadow API endpoint leaking env vars (OWASP API9)",
            auth_required=True,
            registered=False,
            hit_count=14,
            last_seen_at=now - timedelta(minutes=8),
        ),
        Route(
            upstream_id=upstream.id,
            method="GET",
            path_pattern="/.env",
            description="Scanner probe for exposed dotenv configuration file (OWASP API9)",
            auth_required=True,
            registered=False,
            hit_count=9,
            last_seen_at=now - timedelta(minutes=25),
        ),
        Route(
            upstream_id=upstream.id,
            method="GET",
            path_pattern="/actuator/env",
            description="Automated recon probe targeting Spring Boot actuator endpoints (OWASP API9)",
            auth_required=True,
            registered=False,
            hit_count=6,
            last_seen_at=now - timedelta(hours=1),
        ),
    ]
    for r in routes:
        session.add(r)
    session.commit()

    # 4. Seed Security Policies (Mapped across OWASP API1..API9)
    policies = [
        Policy(
            name="BOLA Object Ownership & Enumeration Shield",
            description="Enforces JWT `sub` to path `{id}` ownership on /users/{id} and /orders/{id} and blocks sequential ID harvesting.",
            type="bola",
            scope="global",
            owasp_id="API1",
            mode="enforce",
            config_json=json.dumps({"enforce_sub_match": True, "max_distinct_ids_per_min": 5}),
            enabled=True,
        ),
        Policy(
            name="Strict 8-Point JWT & API Key Authentication",
            description="Pins HS256, rejects alg=none, verifies HMAC signature, checks exp/nbf/iat with 10s leeway, validates iss/aud, and enforces JTI revocation list.",
            type="auth",
            scope="global",
            owasp_id="API2",
            mode="enforce",
            config_json=json.dumps({"allowed_algorithms": ["HS256"], "reject_alg_none": True, "leeway_sec": 10}),
            enabled=True,
        ),
        Policy(
            name="Response Property Redaction & Mass Assignment Filter",
            description="Redacts `password_hash`, `ssn`, `credit_card`, and `secret_note` from JSON responses and blocks mass-assigned `role=admin` in request bodies.",
            type="field_redaction",
            scope="global",
            owasp_id="API3",
            mode="enforce",
            config_json=json.dumps({"redact_fields": ["password_hash", "ssn", "credit_card", "secret_note"]}),
            enabled=True,
        ),
        Policy(
            name="Hybrid Rate Limiter & Pagination / Payload Cap",
            description="Enforces Sliding Window Counter + Token Bucket burst limits, caps payload size at 64KB, and restricts `?limit=` pagination to <= 100.",
            type="rate_limit",
            scope="global",
            owasp_id="API4",
            mode="enforce",
            config_json=json.dumps({"max_body_bytes": 65536, "max_page_limit": 100}),
            enabled=True,
        ),
        Policy(
            name="Payload Size & Pagination Guard",
            description="Blocks oversized request bodies (>64KB) and unbounded pagination queries (?limit=50000).",
            type="size_limit",
            scope="global",
            owasp_id="API4",
            mode="enforce",
            config_json=json.dumps({"max_body_bytes": 65536, "max_page_limit": 100}),
            enabled=True,
        ),
        Policy(
            name="BFLA Role-to-Route Access Control",
            description="Restricts `/admin/*` endpoints strictly to principals carrying `role=admin` and flags privilege escalation probes.",
            type="bfla",
            scope="route",
            owasp_id="API5",
            mode="enforce",
            config_json=json.dumps({"admin_routes": ["/admin/users"], "required_role": "admin"}),
            enabled=True,
        ),
        Policy(
            name="Sensitive Business Flow Bot Velocity Limiter",
            description="Applies strict token bucket burst caps (6 RPM / 4 burst) on high-value flows (`/coupons/redeem`, `/orders`, `/auth/register`).",
            type="rate_limit",
            scope="route",
            owasp_id="API6",
            mode="enforce",
            config_json=json.dumps({"sensitive_routes": ["/coupons/redeem", "/orders"], "max_rpm": 6, "burst": 4}),
            enabled=True,
        ),
        Policy(
            name="SSRF Cloud Metadata & Internal Network Blocker",
            description="Blocks URL parameters and JSON fields targeting 169.254.169.254, localhost, 127.0.0.0/8, RFC1918 private subnets, and file/gopher schemes.",
            type="ssrf",
            scope="global",
            owasp_id="API7",
            mode="enforce",
            config_json=json.dumps({"block_metadata_ip": True, "block_private_cidrs": True}),
            enabled=True,
        ),
        Policy(
            name="SQLi / XSS / Path Traversal Signature Inspector",
            description="Scans URL path, query parameters, and JSON bodies for SQL injection, NoSQLi, XSS, path traversal, and OS command injection signatures.",
            type="signature",
            scope="global",
            owasp_id="API8",
            mode="enforce",
            config_json=json.dumps({"sqli": True, "xss": True, "path_traversal": True, "cmd_injection": True}),
            enabled=True,
        ),
        Policy(
            name="Response Security Headers & Error Sanitizer",
            description="Injects HSTS, CSP, X-Frame-Options, nosniff, strips `Server`/`X-Powered-By` banners, and sanitizes upstream 500 stack traces.",
            type="header_hardening",
            scope="global",
            owasp_id="API8",
            mode="enforce",
            config_json=json.dumps({"strip_banners": True, "inject_hsts_csp": True}),
            enabled=True,
        ),
        Policy(
            name="Shadow API & Undocumented Endpoint Blocker",
            description="Intercepts and blocks traffic targeting unregistered endpoints (`/internal/debug`, `/.env`) and logs them to the Shadow API inventory.",
            type="shadow_api",
            scope="global",
            owasp_id="API9",
            mode="enforce",
            config_json=json.dumps({"auto_discover": True, "block_unregistered": True}),
            enabled=True,
        ),
    ]
    for p in policies:
        session.add(p)
    session.commit()

    # 5. Seed API Keys & Revoked Tokens
    session.add(
        ApiKey(
            name="Mobile Storefront Partner Key",
            key_prefix="sgw_live_partner",
            hashed_key=hash_api_key("sgw_live_partner_demo_key_2026"),
            owner_email="dev@sentinel.local",
            role="user",
            scopes_json=json.dumps(["read:products", "read:orders"]),
            rate_limit_tier="standard",
            revoked=False,
        )
    )
    session.add(
        ApiKey(
            name="Legacy Billing Integration (Compromised)",
            key_prefix="sgw_live_legacy9",
            hashed_key=hash_api_key("sgw_live_legacy9_revoked_key"),
            owner_email="ops@vulnshop.io",
            role="user",
            scopes_json=json.dumps(["read:orders"]),
            rate_limit_tier="standard",
            revoked=True,
        )
    )
    session.add(
        RevokedToken(
            jti="jti-revoked-demo-token-001",
            user_sub="user-102",
            reason="Leaked in public GitHub gist — revoked by SOC Analyst",
            revoked_by="analyst@sentinel.local",
            revoked_at=now - timedelta(hours=3),
        )
    )
    session.add(
        BlocklistEntry(
            target_type="ip",
            value="185.220.101.44",
            reason="Automated Tor exit node credential stuffing campaign (OWASP API2)",
            owasp_id="API2",
            source="auto_rule",
            created_by="SentinelGW Auto-Defense",
            created_at=now - timedelta(hours=4),
            expires_at=now + timedelta(hours=20),
            active=True,
        )
    )
    session.commit()

    # 6. Seed 24h of Realistic Historical Traffic Logs (Allowed + Blocked Attacks across API1..API9)
    rng = random.Random(2026)
    benign_ips = ["172.56.21.14", "98.210.44.12", "73.162.88.91", "34.102.136.180", "52.14.99.201"]
    benign_routes = [
        ("GET", "/products", "limit=20", "user-101", "user", 200),
        ("GET", "/search", "q=security+key", "user-102", "user", 200),
        ("GET", "/users/me", "", "user-101", "user", 200),
        ("GET", "/users/101", "", "user-101", "user", 200),
        ("GET", "/orders/5001", "", "user-101", "user", 200),
        ("POST", "/orders", "", "user-102", "user", 200),
    ]

    attack_templates = [
        {
            "ip": "198.51.100.101",
            "sub": "user-101",
            "role": "user",
            "method": "GET",
            "path": "/users/104",
            "qs": "",
            "status": 403,
            "decision": "blocked",
            "owasp": "API1",
            "score": 88,
            "reason": "BOLA Violation (OWASP API1): Principal 'user-101' attempted unauthorized access to object ID '104' on '/users/{id}'",
            "body": "",
        },
        {
            "ip": "203.0.113.42",
            "sub": None,
            "role": None,
            "method": "POST",
            "path": "/auth/login",
            "qs": "",
            "status": 401,
            "decision": "blocked",
            "owasp": "API2",
            "score": 82,
            "reason": "Brute-force / credential stuffing failed login attempt against VulnShop DB",
            "body": '{"username": "root_admin", "password": "Password123!"}',
        },
        {
            "ip": "198.51.100.202",
            "sub": "admin-999",
            "role": "admin",
            "method": "GET",
            "path": "/orders/5003",
            "qs": "",
            "status": 401,
            "decision": "blocked",
            "owasp": "API2",
            "score": 96,
            "reason": "JWT Validation Failed [jwt_alg_none] (OWASP API2): Rejected alg=none unsigned JWT attack",
            "body": "",
        },
        {
            "ip": "198.51.100.150",
            "sub": None,
            "role": None,
            "method": "POST",
            "path": "/auth/register",
            "qs": "",
            "status": 403,
            "decision": "blocked",
            "owasp": "API3",
            "score": 85,
            "reason": "Blocked Mass Assignment attempt: client tried to self-assign 'role=admin' (OWASP API3)",
            "body": '{"username": "rogue_admin", "email": "rogue@evil.io", "role": "admin"}',
        },
        {
            "ip": "203.0.113.88",
            "sub": "user-103",
            "role": "user",
            "method": "GET",
            "path": "/products",
            "qs": "limit=50000",
            "status": 400,
            "decision": "blocked",
            "owasp": "API4",
            "score": 68,
            "reason": "Unrestricted pagination parameter 'limit=50000' exceeds gateway cap (100)",
            "body": "",
        },
        {
            "ip": "198.51.100.55",
            "sub": "user-102",
            "role": "user",
            "method": "GET",
            "path": "/admin/users",
            "qs": "",
            "status": 403,
            "decision": "blocked",
            "owasp": "API5",
            "score": 90,
            "reason": "BFLA Violation (OWASP API5): Route '/admin/users' requires role='admin', caller has role='user'",
            "body": "",
        },
        {
            "ip": "203.0.113.88",
            "sub": "user-103",
            "role": "user",
            "method": "POST",
            "path": "/coupons/redeem",
            "qs": "",
            "status": 429,
            "decision": "rate_limited",
            "owasp": "API6",
            "score": 76,
            "reason": "Rate/Velocity Limit Exceeded (OWASP API6): Token bucket burst capacity exhausted on sensitive flow",
            "body": '{"code": "WELCOME50"}',
        },
        {
            "ip": "203.0.113.199",
            "sub": "user-101",
            "role": "user",
            "method": "GET",
            "path": "/fetch",
            "qs": "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "status": 403,
            "decision": "blocked",
            "owasp": "API7",
            "score": 98,
            "reason": "SSRF attempt targeting internal/metadata host '169.254.169.254' (OWASP API7)",
            "body": "",
        },
        {
            "ip": "203.0.113.250",
            "sub": None,
            "role": None,
            "method": "GET",
            "path": "/search",
            "qs": "q=' UNION SELECT username, password_hash FROM users --",
            "status": 403,
            "decision": "blocked",
            "owasp": "API8",
            "score": 92,
            "reason": "SQL Injection (SQLi) payload signature detected in request",
            "body": "",
        },
        {
            "ip": "203.0.113.250",
            "sub": None,
            "role": None,
            "method": "GET",
            "path": "/internal/debug",
            "qs": "",
            "status": 403,
            "decision": "blocked",
            "owasp": "API9",
            "score": 82,
            "reason": "Shadow API Protection (OWASP API9): Unregistered endpoint 'GET /internal/debug' is not in the API route inventory",
            "body": "",
        },
    ]

    sample_attack_req_ids: dict[str, list[str]] = {tpl["owasp"]: [] for tpl in attack_templates}

    # Generate 240 requests spread over the last 24 hours
    for i in range(240):
        mins_ago = int((240 - i) * 5.8)
        ts = now - timedelta(minutes=mins_ago, seconds=rng.randint(0, 50))
        req_id = f"req-{uuid.uuid4().hex[:10]}"

        if i % 3 != 0:
            # Benign traffic
            method, path, qs, sub, role, status = rng.choice(benign_routes)
            ip = rng.choice(benign_ips)
            is_api3_redacted = path == "/users/me"
            session.add(
                RequestLog(
                    ts=ts,
                    request_id=req_id,
                    client_ip=ip,
                    user_sub=sub,
                    user_role=role,
                    method=method,
                    path=path,
                    query_params=qs,
                    request_headers_json=json.dumps({
                        "Host": "gateway.sentinel.local",
                        "Authorization": "Bearer eyJhbGciOiJIUzI1...9fK2",
                        "User-Agent": "Mozilla/5.0 (SentinelClient/2.4)",
                    }),
                    request_body_preview='{"item": "Hardware Security Key v2", "total": 59.99}' if method == "POST" else "",
                    response_body_preview='{"id": "101", "username": "alice_mercer", "password_hash": "[REDACTED BY GATEWAY API3 POLICY]"}' if is_api3_redacted else '{"status": "ok"}',
                    decoded_jwt_json=json.dumps({
                        "header": {"alg": "HS256", "typ": "JWT", "kid": "vulnshop-key-2026"},
                        "payload": {"sub": sub, "role": role, "iss": "https://auth.vulnshop.internal", "aud": "vulnshop-api"},
                    }),
                    status_code=status,
                    latency_ms=round(rng.uniform(1.4, 7.8), 2),
                    req_size_bytes=rng.randint(120, 950),
                    resp_size_bytes=rng.randint(420, 2400),
                    user_agent="Mozilla/5.0 (SentinelClient/2.4)",
                    decision="allowed",
                    block_reason="Redacted excessive fields: credit_card, password_hash, secret_note, ssn (OWASP API3)" if is_api3_redacted else None,
                    owasp_id="API3" if is_api3_redacted else None,
                    threat_score=10 if is_api3_redacted else 0,
                    anomaly_zscore=round(rng.uniform(0.1, 1.2), 2),
                )
            )
        else:
            # Malicious traffic
            tpl = attack_templates[i % len(attack_templates)]
            sample_attack_req_ids[tpl["owasp"]].append(req_id)
            session.add(
                RequestLog(
                    ts=ts,
                    request_id=req_id,
                    client_ip=tpl["ip"],
                    user_sub=tpl["sub"],
                    user_role=tpl["role"],
                    method=tpl["method"],
                    path=tpl["path"],
                    query_params=tpl["qs"],
                    request_headers_json=json.dumps({
                        "Host": "gateway.sentinel.local",
                        "X-Forwarded-For": tpl["ip"],
                        "User-Agent": "Nuclei-AttackerSim/3.1",
                    }),
                    request_body_preview=tpl["body"],
                    response_body_preview=json.dumps({
                        "error": "Gatekeeper Security Enforcement",
                        "status": tpl["status"],
                        "owasp_category": tpl["owasp"],
                        "reason": tpl["reason"],
                    }),
                    decoded_jwt_json=json.dumps({
                        "header": {"alg": "none" if "alg_none" in tpl["reason"] else "HS256"},
                        "payload": {"sub": tpl["sub"] or "anonymous", "role": tpl["role"] or "none"},
                    }),
                    status_code=tpl["status"],
                    latency_ms=round(rng.uniform(0.6, 2.9), 2),
                    req_size_bytes=rng.randint(180, 1400),
                    resp_size_bytes=260,
                    user_agent="Nuclei-AttackerSim/3.1",
                    decision=tpl["decision"],
                    block_reason=tpl["reason"],
                    owasp_id=tpl["owasp"],
                    threat_score=tpl["score"],
                    anomaly_zscore=round(rng.uniform(2.8, 4.9), 2),
                )
            )
    session.commit()

    # 7. Seed Client Anomaly Baselines
    baselines = [
        ClientBaseline(client_key="203.0.113.88", window_counts_json="[5,6,5,7,6,48,52]", mean_rpm=6.2, std_rpm=2.1, current_rpm=52, last_zscore=4.65),
        ClientBaseline(client_key="198.51.100.101", window_counts_json="[4,5,4,6,5,36,40]", mean_rpm=5.0, std_rpm=1.8, current_rpm=40, last_zscore=3.92),
        ClientBaseline(client_key="203.0.113.42", window_counts_json="[3,4,5,4,4,28,32]", mean_rpm=4.1, std_rpm=1.5, current_rpm=32, last_zscore=3.45),
        ClientBaseline(client_key="user-101", window_counts_json="[8,9,7,8,9,10,8]", mean_rpm=8.4, std_rpm=1.2, current_rpm=9, last_zscore=0.50),
        ClientBaseline(client_key="user-102", window_counts_json="[5,6,5,4,6,5,6]", mean_rpm=5.3, std_rpm=1.1, current_rpm=6, last_zscore=0.63),
    ]
    for b in baselines:
        session.add(b)
    session.commit()

    # 8. Seed Rich OWASP Alerts with Pre-Populated AI Triage Summaries
    seeded_alerts = [
        Alert(
            ts=now - timedelta(minutes=6),
            updated_at=now - timedelta(minutes=6),
            severity="critical",
            type="ssrf_attempt",
            owasp_id="API7",
            title="Server-Side Request Forgery (SSRF) Targeting AWS EC2 Metadata (169.254.169.254)",
            description="Blocked SSRF payload from 203.0.113.199 on 'GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'.",
            client_ip="203.0.113.199",
            user_sub="user-101",
            target_path="/fetch",
            event_count=8,
            status="open",
            assigned_to="analyst@sentinel.local",
            related_request_ids_json=json.dumps(sample_attack_req_ids.get("API7", [])[:8]),
            evidence_json=json.dumps({
                "method": "GET",
                "path": "/fetch",
                "query_params": "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "status_code": 403,
                "decision": "blocked",
                "block_reason": "SSRF attempt targeting internal/metadata host '169.254.169.254' (OWASP API7)",
            }),
            ai_summary_json=json.dumps({
                "engine": "SentinelAI Neural Threat Triage Engine",
                "confidence_score": 98,
                "executive_summary": "Critical SSRF exploitation attempt from IP 203.0.113.199 attempting to extract AWS IAM Instance Profile credentials via the link-local metadata service (169.254.169.254). All 8 requests were intercepted and blocked at the gateway perimeter.",
                "attack_classification": "Cloud Metadata SSRF (API7:2023 - Server Side Request Forgery)",
                "owasp_mapping": "API7:2023 - Server-Side Request Forgery",
                "root_cause_analysis": "Upstream `/fetch` endpoint fetches arbitrary URLs supplied in the `url` query parameter without egress allowlisting or link-local IP filtering.",
                "blast_radius": "Contained at gateway edge (0 bytes exfiltrated). Without gateway protection, temporary AWS IAM AccessKeyId and SecretAccessKey are leaked.",
                "recommended_actions": [
                    "Immediately block offending source IP '203.0.113.199' for 24 hours.",
                    "Revoke active JWT tokens associated with compromised principal 'user-101'.",
                    "Keep the API7 SSRF Cloud Metadata policy in strict 'Enforce' mode.",
                    "Enforce IMDSv2 hop-limit=1 and strict domain allowlisting in the upstream VulnShop fetcher.",
                ],
            }),
        ),
        Alert(
            ts=now - timedelta(minutes=11),
            updated_at=now - timedelta(minutes=11),
            severity="critical",
            type="jwt_tampering",
            owasp_id="API2",
            title="Cryptographic JWT Forgery (`alg=none` & Tampered Signature) from 198.51.100.202",
            description="Client submitted unsigned `alg=none` and modified-payload JWT tokens attempting administrative impersonation on /orders/5003.",
            client_ip="198.51.100.202",
            user_sub="admin-999",
            target_path="/orders/5003",
            event_count=9,
            status="open",
            assigned_to="analyst@sentinel.local",
            related_request_ids_json=json.dumps(sample_attack_req_ids.get("API2", [])[:8]),
            evidence_json=json.dumps({
                "method": "GET",
                "path": "/orders/5003",
                "status_code": 401,
                "decision": "blocked",
                "block_reason": "JWT Validation Failed [jwt_alg_none] (OWASP API2): Rejected alg=none unsigned JWT attack",
            }),
            ai_summary_json=json.dumps({
                "engine": "SentinelAI Neural Threat Triage Engine",
                "confidence_score": 97,
                "executive_summary": "Attacker at 198.51.100.202 attempted to bypass JWT verification by stripping the HMAC signature and setting header `alg: none` while elevating claim `role: admin`. Blocked by Step 2 of the gateway's 8-point JWT checklist.",
                "attack_classification": "JWT Algorithm Downgrade & Forgery (API2:2023 - Broken Authentication)",
                "owasp_mapping": "API2:2023 - Broken Authentication",
                "root_cause_analysis": "Adversary probing for unpinned JWT verification libraries that honor the token header's `alg` field.",
                "blast_radius": "Contained at gateway edge (all 9 forged tokens rejected with 401 Unauthorized).",
                "recommended_actions": [
                    "Block source IP '198.51.100.202' on the gateway blocklist.",
                    "Keep algorithm pinning strictly locked to ['HS256'] in Authentication Settings.",
                    "Audit all active admin sessions for abnormal JTI reuse.",
                ],
            }),
        ),
        Alert(
            ts=now - timedelta(minutes=19),
            updated_at=now - timedelta(minutes=19),
            severity="high",
            type="bola_enumeration",
            owasp_id="API1",
            title="BOLA Object ID Enumeration & Ownership Violation on /users/{id}",
            description="Principal 'user-101' (198.51.100.101) probed multiple customer IDs (/users/102..108) violating JWT sub=={id} ownership policy.",
            client_ip="198.51.100.101",
            user_sub="user-101",
            target_path="/users/104",
            event_count=12,
            status="investigating",
            assigned_to="analyst@sentinel.local",
            related_request_ids_json=json.dumps(sample_attack_req_ids.get("API1", [])[:8]),
            evidence_json=json.dumps({
                "method": "GET",
                "path": "/users/104",
                "status_code": 403,
                "decision": "blocked",
                "block_reason": "BOLA Violation (OWASP API1): Principal 'user-101' attempted unauthorized access to object ID '104'",
            }),
            ai_summary_json=json.dumps({
                "engine": "SentinelAI Neural Threat Triage Engine",
                "confidence_score": 94,
                "executive_summary": "Authenticated user 'user-101' performed sequential horizontal ID enumeration across `/users/{id}` to harvest other customers' PII. Blocked by the Gateway BOLA ownership rule.",
                "attack_classification": "Horizontal Privilege Escalation / IDOR (API1:2023 - BOLA)",
                "owasp_mapping": "API1:2023 - Broken Object Level Authorization",
                "root_cause_analysis": "Upstream `/users/{id}` handler looks up records by primary key without verifying caller ownership.",
                "blast_radius": "Zero records leaked (blocked with 403 Forbidden at Stage 6).",
                "recommended_actions": [
                    "Suspend or block principal 'user-101' and revoke their active JWT JTI.",
                    "Migrate upstream user identifiers from sequential integers to UUIDv4.",
                    "Maintain BOLA ownership enforcement on `/users/{id}` and `/orders/{id}`.",
                ],
            }),
        ),
        Alert(
            ts=now - timedelta(minutes=27),
            updated_at=now - timedelta(minutes=27),
            severity="high",
            type="bfla_privilege_probe",
            owasp_id="API5",
            title="BFLA Privilege Escalation Probe on Admin Endpoint (/admin/users)",
            description="Non-admin principal 'user-102' (role=user) attempted to invoke administrative function 'GET /admin/users'.",
            client_ip="198.51.100.55",
            user_sub="user-102",
            target_path="/admin/users",
            event_count=7,
            status="open",
            related_request_ids_json=json.dumps(sample_attack_req_ids.get("API5", [])[:7]),
            evidence_json=json.dumps({
                "method": "GET",
                "path": "/admin/users",
                "status_code": 403,
                "decision": "blocked",
                "block_reason": "BFLA Violation (OWASP API5): Route '/admin/users' requires role='admin', caller has role='user'",
            }),
            ai_summary_json=json.dumps({
                "engine": "SentinelAI Neural Threat Triage Engine",
                "confidence_score": 93,
                "executive_summary": "Standard customer token ('user-102', role='user') repeatedly probed `/admin/users`. The gateway enforced RBAC policy and rejected the vertical privilege escalation attempt.",
                "attack_classification": "Vertical Privilege Escalation (API5:2023 - BFLA)",
                "owasp_mapping": "API5:2023 - Broken Function Level Authorization",
                "root_cause_analysis": "Upstream `/admin/users` endpoint lacks an internal role check decorator.",
                "blast_radius": "Contained at gateway edge.",
                "recommended_actions": [
                    "Block source IP 198.51.100.55 and audit account 'user-102'.",
                    "Verify all `/admin/*` routes require `role=admin` in the Route Inventory.",
                ],
            }),
        ),
        Alert(
            ts=now - timedelta(minutes=34),
            updated_at=now - timedelta(minutes=34),
            severity="high",
            type="injection_signature",
            owasp_id="API8",
            title="SQL Injection (UNION SELECT) & Shadow Debug Endpoint Recon",
            description="Signature inspector blocked SQLi payload on 'GET /search' and shadow API probe on 'GET /internal/debug' from 203.0.113.250.",
            client_ip="203.0.113.250",
            user_sub=None,
            target_path="/search",
            event_count=11,
            status="open",
            related_request_ids_json=json.dumps(sample_attack_req_ids.get("API8", [])[:8]),
            evidence_json=json.dumps({
                "method": "GET",
                "path": "/search",
                "query_params": "q=' UNION SELECT username, password_hash FROM users --",
                "status_code": 403,
                "decision": "blocked",
                "block_reason": "SQL Injection (SQLi) payload signature detected in request",
            }),
            ai_summary_json=json.dumps({
                "engine": "SentinelAI Neural Threat Triage Engine",
                "confidence_score": 95,
                "executive_summary": "Automated vulnerability scanner (sqlmap / Nuclei) at 203.0.113.250 launched UNION-based SQL injection attacks against `/search` and probed undocumented `/internal/debug`.",
                "attack_classification": "SQL Injection & Shadow Endpoint Recon (API8 & API9)",
                "owasp_mapping": "API8:2023 - Security Misconfiguration / Injection",
                "root_cause_analysis": "Unparameterized string concatenation in upstream search query and exposed debug handler.",
                "blast_radius": "Blocked at Stage 4 & Stage 8 before reaching upstream database.",
                "recommended_actions": [
                    "Block scanner IP 203.0.113.250.",
                    "Permanently block `/internal/debug` in the Shadow API Inventory tab.",
                ],
            }),
        ),
        Alert(
            ts=now - timedelta(minutes=48),
            updated_at=now - timedelta(minutes=48),
            severity="high",
            type="sensitive_flow_abuse",
            owasp_id="API6",
            title="Automated Coupon Scalping Bot Velocity Abuse (/coupons/redeem)",
            description="High-velocity automated requests from 203.0.113.88 exceeded token bucket burst capacity on sensitive flow '/coupons/redeem' (Z-score = 4.65).",
            client_ip="203.0.113.88",
            user_sub="user-103",
            target_path="/coupons/redeem",
            event_count=14,
            status="open",
            related_request_ids_json=json.dumps(sample_attack_req_ids.get("API6", [])[:8]),
            evidence_json=json.dumps({
                "method": "POST",
                "path": "/coupons/redeem",
                "status_code": 429,
                "decision": "rate_limited",
                "block_reason": "Rate/Velocity Limit Exceeded (OWASP API6): Token bucket burst capacity exhausted",
            }),
            ai_summary_json=json.dumps({
                "engine": "SentinelAI Neural Threat Triage Engine",
                "confidence_score": 92,
                "executive_summary": "Client 203.0.113.88 spiked to 52 RPM (4.65 standard deviations above baseline) attempting to drain promotional coupon codes on `/coupons/redeem`. Throttled with HTTP 429.",
                "attack_classification": "Automated Business Flow Scalping (API6:2023)",
                "owasp_mapping": "API6:2023 - Unrestricted Access to Sensitive Business Flows",
                "root_cause_analysis": "Upstream coupon endpoint lacks per-account redemption velocity locks.",
                "blast_radius": "Promo pool protected after initial burst of 4 requests.",
                "recommended_actions": [
                    "Maintain strict 6 RPM / 4 burst limit on `/coupons/redeem`.",
                    "Block IP 203.0.113.88 if automated retries persist.",
                ],
            }),
        ),
    ]
    for al in seeded_alerts:
        session.add(al)
    session.commit()
