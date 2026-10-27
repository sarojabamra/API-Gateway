from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from sqlmodel import Session, select
from app.db import get_session
from app.models import Alert, Policy, RequestLog

router = APIRouter(prefix="/owasp", tags=["OWASP API Top 10 (2023) Coverage"])

OWASP_TOP_10_2023: List[Dict[str, Any]] = [
    {
        "owasp_id": "API1",
        "code": "API1:2023",
        "title": "Broken Object Level Authorization (BOLA)",
        "risk_summary": "Attackers substitute object IDs in URL paths (/users/{id}, /orders/{id}) to access other users' records.",
        "gateway_mitigation": "Enforces JWT `sub` to path `{id}` ownership binding and detects high-velocity sequential ID enumeration across routes.",
        "demo_endpoint": "GET /gw/users/{id}, GET /gw/orders/{id}",
        "simulator_scenario": "bola_enum",
        "in_scope": True,
    },
    {
        "owasp_id": "API2",
        "code": "API2:2023",
        "title": "Broken Authentication",
        "risk_summary": "Weak JWT verification (alg=none, unverified signatures, expired/revoked tokens) and credential stuffing/brute force on login.",
        "gateway_mitigation": "8-step cryptographic JWT checklist (alg pinning, kid registry, exp/iss/aud, JTI revocation list) + login brute-force & credential stuffing detection.",
        "demo_endpoint": "POST /gw/auth/login, All Protected Routes",
        "simulator_scenario": "jwt_tamper",
        "in_scope": True,
    },
    {
        "owasp_id": "API3",
        "code": "API3:2023",
        "title": "Broken Object Property Level Authorization",
        "risk_summary": "Excessive data exposure in API responses (leaking password_hash, SSN, credit_card) and Mass Assignment of privileged fields.",
        "gateway_mitigation": "Response JSON property redaction filter strips sensitive fields automatically; request inspector blocks mass-assigned `role=admin` / `is_admin` fields.",
        "demo_endpoint": "GET /gw/users/me, POST /gw/auth/register, POST /gw/orders",
        "simulator_scenario": "data_exposure",
        "in_scope": True,
    },
    {
        "owasp_id": "API4",
        "code": "API4:2023",
        "title": "Unrestricted Resource Consumption",
        "risk_summary": "Missing rate limits, burst controls, payload size limits, or unbounded pagination (?limit=50000).",
        "gateway_mitigation": "Hybrid Sliding Window Counter + Token Bucket rate limiter, 64KB max payload enforcement, and `?limit=100` query parameter cap.",
        "demo_endpoint": "GET /gw/products?limit=50000",
        "simulator_scenario": "rate_flood",
        "in_scope": True,
    },
    {
        "owasp_id": "API5",
        "code": "API5:2023",
        "title": "Broken Function Level Authorization (BFLA)",
        "risk_summary": "Standard non-admin users invoking administrative endpoints (/admin/users) where upstream forgot RBAC checks.",
        "gateway_mitigation": "Declarative role/scope-to-route policy enforcement rejecting non-admin tokens with 403 Forbidden and flagging privilege probes.",
        "demo_endpoint": "GET /gw/admin/users",
        "simulator_scenario": "bfla_admin",
        "in_scope": True,
    },
    {
        "owasp_id": "API6",
        "code": "API6:2023",
        "title": "Unrestricted Access to Sensitive Business Flows",
        "risk_summary": "Automated bots scalping inventory, exhausting promo coupon pools (/coupons/redeem), or spamming account creation.",
        "gateway_mitigation": "Dedicated sensitive-flow strict velocity thresholds, token bucket burst limits, and rolling Z-score client anomaly detection.",
        "demo_endpoint": "POST /gw/coupons/redeem, POST /gw/orders",
        "simulator_scenario": "rate_flood",
        "in_scope": True,
    },
    {
        "owasp_id": "API7",
        "code": "API7:2023",
        "title": "Server-Side Request Forgery (SSRF)",
        "risk_summary": "API fetches attacker-controlled URLs (?url=) targeting cloud metadata (169.254.169.254), localhost, or internal VPC services.",
        "gateway_mitigation": "Deep URL parameter & JSON body inspector blocking RFC1918 private IPs, loopback, link-local cloud metadata, and non-HTTP schemes.",
        "demo_endpoint": "GET /gw/fetch?url=http://169.254.169.254/latest/meta-data/",
        "simulator_scenario": "ssrf_metadata",
        "in_scope": True,
    },
    {
        "owasp_id": "API8",
        "code": "API8:2023",
        "title": "Security Misconfiguration & Injection",
        "risk_summary": "Missing security headers, leaky Server/X-Powered-By banners, verbose 500 stack traces, and SQLi/XSS/Path Traversal payloads.",
        "gateway_mitigation": "Injects HSTS/CSP/nosniff headers, strips server banners, sanitizes 500 errors, and inspects query/path/body for SQLi, XSS, and traversal.",
        "demo_endpoint": "GET /gw/search?q=' UNION SELECT ...",
        "simulator_scenario": "sqli_shadow",
        "in_scope": True,
    },
    {
        "owasp_id": "API9",
        "code": "API9:2023",
        "title": "Improper Inventory Management (Shadow APIs)",
        "risk_summary": "Undocumented debug or legacy endpoints (/internal/debug, /.env) left exposed in production outside the OpenAPI spec.",
        "gateway_mitigation": "Strict route registry lookup flags and blocks any traffic to unregistered paths and populates the Shadow API Discovery queue.",
        "demo_endpoint": "GET /gw/internal/debug",
        "simulator_scenario": "sqli_shadow",
        "in_scope": True,
    },
    {
        "owasp_id": "API10",
        "code": "API10:2023",
        "title": "Unsafe Consumption of APIs",
        "risk_summary": "Backend service blindly trusting data returned from third-party outbound integrations without validation.",
        "gateway_mitigation": "Architectural Out-of-Scope for an inbound reverse proxy (requires egress proxy / outbound SDK instrumentation; documented in roadmap).",
        "demo_endpoint": "N/A (Outbound Third-Party Egress)",
        "simulator_scenario": None,
        "in_scope": False,
    },
]


@router.get("/coverage")
def get_owasp_coverage(session: Session = Depends(get_session)):
    policies = session.exec(select(Policy)).all()
    logs = session.exec(select(RequestLog)).all()
    alerts = session.exec(select(Alert).order_by(Alert.ts.desc())).all()

    cards = []
    for item in OWASP_TOP_10_2023:
        oid = item["owasp_id"]
        cat_policies = [p for p in policies if p.owasp_id == oid]
        enforcing_count = sum(1 for p in cat_policies if p.enabled and p.mode == "enforce")
        monitoring_count = sum(1 for p in cat_policies if p.enabled and p.mode == "monitor")

        cat_logs = [lg for lg in logs if lg.owasp_id == oid]
        blocked_24h = sum(1 for lg in cat_logs if lg.decision in ("blocked", "rate_limited"))
        cat_alerts = [a for a in alerts if a.owasp_id == oid]

        if not item["in_scope"]:
            status = "out_of_scope"
        elif enforcing_count > 0:
            status = "enforcing"
        elif monitoring_count > 0:
            status = "monitoring"
        else:
            status = "disabled"

        cards.append({
            **item,
            "protection_status": status,
            "active_rules_count": len(cat_policies),
            "enforcing_rules_count": enforcing_count,
            "events_24h": len(cat_logs),
            "blocked_24h": blocked_24h,
            "alerts_count": len(cat_alerts),
            "last_alert_ts": cat_alerts[0].ts.isoformat() if cat_alerts else None,
            "last_alert_title": cat_alerts[0].title if cat_alerts else None,
            "policies": [
                {"id": p.id, "name": p.name, "mode": p.mode, "enabled": p.enabled}
                for p in cat_policies
            ],
        })

    protected_categories = sum(1 for c in cards if c["protection_status"] in ("enforcing", "monitoring"))
    return {
        "edition": "OWASP API Security Top 10 (2023 Final Edition)",
        "protected_in_scope_count": protected_categories,
        "total_in_scope_count": 9,
        "posture_score": round((protected_categories / 9.0) * 100),
        "cards": cards,
    }
