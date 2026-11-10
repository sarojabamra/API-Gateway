from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from sqlmodel import Session, select
from app.db import get_session
from app.models import Alert, Policy, RequestLog, to_ist_iso

router = APIRouter(prefix="/owasp", tags=["OWASP API Top 10 Coverage"])

OWASP_TOP_10: List[Dict[str, Any]] = [
    {
        "owasp_id": "API1",
        "code": "API1",
        "title": "Broken Object Level Authorization (BOLA)",
        "risk_summary": "Attackers substitute object IDs in URL paths (/users/{id}, /orders/{id}) to access other users' records.",
        "gateway_mitigation": "Compares configurable owner claims to path/query/body object IDs, learns owners from successful GETs, and enforces distinct-ID enumeration caps.",
        "demo_endpoint": "GET /gw/{slug}/users/{id} as user 2, GET /gw/{slug}/orders/{id} IDs 1–6",
        "simulator_scenario": "bola_cross_user",
        "in_scope": True,
    },
    {
        "owasp_id": "API2",
        "code": "API2",
        "title": "Broken Authentication",
        "risk_summary": "Weak JWT verification (alg=none, unverified signatures, expired/revoked tokens) and credential stuffing/brute force on login.",
        "gateway_mitigation": "8-step cryptographic JWT checklist (alg pinning, kid registry, exp/iss/aud, JTI revocation list) + login brute-force & credential stuffing detection.",
        "demo_endpoint": "POST /gw/auth/login, All Protected Routes",
        "simulator_scenario": "jwt_tamper",
        "in_scope": True,
    },
    {
        "owasp_id": "API3",
        "code": "API3",
        "title": "Broken Object Property Level Authorization",
        "risk_summary": "Excessive data exposure in API responses (leaking password_hash, SSN, credit_card) and Mass Assignment of privileged fields.",
        "gateway_mitigation": "Recursive mass-assignment blocking, OpenAPI request schema validation, response field redaction, and SSN/PAN pattern masking.",
        "demo_endpoint": "GET /gw/users/me, POST /gw/auth/register, POST /gw/orders",
        "simulator_scenario": "data_exposure",
        "in_scope": True,
    },
    {
        "owasp_id": "API4",
        "code": "API4",
        "title": "Unrestricted Resource Consumption",
        "risk_summary": "Missing rate limits, burst controls, payload size limits, or unbounded pagination (?limit=50000).",
        "gateway_mitigation": "Hybrid Sliding Window Counter + Token Bucket rate limiter, 64KB max payload enforcement, and `?limit=100` query parameter cap.",
        "demo_endpoint": "GET /gw/products?limit=50000",
        "simulator_scenario": "rate_flood",
        "in_scope": True,
    },
    {
        "owasp_id": "API5",
        "code": "API5",
        "title": "Broken Function Level Authorization (BFLA)",
        "risk_summary": "Standard non-admin users invoking administrative endpoints (/admin/users) where upstream forgot RBAC checks.",
        "gateway_mitigation": "Declarative role/scope-to-route policy enforcement rejecting non-admin tokens with 403 Forbidden and flagging privilege probes.",
        "demo_endpoint": "GET /gw/admin/users",
        "simulator_scenario": "bfla_admin",
        "in_scope": True,
    },
    {
        "owasp_id": "API6",
        "code": "API6",
        "title": "Unrestricted Access to Sensitive Business Flows",
        "risk_summary": "Automated bots scalping inventory, exhausting promo coupon pools (/coupons/redeem), or spamming account creation.",
        "gateway_mitigation": "Dedicated sensitive-flow strict velocity thresholds, token bucket burst limits, and rolling Z-score client anomaly detection.",
        "demo_endpoint": "POST /gw/coupons/redeem, POST /gw/orders",
        "simulator_scenario": "rate_flood",
        "in_scope": True,
    },
    {
        "owasp_id": "API7",
        "code": "API7",
        "title": "Server-Side Request Forgery (SSRF)",
        "risk_summary": "API fetches attacker-controlled URLs (?url=) targeting cloud metadata (169.254.169.254), localhost, or internal VPC services.",
        "gateway_mitigation": "DNS-resolved SSRF checks (decimal/hex/IPv4-mapped normalization), nested JSON URL walking, and private-IP redirect pinning on egress.",
        "demo_endpoint": "GET /gw/fetch?url=http://169.254.169.254/latest/meta-data/",
        "simulator_scenario": "ssrf_metadata",
        "in_scope": True,
    },
    {
        "owasp_id": "API8",
        "code": "API8",
        "title": "Security Misconfiguration & Injection",
        "risk_summary": "Missing security headers, leaky Server/X-Powered-By banners, verbose 500 stack traces, and SQLi/XSS/Path Traversal payloads.",
        "gateway_mitigation": "Injects HSTS/CSP/nosniff headers, strips server banners, sanitizes 500 errors, and inspects query/path/body for SQLi, XSS, and traversal.",
        "demo_endpoint": "GET /gw/search?q=' UNION SELECT ...",
        "simulator_scenario": "sqli_shadow",
        "in_scope": True,
    },
    {
        "owasp_id": "API9",
        "code": "API9",
        "title": "Improper Inventory Management (Shadow APIs)",
        "risk_summary": "Undocumented debug or legacy endpoints (/internal/debug, /.env) left exposed in production outside the OpenAPI spec.",
        "gateway_mitigation": "Strict route registry lookup flags and blocks any traffic to unregistered paths and populates the Shadow API Discovery queue.",
        "demo_endpoint": "GET /gw/internal/debug",
        "simulator_scenario": "sqli_shadow",
        "in_scope": True,
    },
    {
        "owasp_id": "API10",
        "code": "API10",
        "title": "Unsafe Consumption of APIs",
        "risk_summary": "Backend blindly trusts third-party / supplier JSON containing private webhook URLs, redirects to metadata, or oversized nested payloads.",
        "gateway_mitigation": "Inspects upstream JSON responses for URL-like fields, DNS-resolves destinations, strips or blocks private/metadata targets, and pin-checks gateway-originated egress redirects.",
        "demo_endpoint": "GET /gw/supplier/catalog",
        "simulator_scenario": "unsafe_api_consume",
        "in_scope": True,
    },
]


@router.get("/coverage")
def get_owasp_coverage(session: Session = Depends(get_session)):
    policies = session.exec(select(Policy)).all()
    logs = session.exec(select(RequestLog)).all()
    alerts = session.exec(select(Alert).order_by(Alert.ts.desc())).all()

    cards = []
    for item in OWASP_TOP_10:
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
            "last_alert_ts": to_ist_iso(cat_alerts[0].ts) if cat_alerts else None,
            "last_alert_title": cat_alerts[0].title if cat_alerts else None,
            "policies": [
                {"id": p.id, "name": p.name, "mode": p.mode, "enabled": p.enabled}
                for p in cat_policies
            ],
        })

    protected_categories = sum(1 for c in cards if c["protection_status"] in ("enforcing", "monitoring"))
    in_scope_total = sum(1 for c in cards if c["in_scope"])
    return {
        "edition": "OWASP API Security Top 10",
        "protected_in_scope_count": protected_categories,
        "total_in_scope_count": in_scope_total,
        "posture_score": round((protected_categories / float(max(1, in_scope_total))) * 100),
        "cards": cards,
    }
