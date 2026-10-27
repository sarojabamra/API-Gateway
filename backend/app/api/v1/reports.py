from collections import Counter
import csv
from datetime import datetime, timezone
import io
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlmodel import Session, select
from app.db import get_session
from app.models import Alert, BlocklistEntry, Policy, RequestLog, Route

router = APIRouter(prefix="/reports", tags=["Executive Reports & CSV/PDF Export"])


@router.get("/summary")
def generate_executive_report(
    time_range: str = Query("24h"),
    session: Session = Depends(get_session),
):
    logs = session.exec(select(RequestLog).order_by(RequestLog.ts.desc())).all()
    alerts = session.exec(select(Alert).order_by(Alert.ts.desc())).all()
    policies = session.exec(select(Policy)).all()
    routes = session.exec(select(Route)).all()
    blocks = session.exec(select(BlocklistEntry).where(BlocklistEntry.active == True)).all()

    total_reqs = len(logs)
    blocked_reqs = sum(1 for r in logs if r.decision in ("blocked", "rate_limited"))
    monitored_reqs = sum(1 for r in logs if r.decision == "monitored")
    allowed_reqs = sum(1 for r in logs if r.decision == "allowed")
    avg_lat = round(sum(r.latency_ms for r in logs) / max(1, total_reqs), 2)

    owasp_breakdown = Counter(r.owasp_id for r in logs if r.owasp_id)
    severity_breakdown = Counter(a.severity for a in alerts)

    shadow_count = sum(1 for r in routes if not r.registered)
    enforcing_policies = sum(1 for p in policies if p.enabled and p.mode == "enforce")

    posture_score = min(100, max(50, int((enforcing_policies / max(1, len(policies))) * 90 + (10 if shadow_count == 0 else 4))))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "time_range": time_range,
        "posture_score": posture_score,
        "executive_metrics": {
            "total_requests": total_reqs,
            "allowed_requests": allowed_reqs,
            "blocked_requests": blocked_reqs,
            "monitored_requests": monitored_reqs,
            "block_rate_pct": round((blocked_reqs / max(1, total_reqs)) * 100, 1),
            "avg_gateway_latency_ms": avg_lat,
            "total_alerts": len(alerts),
            "open_alerts": sum(1 for a in alerts if a.status in ("open", "investigating")),
            "active_blocklist_entries": len(blocks),
            "enforcing_policies": enforcing_policies,
            "total_policies": len(policies),
            "registered_routes": sum(1 for r in routes if r.registered),
            "shadow_routes_discovered": shadow_count,
        },
        "owasp_breakdown": [{"owasp_id": k, "incidents": v} for k, v in sorted(owasp_breakdown.items())],
        "severity_breakdown": dict(severity_breakdown),
        "top_alerts": [
            {
                "id": a.id,
                "ts": a.ts.isoformat(),
                "severity": a.severity,
                "owasp_id": a.owasp_id,
                "title": a.title,
                "client_ip": a.client_ip,
                "event_count": a.event_count,
                "status": a.status,
            }
            for a in alerts[:10]
        ],
    }


@router.get("/export/traffic.csv")
def export_traffic_csv(session: Session = Depends(get_session)):
    logs = session.exec(select(RequestLog).order_by(RequestLog.ts.desc()).limit(1000)).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id",
        "timestamp",
        "request_id",
        "client_ip",
        "user_sub",
        "method",
        "path",
        "status_code",
        "latency_ms",
        "decision",
        "owasp_id",
        "threat_score",
        "block_reason",
    ])
    for r in logs:
        writer.writerow([
            r.id,
            r.ts.isoformat(),
            r.request_id,
            r.client_ip,
            r.user_sub or "",
            r.method,
            r.path,
            r.status_code,
            r.latency_ms,
            r.decision,
            r.owasp_id or "",
            r.threat_score,
            r.block_reason or "",
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinelgw_traffic_logs.csv"},
    )


@router.get("/export/alerts.csv")
def export_alerts_csv(session: Session = Depends(get_session)):
    alerts = session.exec(select(Alert).order_by(Alert.ts.desc())).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id",
        "timestamp",
        "severity",
        "owasp_id",
        "type",
        "title",
        "client_ip",
        "user_sub",
        "target_path",
        "event_count",
        "status",
    ])
    for a in alerts:
        writer.writerow([
            a.id,
            a.ts.isoformat(),
            a.severity,
            a.owasp_id,
            a.type,
            a.title,
            a.client_ip,
            a.user_sub or "",
            a.target_path,
            a.event_count,
            a.status,
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinelgw_security_alerts.csv"},
    )
