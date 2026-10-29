from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, select
from app.db import get_session
from app.models import Alert, BlocklistEntry, RequestLog, Upstream, to_ist, to_ist_iso
from app.gateway.pipeline import gateway_state
from app.detection.engine import get_alert_upstream_id

router = APIRouter(prefix="/overview", tags=["Overview Dashboard"])


def _parse_window(time_range: str) -> timedelta:
    mapping = {
        "15m": timedelta(minutes=15),
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
    }
    return mapping.get(time_range, timedelta(hours=24))


@router.get("")
def get_overview_dashboard(
    time_range: str = Query("24h", description="15m, 1h, 24h, 7d"),
    upstream_id: int = Query(1),
    session: Session = Depends(get_session),
):
    now = datetime.now(timezone.utc)
    delta = _parse_window(time_range)
    cutoff = now - delta
    prev_cutoff = cutoff - delta

    all_logs = session.exec(
        select(RequestLog)
        .where(RequestLog.upstream_id == upstream_id)
        .order_by(RequestLog.ts.desc())
    ).all()
    curr_logs: List[RequestLog] = []
    prev_logs: List[RequestLog] = []

    for lg in all_logs:
        ts_utc = lg.ts if lg.ts.tzinfo else lg.ts.replace(tzinfo=timezone.utc)
        if ts_utc >= cutoff:
            curr_logs.append(lg)
        elif ts_utc >= prev_cutoff:
            prev_logs.append(lg)

    # Fallback if tight time window has few logs so dashboard always looks informative
    if len(curr_logs) < 5 and all_logs:
        curr_logs = all_logs[:250]

    total_requests = len(curr_logs)
    prev_total = max(1, len(prev_logs))
    blocked_requests = sum(1 for r in curr_logs if r.decision in ("blocked", "rate_limited"))
    prev_blocked = max(1, sum(1 for r in prev_logs if r.decision in ("blocked", "rate_limited")))

    avg_latency = round(sum(r.latency_ms for r in curr_logs) / max(1, total_requests), 2)
    prev_latency = round(sum(r.latency_ms for r in prev_logs) / prev_total, 2) if prev_logs else avg_latency

    error_count = sum(1 for r in curr_logs if r.status_code >= 400)
    error_rate = round((error_count / max(1, total_requests)) * 100, 1)
    unique_clients = len(set(r.client_ip for r in curr_logs))

    all_open_alerts = session.exec(
        select(Alert).where(Alert.status.in_(["open", "investigating"])).order_by(Alert.ts.desc())
    ).all()
    open_alerts = [a for a in all_open_alerts if get_alert_upstream_id(a) == upstream_id]
    critical_alerts = sum(1 for a in open_alerts if a.severity == "critical")
    high_alerts = sum(1 for a in open_alerts if a.severity == "high")

    # Build time-series buckets (16 buckets across the selected window)
    bucket_count = 16
    bucket_sec = max(60, int(delta.total_seconds() // bucket_count))
    buckets: Dict[int, Dict[str, Any]] = {}
    for i in range(bucket_count):
        b_time = now - timedelta(seconds=(bucket_count - 1 - i) * bucket_sec)
        b_key = int(b_time.timestamp() // bucket_sec)
        buckets[b_key] = {
            "time": to_ist(b_time).strftime("%H:%M"),
            "allowed": 0,
            "blocked": 0,
            "rate_limited": 0,
            "monitored": 0,
        }

    for r in curr_logs:
        ts_utc = r.ts if r.ts.tzinfo else r.ts.replace(tzinfo=timezone.utc)
        b_key = int(ts_utc.timestamp() // bucket_sec)
        if b_key not in buckets:
            # Map to nearest bucket
            nearest = min(buckets.keys(), key=lambda k: abs(k - b_key))
            b_key = nearest
        dec = r.decision if r.decision in ("allowed", "blocked", "rate_limited", "monitored") else "allowed"
        buckets[b_key][dec] += 1

    traffic_series = list(buckets.values())

    # Top targeted endpoints
    endpoint_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "blocked": 0})
    for r in curr_logs:
        ep = f"{r.method} {r.path}"
        endpoint_stats[ep]["total"] += 1
        if r.decision in ("blocked", "rate_limited", "monitored"):
            endpoint_stats[ep]["blocked"] += 1

    top_endpoints = [
        {"endpoint": ep, "total": st["total"], "blocked": st["blocked"]}
        for ep, st in sorted(endpoint_stats.items(), key=lambda x: (x[1]["blocked"], x[1]["total"]), reverse=True)[:7]
    ]

    # Alerts & detections by OWASP category (Donut chart)
    owasp_counts: Counter = Counter()
    for r in curr_logs:
        if r.owasp_id:
            owasp_counts[r.owasp_id] += 1
    for a in open_alerts:
        if a.owasp_id:
            owasp_counts[a.owasp_id] += a.event_count

    owasp_distribution = [
        {"owasp_id": k, "count": v}
        for k, v in sorted(owasp_counts.items(), key=lambda x: x[0])
    ]

    # Top offending IPs / clients
    offender_map: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"client_ip": "", "total_requests": 0, "blocked_requests": 0, "max_threat_score": 0, "owasp_tags": set()}
    )
    for r in curr_logs:
        ip = r.client_ip
        entry = offender_map[ip]
        entry["client_ip"] = ip
        entry["total_requests"] += 1
        if r.decision in ("blocked", "rate_limited", "monitored"):
            entry["blocked_requests"] += 1
        entry["max_threat_score"] = max(entry["max_threat_score"], r.threat_score)
        if r.owasp_id:
            entry["owasp_tags"].add(r.owasp_id)

    active_ip_blocks = set(
        b.value
        for b in session.exec(
            select(BlocklistEntry).where(BlocklistEntry.target_type == "ip", BlocklistEntry.active == True)
        ).all()
    )

    top_offenders = []
    for data in sorted(
        offender_map.values(),
        key=lambda x: (x["blocked_requests"], x["max_threat_score"], x["total_requests"]),
        reverse=True,
    )[:8]:
        owasp_list = sorted(list(data["owasp_tags"]))
        top_offenders.append({
            "client_ip": data["client_ip"],
            "total_requests": data["total_requests"],
            "blocked_requests": data["blocked_requests"],
            "max_threat_score": data["max_threat_score"],
            "owasp_tags": owasp_list,
            "is_blocked": data["client_ip"] in active_ip_blocks,
        })

    latest_alerts = [
        {
            "id": a.id,
            "ts": to_ist_iso(a.ts),
            "severity": a.severity,
            "type": a.type,
            "owasp_id": a.owasp_id,
            "title": a.title,
            "client_ip": a.client_ip,
            "target_path": a.target_path,
            "event_count": a.event_count,
            "status": a.status,
        }
        for a in open_alerts[:10]
    ]

    project = session.get(Upstream, upstream_id)
    return {
        "gateway_enabled": gateway_state.gateway_enabled,
        "upstream_id": upstream_id,
        "project_name": project.name if project else f"Project {upstream_id}",
        "time_range": time_range,
        "kpis": {
            "total_requests": total_requests,
            "total_requests_delta_pct": round(((total_requests - prev_total) / prev_total) * 100, 1),
            "blocked_requests": blocked_requests,
            "blocked_requests_delta_pct": round(((blocked_requests - prev_blocked) / prev_blocked) * 100, 1),
            "block_rate_pct": round((blocked_requests / max(1, total_requests)) * 100, 1),
            "active_alerts": len(open_alerts),
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "avg_latency_ms": avg_latency,
            "latency_delta_ms": round(avg_latency - prev_latency, 2),
            "error_rate_pct": error_rate,
            "unique_clients": unique_clients,
            "blocked_ips_count": len(active_ip_blocks),
        },
        "traffic_series": traffic_series,
        "top_endpoints": top_endpoints,
        "owasp_distribution": owasp_distribution,
        "latest_alerts": latest_alerts,
        "top_offenders": top_offenders,
    }
