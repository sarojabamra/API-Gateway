import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select
from app.db import get_session
from app.models import Alert, Policy, RequestLog, to_ist_iso

router = APIRouter(prefix="/traffic", tags=["Live Traffic & Forensics"])


@router.get("")
def list_traffic_logs(
    limit: int = Query(100, le=500),
    decision: Optional[str] = None,
    method: Optional[str] = None,
    status_class: Optional[str] = None,  # 2xx, 4xx, 5xx
    client_ip: Optional[str] = None,
    owasp_id: Optional[str] = None,
    search: Optional[str] = None,
    min_threat_score: int = 0,
    upstream_id: int = Query(1),
    session: Session = Depends(get_session),
):
    stmt = (
        select(RequestLog)
        .where(RequestLog.upstream_id == upstream_id)
        .order_by(RequestLog.ts.desc())
    )
    logs = session.exec(stmt).all()

    filtered = []
    for r in logs:
        if decision and r.decision != decision:
            continue
        if method and r.method != method.upper():
            continue
        if status_class:
            if status_class == "2xx" and not (200 <= r.status_code < 300):
                continue
            if status_class == "4xx" and not (400 <= r.status_code < 500):
                continue
            if status_class == "5xx" and r.status_code < 500:
                continue
        if client_ip and client_ip.lower() not in r.client_ip.lower():
            continue
        if owasp_id and r.owasp_id != owasp_id:
            continue
        if r.threat_score < min_threat_score:
            continue
        if search:
            q = search.lower()
            haystack = f"{r.request_id} {r.path} {r.client_ip} {r.user_sub or ''} {r.block_reason or ''} {r.owasp_id or ''}".lower()
            if q not in haystack:
                continue

        filtered.append({
            "id": r.id,
            "upstream_id": r.upstream_id,
            "ts": to_ist_iso(r.ts),
            "request_id": r.request_id,
            "client_ip": r.client_ip,
            "user_sub": r.user_sub,
            "user_role": r.user_role,
            "method": r.method,
            "path": r.path,
            "query_params": r.query_params,
            "status_code": r.status_code,
            "latency_ms": r.latency_ms,
            "req_size_bytes": r.req_size_bytes,
            "resp_size_bytes": r.resp_size_bytes,
            "decision": r.decision,
            "block_reason": r.block_reason,
            "owasp_id": r.owasp_id,
            "threat_score": r.threat_score,
            "anomaly_zscore": r.anomaly_zscore,
        })
        if len(filtered) >= limit:
            break

    return {"items": filtered, "total_matching": len(filtered)}


@router.get("/{log_id}")
def get_traffic_log_detail(log_id: int, session: Session = Depends(get_session)):
    log = session.get(RequestLog, log_id)
    if not log:
        raise HTTPException(status_code=404, detail="Request log not found")

    policy_name = None
    if log.matched_policy_id:
        pol = session.get(Policy, log.matched_policy_id)
        if pol:
            policy_name = pol.name

    # Find linked alert if any
    linked_alert_id = None
    alerts = session.exec(select(Alert).where(Alert.client_ip == log.client_ip).order_by(Alert.ts.desc())).all()
    for a in alerts:
        if log.request_id in (a.related_request_ids_json or ""):
            linked_alert_id = a.id
            break
    if not linked_alert_id and alerts and log.owasp_id:
        for a in alerts:
            if a.owasp_id == log.owasp_id:
                linked_alert_id = a.id
                break

    return {
        "id": log.id,
        "ts": to_ist_iso(log.ts),
        "request_id": log.request_id,
        "client_ip": log.client_ip,
        "user_sub": log.user_sub,
        "user_role": log.user_role,
        "api_key_id": log.api_key_id,
        "method": log.method,
        "path": log.path,
        "query_params": log.query_params,
        "request_headers": json.loads(log.request_headers_json or "{}"),
        "request_body_preview": log.request_body_preview,
        "response_body_preview": log.response_body_preview,
        "decoded_jwt": json.loads(log.decoded_jwt_json or "{}"),
        "status_code": log.status_code,
        "latency_ms": log.latency_ms,
        "req_size_bytes": log.req_size_bytes,
        "resp_size_bytes": log.resp_size_bytes,
        "user_agent": log.user_agent,
        "decision": log.decision,
        "block_reason": log.block_reason,
        "matched_policy_id": log.matched_policy_id,
        "matched_policy_name": policy_name,
        "owasp_id": log.owasp_id,
        "threat_score": log.threat_score,
        "anomaly_zscore": log.anomaly_zscore,
        "linked_alert_id": linked_alert_id,
    }
