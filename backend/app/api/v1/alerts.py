from datetime import datetime, timedelta, timezone
import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select

from app.db import get_session
from app.models import Alert, BlocklistEntry, ClientBaseline, Policy, RequestLog, RevokedToken, User, to_ist_iso
from app.schemas import AlertActionRequest, AlertBulkActionRequest
from app.api.v1.deps import require_roles
from app.detection.ai_triage import generate_ai_triage_summary

router = APIRouter(prefix="/alerts", tags=["Alerts & Incident Response"])


@router.get("")
def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    owasp_id: Optional[str] = None,
    search: Optional[str] = None,
    upstream_id: int = Query(1),
    session: Session = Depends(get_session),
):
    alerts = session.exec(select(Alert).order_by(Alert.ts.desc())).all()
    items = []
    project_alerts = []
    for a in alerts:
        try:
            evidence = json.loads(a.evidence_json or "{}")
            alert_upstream_id = int(evidence.get("upstream_id", 1))
        except Exception:
            alert_upstream_id = 1
        if alert_upstream_id != upstream_id:
            continue
        project_alerts.append(a)
        if severity and a.severity != severity:
            continue
        if status and a.status != status:
            continue
        if owasp_id and a.owasp_id != owasp_id:
            continue
        if search:
            q = search.lower()
            if q not in f"{a.title} {a.client_ip} {a.user_sub or ''} {a.target_path} {a.owasp_id}".lower():
                continue
        items.append({
            "id": a.id,
            "upstream_id": alert_upstream_id,
            "ts": to_ist_iso(a.ts),
            "updated_at": to_ist_iso(a.updated_at),
            "severity": a.severity,
            "type": a.type,
            "owasp_id": a.owasp_id,
            "title": a.title,
            "description": a.description,
            "client_ip": a.client_ip,
            "user_sub": a.user_sub,
            "target_path": a.target_path,
            "event_count": a.event_count,
            "status": a.status,
            "assigned_to": a.assigned_to,
        })

    counts = {
        "total": len(project_alerts),
        "open": sum(1 for a in project_alerts if a.status == "open"),
        "investigating": sum(1 for a in project_alerts if a.status == "investigating"),
        "resolved": sum(1 for a in project_alerts if a.status == "resolved"),
        "false_positive": sum(1 for a in project_alerts if a.status == "false_positive"),
        "critical": sum(1 for a in project_alerts if a.severity == "critical" and a.status in ("open", "investigating")),
        "high": sum(1 for a in project_alerts if a.severity == "high" and a.status in ("open", "investigating")),
    }
    return {"items": items, "summary": counts}


@router.post("/bulk")
def bulk_update_alerts(
    payload: AlertBulkActionRequest,
    session: Session = Depends(get_session),
    user: User = Depends(require_roles(["admin", "analyst"])),
):
    updated = 0
    for aid in payload.alert_ids:
        alert = session.get(Alert, aid)
        if alert:
            alert.status = payload.status
            alert.updated_at = datetime.now(timezone.utc)
            alert.assigned_to = alert.assigned_to or user.email
            session.add(alert)
            updated += 1
    session.commit()
    return {"status": "ok", "updated_count": updated}


@router.get("/{alert_id}")
def get_alert_detail(alert_id: int, session: Session = Depends(get_session)):
    alert = session.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    try:
        alert_evidence = json.loads(alert.evidence_json or "{}")
        alert_upstream_id = int(alert_evidence.get("upstream_id", 1))
    except Exception:
        alert_evidence = {}
        alert_upstream_id = 1

    req_ids: List[str] = json.loads(alert.related_request_ids_json or "[]")
    related_logs = []
    if req_ids:
        logs = session.exec(select(RequestLog).where(RequestLog.request_id.in_(req_ids)).order_by(RequestLog.ts.desc())).all()
        related_logs = list(logs)
    if not related_logs:
        logs = session.exec(
            select(RequestLog).where(
                RequestLog.client_ip == alert.client_ip,
                RequestLog.upstream_id == alert_upstream_id,
            ).order_by(RequestLog.ts.desc())
        ).all()
        related_logs = list(logs[:15])

    # Offender profile telemetry
    all_ip_logs = session.exec(
        select(RequestLog).where(
            RequestLog.client_ip == alert.client_ip,
            RequestLog.upstream_id == alert_upstream_id,
        )
    ).all()
    blocked_ip_entry = session.exec(
        select(BlocklistEntry).where(
            BlocklistEntry.target_type == "ip",
            BlocklistEntry.value == alert.client_ip,
            BlocklistEntry.active == True,
        )
    ).first()

    baseline = session.exec(
        select(ClientBaseline).where(
            ClientBaseline.client_key == f"{alert_upstream_id}:{alert.user_sub or alert.client_ip}"
        )
    ).first()

    ai_parsed = json.loads(alert.ai_summary_json) if alert.ai_summary_json else None
    timeline_items = [
        {
            "id": r.id,
            "ts": to_ist_iso(r.ts),
            "request_id": r.request_id,
            "method": r.method,
            "path": r.path,
            "query_params": r.query_params,
            "status_code": r.status_code,
            "latency_ms": r.latency_ms,
            "decision": r.decision,
            "block_reason": r.block_reason,
            "owasp_id": r.owasp_id,
            "threat_score": r.threat_score,
            "request_body_preview": r.request_body_preview,
        }
        for r in related_logs
    ]
    offender_prof = {
        "client_ip": alert.client_ip,
        "user_sub": alert.user_sub,
        "total_requests": len(all_ip_logs),
        "total_requests_24h": len(all_ip_logs),
        "blocked_requests": sum(1 for r in all_ip_logs if r.decision in ("blocked", "rate_limited")),
        "blocked_requests_24h": sum(1 for r in all_ip_logs if r.decision in ("blocked", "rate_limited")),
        "is_ip_blocked": blocked_ip_entry is not None,
        "is_currently_blocked": blocked_ip_entry is not None,
        "anomaly_zscore": baseline.last_zscore if baseline else 0.0,
        "mean_rpm": baseline.mean_rpm if baseline else 5.0,
        "baseline": {
            "last_zscore": baseline.last_zscore if baseline else 0.0,
            "mean_rpm": baseline.mean_rpm if baseline else 5.0,
        },
    }
    alert_dict = {
        "id": alert.id,
        "ts": to_ist_iso(alert.ts),
        "updated_at": to_ist_iso(alert.updated_at),
        "severity": alert.severity,
        "type": alert.type,
        "owasp_id": alert.owasp_id,
        "title": alert.title,
        "description": alert.description,
        "client_ip": alert.client_ip,
        "user_sub": alert.user_sub,
        "target_path": alert.target_path,
        "event_count": alert.event_count,
        "status": alert.status,
        "assigned_to": alert.assigned_to,
        "notes": json.loads(alert.notes_json or "[]"),
        "evidence": alert_evidence,
        "upstream_id": alert_upstream_id,
        "ai_summary": ai_parsed,
        "ai_triage": ai_parsed,
    }
    return {
        **alert_dict,
        "alert": alert_dict,
        "offender_profile": offender_prof,
        "timeline": timeline_items,
        "correlated_requests": timeline_items,
    }


@router.post("/{alert_id}/actions")
async def execute_alert_action(
    alert_id: int,
    payload: AlertActionRequest,
    session: Session = Depends(get_session),
    user: User = Depends(require_roles(["admin", "analyst"])),
):
    alert = session.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    notes = json.loads(alert.notes_json or "[]")
    now_iso = to_ist_iso(datetime.now(timezone.utc))

    if payload.action == "update_status" and payload.status:
        alert.status = payload.status
        alert.assigned_to = alert.assigned_to or user.email
        notes.append({
            "author": user.email,
            "ts": now_iso,
            "text": f"Changed alert status to '{payload.status}'",
        })

    elif payload.action == "assign" and payload.assigned_to:
        alert.assigned_to = payload.assigned_to
        notes.append({
            "author": user.email,
            "ts": now_iso,
            "text": f"Assigned incident to {payload.assigned_to}",
        })

    elif payload.action == "add_note" and payload.note:
        notes.append({
            "author": user.email,
            "ts": now_iso,
            "text": payload.note,
        })

    elif payload.action == "block_ip":
        existing = session.exec(
            select(BlocklistEntry).where(
                BlocklistEntry.target_type == "ip",
                BlocklistEntry.value == alert.client_ip,
                BlocklistEntry.active == True,
            )
        ).first()
        if not existing:
            session.add(
                BlocklistEntry(
                    target_type="ip",
                    value=alert.client_ip,
                    reason=f"Blocked from Alert #{alert.id}: {alert.title}",
                    owasp_id=alert.owasp_id,
                    source="manual",
                    created_by=user.email,
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=payload.block_duration_minutes),
                    active=True,
                )
            )
        notes.append({
            "author": user.email,
            "ts": now_iso,
            "text": f"Blocked offending IP {alert.client_ip} for {payload.block_duration_minutes} minutes.",
        })

    elif payload.action == "block_user" and alert.user_sub:
        existing = session.exec(
            select(BlocklistEntry).where(
                BlocklistEntry.target_type == "user_sub",
                BlocklistEntry.value == alert.user_sub,
                BlocklistEntry.active == True,
            )
        ).first()
        if not existing:
            session.add(
                BlocklistEntry(
                    target_type="user_sub",
                    value=alert.user_sub,
                    reason=f"Principal blocked from Alert #{alert.id}",
                    owasp_id=alert.owasp_id,
                    source="manual",
                    created_by=user.email,
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=payload.block_duration_minutes),
                    active=True,
                )
            )
        notes.append({
            "author": user.email,
            "ts": now_iso,
            "text": f"Blocked user principal '{alert.user_sub}'.",
        })

    elif payload.action == "revoke_token":
        jti_to_revoke = f"jti-alert-{alert.id}"
        req_ids: List[str] = json.loads(alert.related_request_ids_json or "[]")
        if req_ids:
            sample_log = session.exec(select(RequestLog).where(RequestLog.request_id == req_ids[0])).first()
            if sample_log and sample_log.decoded_jwt_json:
                try:
                    jwt_data = json.loads(sample_log.decoded_jwt_json)
                    jti_to_revoke = (jwt_data.get("payload") or {}).get("jti") or jti_to_revoke
                except Exception:
                    pass
        existing_jti = session.exec(select(RevokedToken).where(RevokedToken.jti == jti_to_revoke)).first()
        if not existing_jti:
            session.add(
                RevokedToken(
                    jti=jti_to_revoke,
                    user_sub=alert.user_sub or "unknown",
                    reason=f"Revoked during incident response on Alert #{alert.id}",
                    revoked_by=user.email,
                )
            )
        notes.append({
            "author": user.email,
            "ts": now_iso,
            "text": f"Added token JTI '{jti_to_revoke}' to revocation blacklist.",
        })

    elif payload.action == "create_exception":
        alert.status = "false_positive"
        pol = session.exec(select(Policy).where(Policy.owasp_id == alert.owasp_id)).first()
        if pol:
            pol.mode = "monitor"
            session.add(pol)
        notes.append({
            "author": user.email,
            "ts": now_iso,
            "text": f"Marked false positive and switched {alert.owasp_id} policy to Monitor (Dry-Run) mode.",
        })

    elif payload.action == "ai_triage":
        logs = session.exec(select(RequestLog).where(RequestLog.client_ip == alert.client_ip).limit(10)).all()
        ai_summary = await generate_ai_triage_summary(alert, list(logs))
        alert.ai_summary_json = json.dumps(ai_summary)
        notes.append({
            "author": user.email,
            "ts": now_iso,
            "text": "Generated fresh AI Triage & Remediation analysis.",
        })

    alert.notes_json = json.dumps(notes)
    alert.updated_at = datetime.now(timezone.utc)
    session.add(alert)
    session.commit()
    session.refresh(alert)

    return get_alert_detail(alert_id, session)


@router.post("/{alert_id}/triage")
@router.post("/{alert_id}/ai-triage")
async def generate_alert_ai_triage_endpoint(
    alert_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_roles(["admin", "analyst", "developer"])),
):
    alert = session.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    logs = session.exec(select(RequestLog).where(RequestLog.client_ip == alert.client_ip).limit(10)).all()
    ai_summary = await generate_ai_triage_summary(alert, list(logs))
    alert.ai_summary_json = json.dumps(ai_summary)
    alert.updated_at = datetime.now(timezone.utc)
    session.add(alert)
    session.commit()
    return {
        "alert_id": alert.id,
        "triage": {
            **ai_summary,
            "summary": ai_summary.get("executive_summary") or ai_summary.get("summary") or "AI Incident Triage Complete",
        },
    }

