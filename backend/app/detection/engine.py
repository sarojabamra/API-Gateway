from datetime import datetime, timedelta, timezone
import json
from typing import List
from sqlmodel import Session, select
from app.models import Alert, BlocklistEntry, RequestLog
from app.detection.anomaly import anomaly_detector
from app.detection.rules import behavioral_tracker
from app.detection.scoring import compute_threat_score
from app.detection.ai_triage import generate_ai_triage_summary
from app.gateway.pipeline import gateway_state


async def process_request_event(session: Session, log_entry: RequestLog) -> List[Alert]:
    """
    Consumes a newly logged RequestLog:
    1. Updates the per-client rolling baseline & computes Z-score.
    2. Computes composite threat score (0-100).
    3. Evaluates all 12 OWASP behavioral & signature rules.
    4. Creates or deduplicates Alerts (aggregating repeated hits into event_count).
    5. Triggers Auto-Block on Critical alerts when enabled.
    6. Broadcasts live traffic & alert events over WebSocket (/ws/live).
    """
    from app.api.v1.ws import ws_manager

    client_key = log_entry.user_sub or log_entry.client_ip
    zscore, _ = anomaly_detector.record_and_score(session, client_key)
    log_entry.anomaly_zscore = zscore
    log_entry.threat_score = compute_threat_score(log_entry, zscore)
    session.add(log_entry)
    session.commit()
    session.refresh(log_entry)

    triggered_rules = behavioral_tracker.evaluate(log_entry, zscore)
    created_or_updated_alerts: List[Alert] = []

    for rule in triggered_rules:
        # Deduplicate against an existing open/investigating alert of same type + client_ip within last 30 mins
        existing = session.exec(
            select(Alert).where(
                Alert.type == rule["type"],
                Alert.client_ip == log_entry.client_ip,
                Alert.status.in_(["open", "investigating"]),
            )
        ).first()

        if existing:
            existing.event_count = (existing.event_count or 1) + 1
            existing.updated_at = datetime.now(timezone.utc)
            existing.description = rule["description"]
            req_ids: List[str] = []
            try:
                req_ids = json.loads(existing.related_request_ids_json or "[]")
            except Exception:
                req_ids = []
            if log_entry.request_id not in req_ids:
                req_ids.append(log_entry.request_id)
                existing.related_request_ids_json = json.dumps(req_ids[-30:])

            # Refresh AI triage summary with updated counts
            ai_summary = await generate_ai_triage_summary(existing, [log_entry])
            existing.ai_summary_json = json.dumps(ai_summary)

            session.add(existing)
            session.commit()
            session.refresh(existing)
            alert_obj = existing
        else:
            evidence = {
                "method": log_entry.method,
                "path": log_entry.path,
                "query_params": log_entry.query_params,
                "status_code": log_entry.status_code,
                "decision": log_entry.decision,
                "block_reason": log_entry.block_reason,
                "user_agent": log_entry.user_agent,
                "sample_body": log_entry.request_body_preview[:300],
            }
            alert_obj = Alert(
                ts=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                severity=rule["severity"],
                type=rule["type"],
                owasp_id=rule["owasp_id"],
                title=rule["title"],
                description=rule["description"],
                client_ip=log_entry.client_ip,
                user_sub=log_entry.user_sub,
                target_path=log_entry.path,
                event_count=1,
                status="open",
                related_request_ids_json=json.dumps([log_entry.request_id]),
                evidence_json=json.dumps(evidence),
            )
            ai_summary = await generate_ai_triage_summary(alert_obj, [log_entry])
            alert_obj.ai_summary_json = json.dumps(ai_summary)
            session.add(alert_obj)
            session.commit()
            session.refresh(alert_obj)

        created_or_updated_alerts.append(alert_obj)

        # Auto-block IP on critical alert if enabled
        if alert_obj.severity == "critical" and gateway_state.auto_block_critical:
            already_blocked = session.exec(
                select(BlocklistEntry).where(
                    BlocklistEntry.target_type == "ip",
                    BlocklistEntry.value == log_entry.client_ip,
                    BlocklistEntry.active == True,
                )
            ).first()
            if not already_blocked:
                session.add(
                    BlocklistEntry(
                        target_type="ip",
                        value=log_entry.client_ip,
                        reason=f"Auto-blocked by Critical Alert: {alert_obj.title}",
                        owasp_id=alert_obj.owasp_id,
                        source="auto_rule",
                        created_by="SentinelGW Auto-Defense",
                        expires_at=datetime.now(timezone.utc) + timedelta(minutes=gateway_state.auto_block_duration_minutes),
                        active=True,
                    )
                )
                session.commit()

    # Broadcast traffic log & any alerts over WebSocket
    await ws_manager.broadcast({
        "event": "traffic",
        "data": {
            "id": log_entry.id,
            "ts": log_entry.ts.isoformat(),
            "request_id": log_entry.request_id,
            "client_ip": log_entry.client_ip,
            "user_sub": log_entry.user_sub,
            "user_role": log_entry.user_role,
            "method": log_entry.method,
            "path": log_entry.path,
            "query_params": log_entry.query_params,
            "status_code": log_entry.status_code,
            "latency_ms": log_entry.latency_ms,
            "decision": log_entry.decision,
            "block_reason": log_entry.block_reason,
            "owasp_id": log_entry.owasp_id,
            "threat_score": log_entry.threat_score,
            "anomaly_zscore": log_entry.anomaly_zscore,
        },
    })

    for al in created_or_updated_alerts:
        await ws_manager.broadcast({
            "event": "alert",
            "data": {
                "id": al.id,
                "ts": al.ts.isoformat(),
                "severity": al.severity,
                "type": al.type,
                "owasp_id": al.owasp_id,
                "title": al.title,
                "description": al.description,
                "client_ip": al.client_ip,
                "user_sub": al.user_sub,
                "target_path": al.target_path,
                "event_count": al.event_count,
                "status": al.status,
            },
        })

    return created_or_updated_alerts
