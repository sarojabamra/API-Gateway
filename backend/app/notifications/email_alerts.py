"""Email every active member of an organization when a new threat is opened."""

from __future__ import annotations

import asyncio
import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage

from sqlmodel import Session, select

from app.config import settings
from app.models import Alert, Organization, Upstream, User

logger = logging.getLogger("sentinel.alerts")


@dataclass
class OutboundEmail:
    to: str
    subject: str
    body: str


def _alert_upstream_id(alert: Alert) -> int | None:
    import json

    try:
        evidence = json.loads(alert.evidence_json or "{}")
    except Exception:
        return None
    if isinstance(evidence, dict) and evidence.get("upstream_id") is not None:
        try:
            return int(evidence["upstream_id"])
        except (TypeError, ValueError):
            return None
    return None


def threat_recipients(session: Session, alert: Alert) -> tuple[Organization | None, Upstream | None, list[User]]:
    """Active members of the organization that owns the project this threat hit."""
    upstream_id = _alert_upstream_id(alert)
    if upstream_id is None:
        return None, None, []
    upstream = session.get(Upstream, upstream_id)
    if upstream is None or upstream.organization_id is None:
        return None, upstream, []
    organization = session.get(Organization, upstream.organization_id)
    members = session.exec(
        select(User).where(
            User.organization_id == upstream.organization_id,
            User.is_active == True,  # noqa: E712
        )
    ).all()
    recipients = [member for member in members if (member.email or "").strip()]
    return organization, upstream, recipients


def build_threat_email(
    alert: Alert,
    recipient: User,
    organization: Organization | None,
    upstream: Upstream | None,
) -> OutboundEmail:
    org_name = organization.name if organization else "your organization"
    project_name = upstream.name if upstream else "an API project"
    base = (settings.DASHBOARD_BASE_URL or "").rstrip("/")
    incident_url = f"{base}/alerts/{alert.id}" if base and alert.id else ""
    principal = alert.user_sub or "unauthenticated"
    lines = [
        f"Hello {recipient.full_name},",
        "",
        f"SentinelGW opened a new threat on {project_name} ({org_name}).",
        "",
        f"Severity: {alert.severity}",
        f"Title: {alert.title}",
        f"OWASP: {alert.owasp_id}",
        f"Source IP: {alert.client_ip}",
        f"Principal: {principal}",
        f"Target: {alert.target_path or 'unknown'}",
        "",
        alert.description or "",
        "",
    ]
    if incident_url:
        lines.extend([f"Open the incident: {incident_url}", ""])
    lines.append(
        "This message was sent to every active member of the organization. "
        "Further hits on this same open incident are grouped into the alert and do not send another email."
    )
    severity = (alert.severity or "threat").upper()
    return OutboundEmail(
        to=recipient.email.strip(),
        subject=f"[SentinelGW] {severity} threat on {project_name}: {alert.title}",
        body="\n".join(lines).strip() + "\n",
    )


def _from_header() -> str:
    sender = (settings.SMTP_FROM or "alerts@sentinel.local").strip()
    if "<" in sender:
        return sender
    return f"SentinelGW <{sender}>"


def deliver_messages(messages: list[OutboundEmail]) -> dict:
    """Send one message per recipient. Missing SMTP config skips delivery without raising."""
    if not messages:
        return {"sent": [], "skipped": [], "failed": []}

    host = (settings.SMTP_HOST or "").strip()
    if not host:
        skipped = [message.to for message in messages]
        logger.warning(
            "Threat email not sent because SMTP_HOST is not set. Recipients: %s",
            ", ".join(skipped),
        )
        return {"sent": [], "skipped": skipped, "failed": []}

    sent: list[str] = []
    failed: list[dict] = []
    smtp_factory = smtplib.SMTP_SSL if settings.SMTP_USE_SSL else smtplib.SMTP
    try:
        server = smtp_factory(host, settings.SMTP_PORT, timeout=10)
    except Exception as exc:
        logger.exception("Threat email SMTP connection failed")
        return {
            "sent": [],
            "skipped": [],
            "failed": [{"to": message.to, "error": str(exc)} for message in messages],
        }

    try:
        if settings.SMTP_USE_TLS and not settings.SMTP_USE_SSL:
            server.starttls()
        username = (settings.SMTP_USERNAME or "").strip()
        if username:
            server.login(username, settings.SMTP_PASSWORD or "")
        from_header = _from_header()
        for message in messages:
            email = EmailMessage()
            email["From"] = from_header
            email["To"] = message.to
            email["Subject"] = message.subject
            email.set_content(message.body)
            try:
                server.send_message(email)
                sent.append(message.to)
            except Exception as exc:
                logger.exception("Threat email failed for %s", message.to)
                failed.append({"to": message.to, "error": str(exc)})
    finally:
        try:
            server.quit()
        except Exception:
            pass

    return {"sent": sent, "skipped": [], "failed": failed}


async def notify_organization_of_threat(session: Session, alert: Alert) -> dict:
    """Email every active member of the organization that owns the affected project."""
    if not settings.ALERT_EMAIL_ENABLED:
        return {"sent": [], "skipped": [], "failed": [], "disabled": True}
    try:
        organization, upstream, members = threat_recipients(session, alert)
        messages = [
            build_threat_email(alert, member, organization, upstream)
            for member in members
        ]
        if not messages:
            return {"sent": [], "skipped": [], "failed": []}
        return await asyncio.to_thread(deliver_messages, messages)
    except Exception:
        logger.exception("Threat email notification failed for alert %s", alert.id)
        return {"sent": [], "skipped": [], "failed": [{"to": "*", "error": "notification failed"}]}
