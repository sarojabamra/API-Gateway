import asyncio
import uuid

from sqlmodel import Session

from app.config import settings
from app.db import create_db_and_tables, engine
from app.detection.engine import process_request_event
from app.models import Alert, Organization, RequestLog, Upstream, User
from app.notifications.email_alerts import (
    OutboundEmail,
    deliver_messages,
    notify_organization_of_threat,
    threat_recipients,
)


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def test_threat_email_goes_to_every_active_member(monkeypatch):
    create_db_and_tables()
    token = _unique("mail")
    delivered: list[str] = []

    def fake_deliver(messages):
        delivered.extend(message.to for message in messages)
        return {"sent": list(delivered), "skipped": [], "failed": []}

    monkeypatch.setattr("app.notifications.email_alerts.deliver_messages", fake_deliver)
    monkeypatch.setattr(settings, "ALERT_EMAIL_ENABLED", True)

    with Session(engine) as session:
        org = Organization(name=f"Mail Org {token}", slug=_unique("mail-org"))
        other = Organization(name=f"Other Org {token}", slug=_unique("other-org"))
        session.add(org)
        session.add(other)
        session.commit()
        session.refresh(org)
        session.refresh(other)

        members = [
            User(email=f"ada-{token}@example.com", full_name="Ada Admin", password_hash="x", role="admin", organization_id=org.id, is_active=True),
            User(email=f"sam-{token}@example.com", full_name="Sam Analyst", password_hash="x", role="analyst", organization_id=org.id, is_active=True),
            User(email=f"off-{token}@example.com", full_name="Off Duty", password_hash="x", role="viewer", organization_id=org.id, is_active=False),
            User(email=f"out-{token}@example.com", full_name="Other Org", password_hash="x", role="admin", organization_id=other.id, is_active=True),
        ]
        for member in members:
            session.add(member)
        project = Upstream(
            name=f"Parking {token}",
            slug=_unique("parking"),
            organization_id=org.id,
            base_url="http://127.0.0.1:9",
        )
        session.add(project)
        session.commit()
        session.refresh(project)

        alert = Alert(
            severity="high",
            type="jwt_tampering",
            owasp_id="API2",
            title="Forged token",
            description="A client presented a forged JWT.",
            client_ip="203.0.113.10",
            user_sub="alice",
            target_path="/orders/1044",
            evidence_json='{"upstream_id": %d}' % project.id,
        )
        session.add(alert)
        session.commit()
        session.refresh(alert)

        organization, upstream, recipients = threat_recipients(session, alert)
        assert organization.id == org.id
        assert upstream.id == project.id
        assert {user.email for user in recipients} == {
            f"ada-{token}@example.com",
            f"sam-{token}@example.com",
        }

        result = asyncio.run(notify_organization_of_threat(session, alert))
        assert set(result["sent"]) == {
            f"ada-{token}@example.com",
            f"sam-{token}@example.com",
        }
        assert set(delivered) == set(result["sent"])


def test_missing_smtp_skips_delivery_without_raising(monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", None)
    result = deliver_messages(
        [OutboundEmail(to="ada@example.com", subject="Threat", body="Details")]
    )
    assert result["sent"] == []
    assert result["skipped"] == ["ada@example.com"]
    assert result["failed"] == []


def test_smtp_sends_one_message_per_member(monkeypatch):
    delivered = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            self.host = host
            self.port = port

        def __enter__(self):
            return self

        def starttls(self):
            return None

        def login(self, username, password):
            return None

        def send_message(self, email):
            delivered.append((email["To"], email["Subject"], email.get_content()))

        def quit(self):
            return None

    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(settings, "SMTP_PORT", 587)
    monkeypatch.setattr(settings, "SMTP_USERNAME", "alerts")
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "secret")
    monkeypatch.setattr(settings, "SMTP_USE_TLS", True)
    monkeypatch.setattr(settings, "SMTP_USE_SSL", False)
    monkeypatch.setattr("app.notifications.email_alerts.smtplib.SMTP", FakeSMTP)

    result = deliver_messages(
        [
            OutboundEmail(to="ada@example.com", subject="One", body="Body one"),
            OutboundEmail(to="sam@example.com", subject="Two", body="Body two"),
        ]
    )
    assert result["sent"] == ["ada@example.com", "sam@example.com"]
    assert [item[0] for item in delivered] == ["ada@example.com", "sam@example.com"]


def test_detection_emails_a_new_threat_once(monkeypatch):
    create_db_and_tables()
    calls = []

    async def fake_notify(session, alert):
        calls.append(alert.id)
        return {"sent": ["ada@example.com"], "skipped": [], "failed": []}

    monkeypatch.setattr("app.detection.engine.notify_organization_of_threat", fake_notify)
    client_ip = f"203.0.113.{uuid.uuid4().int % 200 + 20}"

    def make_log(request_id: str) -> RequestLog:
        return RequestLog(
            request_id=request_id,
            client_ip=client_ip,
            method="GET",
            path="/orders/1044",
            decision="blocked",
            block_reason="jwt_alg_none",
            status_code=401,
            upstream_id=1,
        )

    with Session(engine) as session:
        first = asyncio.run(process_request_event(session, make_log(_unique("req"))))
        second = asyncio.run(process_request_event(session, make_log(_unique("req"))))

    assert len(first) == 1
    assert first[0].id == second[0].id
    assert second[0].event_count == 2
    assert calls == [first[0].id]
