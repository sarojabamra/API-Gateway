from app.detection.rules import BehavioralTracker
from app.models import RequestLog


def test_admin_role_case_insensitive_does_not_alert():
    tracker = BehavioralTracker()
    log = RequestLog(
        request_id="bfla-case-1",
        client_ip="203.0.113.50",
        user_sub="admin-user",
        user_role="ADMIN",
        method="GET",
        path="/admin/parking-history/101",
        decision="allowed",
        status_code=200,
        upstream_id=2,
    )
    triggered = tracker.evaluate(log, anomaly_zscore=0.0)
    assert not any(r["type"] == "bfla_privilege_probe" for r in triggered)


def test_user_role_on_admin_path_still_alerts():
    tracker = BehavioralTracker()
    log = RequestLog(
        request_id="bfla-case-2",
        client_ip="203.0.113.51",
        user_sub="customer",
        user_role="user",
        method="GET",
        path="/admin/parking-history/101",
        decision="blocked",
        status_code=403,
        upstream_id=2,
        owasp_id="API5",
    )
    triggered = tracker.evaluate(log, anomaly_zscore=0.0)
    assert any(r["type"] == "bfla_privilege_probe" for r in triggered)
