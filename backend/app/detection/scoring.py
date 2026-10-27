from app.models import RequestLog


def compute_threat_score(log_entry: RequestLog, anomaly_zscore: float = 0.0) -> int:
    """Computes a normalized 0..100 threat score for any request log."""
    base = log_entry.threat_score or 0
    if log_entry.decision == "blocked":
        base = max(base, 75)
    elif log_entry.decision == "rate_limited":
        base = max(base, 65)
    elif log_entry.decision == "monitored":
        base = max(base, 60)

    if log_entry.status_code in (401, 403):
        base = max(base, 50)
    elif log_entry.status_code >= 500:
        base = max(base, 40)

    if anomaly_zscore >= 3.0:
        base = min(100, base + int(min(25, (anomaly_zscore - 2.0) * 8)))

    return min(100, max(0, base))
