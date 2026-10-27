from datetime import datetime, timezone
import json
import math
import time
from typing import Dict, List, Tuple
from sqlmodel import Session, select
from app.models import ClientBaseline


class RollingAnomalyDetector:
    """
    Maintains a rolling per-client baseline of request velocity and computes a live Z-score:
    Z = (current_window_rate - mean_rpm) / std_rpm.
    Flags anomalous bursts when Z >= threshold (default 3.0).
    """

    def __init__(self):
        self._buckets: Dict[str, Dict[int, int]] = {}
        self._history: Dict[str, List[int]] = {}

    def record_and_score(self, session: Session, client_key: str) -> Tuple[float, Dict[str, float]]:
        now = int(time.time())
        current_bucket = now // 15  # 15-second micro-windows scaled to RPM
        client_win = self._buckets.setdefault(client_key, {})
        client_win[current_bucket] = client_win.get(current_bucket, 0) + 1

        # Cleanup old buckets and archive completed buckets into history
        hist = self._history.setdefault(client_key, [4, 5, 6, 4, 5, 7, 5, 6, 4, 5, 6, 5])
        for b_id in list(client_win.keys()):
            if b_id < current_bucket - 1:
                completed_rpm = client_win.pop(b_id) * 4
                hist.append(completed_rpm)
                if len(hist) > 30:
                    hist.pop(0)

        current_rpm = client_win[current_bucket] * 4
        mean_rpm = sum(hist) / float(len(hist)) if hist else 5.0
        variance = sum((x - mean_rpm) ** 2 for x in hist) / float(max(1, len(hist)))
        std_rpm = max(1.5, math.sqrt(variance))

        zscore = round((current_rpm - mean_rpm) / std_rpm, 2) if current_rpm > mean_rpm else 0.0

        # Persist summary in ClientBaseline table for Analytics page
        baseline = session.exec(select(ClientBaseline).where(ClientBaseline.client_key == client_key)).first()
        if not baseline:
            baseline = ClientBaseline(
                client_key=client_key,
                window_counts_json=json.dumps(hist[-15:]),
                mean_rpm=round(mean_rpm, 2),
                std_rpm=round(std_rpm, 2),
                current_rpm=current_rpm,
                last_zscore=zscore,
                last_updated_at=datetime.now(timezone.utc),
            )
            session.add(baseline)
        else:
            baseline.window_counts_json = json.dumps(hist[-15:])
            baseline.mean_rpm = round(mean_rpm, 2)
            baseline.std_rpm = round(std_rpm, 2)
            baseline.current_rpm = current_rpm
            baseline.last_zscore = max(zscore, baseline.last_zscore if current_rpm > 12 else zscore)
            baseline.last_updated_at = datetime.now(timezone.utc)
            session.add(baseline)

        return zscore, {
            "current_rpm": current_rpm,
            "mean_rpm": round(mean_rpm, 2),
            "std_rpm": round(std_rpm, 2),
            "zscore": zscore,
        }


anomaly_detector = RollingAnomalyDetector()
