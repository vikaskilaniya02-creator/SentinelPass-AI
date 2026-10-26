"""Statistical anomaly detection on (synthetic) authentication events.

Simple, explainable statistics: unusual login hour vs the user's own history
(feeds the risk engine through the `unusual_hour` flag). Bursts of attempts and a
high recent failure ratio are reported as findings only, because the risk engine
already has explicit rules for them. `score` is a diagnostic summary; the risk
engine consumes the flags plus `ml_score`, so no evidence is counted twice. An optional scikit-learn IsolationForest can add a second opinion
(ENABLE_ML_ANOMALY=true).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class AuthEvent:
    timestamp: datetime
    success: bool
    device_id: str = ""
    ip_label: str = ""
    ua_label: str = ""
    # Were the credentials correct? Differs from `success` when the login was held back by a
    # security decision (step-up / restriction): the password was right, so it is NOT a failed guess.
    credentials_ok: bool | None = None

    @property
    def credential_failure(self) -> bool:
        return not (self.success if self.credentials_ok is None else self.credentials_ok)


@dataclass
class AnomalyResult:
    score: float = 0.0                       # 0.0 (normal) .. 1.0 (very unusual)
    findings: list[str] = field(default_factory=list)
    unusual_hour: bool = False
    burst_of_attempts: bool = False
    ml_score: float = 0.0                    # optional IsolationForest component only


def _circular_hour_distance(a: int, b: int) -> int:
    d = abs(a - b) % 24
    return min(d, 24 - d)


def ml_anomaly_score(history: list[AuthEvent], current: AuthEvent) -> float | None:
    """Optional IsolationForest score in 0..1, or None if unavailable/too little data."""
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return None
    if len(history) < 20:
        return None

    def feats(events: list[AuthEvent]) -> list[list[float]]:
        out, prev = [], None
        for e in events:
            gap = (e.timestamp - prev).total_seconds() if prev else 3600.0
            out.append([e.timestamp.hour, 1.0 if e.success else 0.0, math.log1p(max(gap, 0.0))])
            prev = e.timestamp
        return out

    model = IsolationForest(n_estimators=50, random_state=42).fit(feats(history))
    cur = feats(history[-1:] + [current])[-1]
    return float(min(1.0, max(0.0, -model.decision_function([cur])[0] * 2)))


class AnomalyDetector:
    def __init__(self, use_ml: bool = False) -> None:
        self.use_ml = use_ml

    def analyze(self, history: list[AuthEvent], current: AuthEvent) -> AnomalyResult:
        result = AnomalyResult()
        values: list[float] = []

        successes = [e for e in history if e.success]
        hour = current.timestamp.hour
        if len(successes) >= 5:
            nearest = min(_circular_hour_distance(hour, e.timestamp.hour) for e in successes)
            if nearest >= 4:
                result.unusual_hour = True
                values.append(0.6)
                result.findings.append("login_hour_outside_usual_range")
        elif hour < 5:  # too little history: fall back to a plain night-time rule
            result.unusual_hour = True
            values.append(0.3)
            result.findings.append("login_at_night_hours")

        window_start = current.timestamp - timedelta(minutes=5)
        recent = [e for e in history if e.timestamp >= window_start]
        if len(recent) >= 5:
            # Flag only. The risk engine already scores request frequency with its own rule
            # (high_request_frequency), so adding it here too would double-count the same attempts.
            result.burst_of_attempts = True
            result.findings.append("burst_of_attempts")

        last10 = history[-10:]
        if len(last10) >= 5 and sum(1 for e in last10 if e.credential_failure) / len(last10) >= 0.7:
            # Flag only: the risk engine's repeated_failed_logins rule already scores these failures.
            result.findings.append("high_recent_failure_ratio")

        score = min(1.0, sum(values))
        if self.use_ml:
            ml = ml_anomaly_score(history, current)
            if ml is not None:
                result.ml_score = round(ml, 2)
                score = max(score, ml)
                if ml >= 0.5:
                    result.findings.append("ml_isolation_forest_outlier")
        result.score = round(score, 2)
        return result
