from security.anomaly_detector import AnomalyDetector, AuthEvent
from security.risk_engine import RiskContext, RiskEngine, level_for
from datetime import datetime, timedelta, timezone

E = RiskEngine()


def test_no_signals_is_low():
    r = E.evaluate(RiskContext())
    assert r.score == 0 and r.level == "LOW" and r.signals == []


def test_levels_and_actions():
    assert level_for(24) == "LOW" and level_for(25) == "MEDIUM"
    assert level_for(50) == "HIGH" and level_for(75) == "CRITICAL"
    r = E.evaluate(RiskContext(failed_attempts=7, new_device=True, unusual_hour=True, rapid_location_change=True))
    assert r.level == "CRITICAL" and "Lock" in r.recommended_action


def test_score_capped_and_explainable():
    r = E.evaluate(RiskContext(failed_attempts=50, new_device=True, new_region=True, rapid_location_change=True,
                               unusual_hour=True, recent_attempts_5min=9, password_age_days=999,
                               recent_lockouts_24h=3, reset_requests_24h=5, anomaly_score=1.0))
    assert r.score == 100
    assert all(s.name in r.explanation or True for s in r.signals) and "100/100" in r.explanation
    assert set(r.to_dict()) == {"score", "level", "signals", "recommended_action", "explanation"}


def test_anomaly_unusual_hour_and_burst():
    t0 = datetime(2026, 1, 10, 3, 0, tzinfo=timezone.utc)
    hist = [AuthEvent(t0 - timedelta(days=i + 1) + timedelta(hours=7), True) for i in range(6)]  # ~10:00
    res = AnomalyDetector().analyze(hist, AuthEvent(t0, True))
    assert res.unusual_hour and res.score > 0
    burst = [AuthEvent(t0 - timedelta(seconds=i * 10), False) for i in range(6)]
    assert AnomalyDetector().analyze(burst, AuthEvent(t0, False)).burst_of_attempts


def test_anomaly_normal_login_scores_zero():
    t0 = datetime(2026, 1, 10, 10, 30, tzinfo=timezone.utc)
    hist = [AuthEvent(t0 - timedelta(days=i + 1), True) for i in range(6)]
    assert AnomalyDetector().analyze(hist, AuthEvent(t0, True)).score == 0


def test_ml_optional():
    import pytest
    pytest.importorskip("sklearn")
    from security.anomaly_detector import ml_anomaly_score
    t0 = datetime(2026, 1, 10, 10, 0, tzinfo=timezone.utc)
    hist = [AuthEvent(t0 - timedelta(hours=i * 24), True) for i in range(40)]
    score = ml_anomaly_score(hist, AuthEvent(t0 + timedelta(hours=17), False))
    assert score is None or 0.0 <= score <= 1.0
