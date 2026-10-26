"""Transparent hybrid risk engine: rule-based signals + statistical anomaly signal.

Every point of the score comes from a named signal with a fixed weight, so the
decision is fully explainable. AI never changes this score; it only explains it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

SIGNAL_NAMES = (
    "repeated_failed_logins", "new_device", "new_region", "rapid_location_change",
    "unusual_login_time", "high_request_frequency", "old_password", "previous_lockouts",
    "frequent_reset_requests", "statistical_anomaly",
)
LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ACTIONS = {
    "LOW": "Allow normal login.",
    "MEDIUM": "Require additional verification.",
    "HIGH": "Temporarily restrict login.",
    "CRITICAL": "Lock the account and raise a security event.",
}


@dataclass
class RiskContext:
    failed_attempts: int = 0
    new_device: bool = False
    new_region: bool = False
    rapid_location_change: bool = False
    unusual_hour: bool = False
    recent_attempts_5min: int = 0
    password_age_days: int | None = None
    recent_lockouts_24h: int = 0
    reset_requests_24h: int = 0
    anomaly_score: float = 0.0


@dataclass
class Signal:
    name: str
    weight: int
    description: str


@dataclass
class RiskAssessment:
    score: int
    level: str
    signals: list[Signal] = field(default_factory=list)
    recommended_action: str = ""
    explanation: str = ""

    def to_dict(self) -> dict:
        return {"score": self.score, "level": self.level,
                "signals": [s.__dict__ for s in self.signals],
                "recommended_action": self.recommended_action, "explanation": self.explanation}


def level_for(score: int) -> str:
    if score < 25:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 75:
        return "HIGH"
    return "CRITICAL"


class RiskEngine:
    def evaluate(self, ctx: RiskContext) -> RiskAssessment:
        signals: list[Signal] = []

        def add(name: str, weight: int, text: str) -> None:
            if weight > 0:
                signals.append(Signal(name, weight, text))

        if ctx.failed_attempts:
            add("repeated_failed_logins", min(ctx.failed_attempts, 6) * 8,
                f"{ctx.failed_attempts} failed attempt(s) before this event")
        if ctx.new_device:
            add("new_device", 15, "Login from a device not seen before")
        if ctx.new_region:
            add("new_region", 10, "Login from a region not seen before")
        if ctx.rapid_location_change:
            add("rapid_location_change", 25, "Region changed within 60 minutes of the last successful login")
        if ctx.unusual_hour:
            add("unusual_login_time", 10, "Login outside the user's usual hours")
        if ctx.recent_attempts_5min >= 5:
            add("high_request_frequency", 15, f"{ctx.recent_attempts_5min} attempts in the last 5 minutes")
        if ctx.password_age_days is not None and ctx.password_age_days > 365:
            add("old_password", 5, "Password unchanged for over a year")
        if ctx.recent_lockouts_24h:
            add("previous_lockouts", min(ctx.recent_lockouts_24h, 2) * 10, "Account was locked in the last 24 hours")
        if ctx.reset_requests_24h >= 3:
            add("frequent_reset_requests", 10, f"{ctx.reset_requests_24h} reset requests in 24 hours")
        add("statistical_anomaly", int(round(ctx.anomaly_score * 20)), "Optional ML anomaly model flagged the pattern")

        score = min(100, sum(s.weight for s in signals))
        level = level_for(score)
        top = ", ".join(f"{s.name} (+{s.weight})" for s in sorted(signals, key=lambda s: -s.weight)[:4])
        explanation = (f"Score {score}/100 ({level}). Contributing signals: {top}." if signals
                       else f"Score {score}/100 ({level}). No risk signals were triggered.")
        return RiskAssessment(score, level, signals, ACTIONS[level], explanation)
