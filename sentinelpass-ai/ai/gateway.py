"""The single door between the app and any AI provider.

sanitize (whitelist) -> provider -> validate -> (on ANY failure) local fallback.
"""
from __future__ import annotations

from typing import Any, Callable

from ai.base_provider import AIAssessment, AISecurityProvider
from ai.local_provider import LocalRuleBasedProvider
from ai.output_validator import validate_output
from security.risk_engine import LEVELS, SIGNAL_NAMES


def _bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    raise ValueError("expected bool")


def _int(lo: int = 0, hi: int = 1_000_000) -> Callable[[Any], int]:
    return lambda v: max(lo, min(hi, int(v)))


def _float(lo: float = 0.0, hi: float = 1000.0) -> Callable[[Any], float]:
    return lambda v: max(lo, min(hi, float(v)))


def _level(v: Any) -> str:
    v = str(v).upper()
    if v not in LEVELS:
        raise ValueError("bad level")
    return v


def _signals(v: Any) -> list[dict]:
    return [{"name": s["name"], "weight": max(0, min(100, int(s["weight"])))}
            for s in v if isinstance(s, dict) and s.get("name") in SIGNAL_NAMES][:12]


def _dist(v: Any) -> dict:
    return {k: max(0, int(v.get(k, 0))) for k in LEVELS}


PASSWORD_SPEC = {
    "length": _int(0, 1024), "has_uppercase": _bool, "has_lowercase": _bool, "has_numbers": _bool,
    "has_special": _bool, "repeated_pattern": _bool, "sequential_pattern": _bool, "keyboard_pattern": _bool,
    "date_pattern": _bool, "common_password_match": _bool, "username_similarity": _float(0, 1),
    "entropy_estimate": _float(0, 10_000), "strength_score": _int(0, 100),
}
RISK_SPEC = {"score": _int(0, 100), "level": _level, "signals": _signals}
EVENTS_SPEC = {
    "total_users": _int(), "active_users": _int(), "locked_accounts": _int(), "successful_logins": _int(),
    "failed_logins": _int(), "suspicious_logins": _int(), "reset_requests": _int(),
    "weak_password_pct": _float(0, 100), "risk_distribution": _dist,
}


def sanitize(payload: dict, spec: dict) -> dict:
    """Keep only whitelisted keys with validated types. Anything else is dropped."""
    clean = {}
    for key, coerce in spec.items():
        if key in payload:
            try:
                clean[key] = coerce(payload[key])
            except (ValueError, TypeError, KeyError, AttributeError):
                continue
    return clean


class AIGateway:
    def __init__(self, provider: AISecurityProvider) -> None:
        self.provider = provider
        self.fallback = LocalRuleBasedProvider()

    def _run(self, method: str, payload: dict, spec: dict, risks: tuple[str, ...],
             force_risk: str | None = None) -> AIAssessment:
        clean = sanitize(payload, spec)
        source = self.provider.name if self.provider.name == "local" else f"api:{self.provider.name}"
        try:
            data = validate_output(getattr(self.provider, method)(clean), risks)
        except Exception:  # any provider/network/validation failure => deterministic local advisor
            data = validate_output(getattr(self.fallback, method)(clean), risks)
            source = "local-fallback" if self.provider.name != "local" else "local"
        return AIAssessment(force_risk or data["risk"], data["explanation"], data["recommendations"], source)

    def assess_password(self, features: dict) -> AIAssessment:
        return self._run("assess_password", features, PASSWORD_SPEC, ("LOW", "MEDIUM", "HIGH"))

    def explain_risk(self, summary: dict) -> AIAssessment:
        clean_level = sanitize(summary, RISK_SPEC).get("level")
        # The displayed risk label ALWAYS comes from the deterministic engine, not from the AI.
        return self._run("explain_risk", summary, RISK_SPEC, LEVELS, force_risk=clean_level)

    def summarize_events(self, summary: dict) -> AIAssessment:
        return self._run("summarize_events", summary, EVENTS_SPEC, ("LOW", "MEDIUM", "HIGH"))
