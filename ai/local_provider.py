"""Offline, deterministic, rule-based advisor. Always available; no network."""
from __future__ import annotations

from ai.base_provider import AISecurityProvider

SIGNAL_TEXT = {
    "repeated_failed_logins": "several failed password attempts preceded this event",
    "new_device": "the login came from a device not seen before",
    "new_region": "the login came from a region not seen before",
    "rapid_location_change": "the region changed within an hour of the last successful login",
    "unusual_login_time": "the login time is outside the user's usual hours",
    "high_request_frequency": "many attempts occurred in a short period",
    "old_password": "the password has not changed for over a year",
    "previous_lockouts": "the account was locked recently",
    "frequent_reset_requests": "there were repeated password-reset requests",
    "statistical_anomaly": "the statistical detector flagged an unusual pattern",
}


class LocalRuleBasedProvider(AISecurityProvider):
    name = "local"

    def assess_password(self, f: dict) -> dict:
        score = f.get("strength_score", 0)
        risk = "HIGH" if (score < 40 or f.get("common_password_match")) else "MEDIUM" if score < 70 else "LOW"
        reasons, recs = [], []
        if f.get("common_password_match"):
            reasons.append("It matches a commonly used password pattern.")
            recs.append("Avoid common passwords and simple character substitutions.")
        if f.get("length", 0) < 12:
            reasons.append("It is shorter than the recommended 12 characters.")
            recs.append("Use a longer passphrase (4+ random words).")
        if f.get("repeated_pattern") or f.get("sequential_pattern") or f.get("keyboard_pattern"):
            reasons.append("It contains predictable patterns.")
            recs.append("Remove repeats, sequences and keyboard runs.")
        if f.get("username_similarity", 0) >= 0.6:
            reasons.append("It resembles the account identifier.")
            recs.append("Do not base passwords on your username or email.")
        if not reasons:
            reasons.append("It meets length and diversity expectations and shows no known weak patterns.")
        recs += ["Never reuse this password on another site.", "Enable MFA where possible."]
        return {"risk": risk, "explanation": " ".join(reasons), "recommendations": recs[:6]}

    def explain_risk(self, s: dict) -> dict:
        names = [sig["name"] for sig in sorted(s.get("signals", []), key=lambda x: -x["weight"])]
        why = "; ".join(SIGNAL_TEXT.get(n, n) for n in names[:4]) or "no risk signals were triggered"
        level = s.get("level", "LOW")
        recs = {
            "LOW": ["No action needed. Continue normal monitoring."],
            "MEDIUM": ["Require additional verification.", "Ask the user to confirm the activity."],
            "HIGH": ["Temporarily restrict login and review recent events.", "Advise the user to change the password."],
            "CRITICAL": ["Keep the account locked until the owner is verified.", "Review audit logs and reset credentials."],
        }[level]
        return {"risk": level, "explanation": f"Risk is {level} ({s.get('score', 0)}/100) because {why}.",
                "recommendations": recs}

    def summarize_events(self, s: dict) -> dict:
        total = s.get("successful_logins", 0) + s.get("failed_logins", 0)
        ratio = s.get("suspicious_logins", 0) / total if total else 0
        risk = "HIGH" if ratio > 0.3 else "MEDIUM" if ratio > 0.1 else "LOW"
        recs = []
        if s.get("failed_logins", 0) > s.get("successful_logins", 0):
            recs.append("Failed logins exceed successes; review brute-force protections.")
        if s.get("locked_accounts", 0):
            recs.append("Review locked accounts to separate attacks from forgotten passwords.")
        if s.get("weak_password_pct", 0) > 20:
            recs.append("Many weak passwords stored; prompt affected users to update them.")
        if s.get("reset_requests", 0) >= 5:
            recs.append("Elevated reset activity; check for reset abuse.")
        recs.append("Roll out MFA and passkeys to reduce reliance on passwords.")
        return {"risk": risk,
                "explanation": (f"{s.get('suspicious_logins', 0)} of {total} login events were flagged "
                                f"suspicious across {s.get('total_users', 0)} account(s)."),
                "recommendations": recs[:6]}
