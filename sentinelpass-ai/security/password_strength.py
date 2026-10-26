"""Password strength analyser.

IMPORTANT LIMITS: this is a heuristic. Entropy estimates assume random
characters, which humans do not choose. A high score does NOT prove a password
is safe (it may be in a breach list), and a low score does not prove it is
cracked. Real systems should also check breached-password corpora.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher

DISCLAIMER = ("Scores are heuristic. Entropy assumes random characters and overestimates "
              "human-chosen passwords; breach-list checks are not performed.")

COMMON_PASSWORDS = frozenset("""
password password1 password123 passw0rd p@ssw0rd letmein welcome welcome1 admin admin123
administrator login master hello hello123 iloveyou monkey dragon sunshine princess football
baseball superman batman trustno1 shadow michael jordan harley ranger starwars whatever
freedom qwerty qwerty123 qwertyuiop asdfgh asdfghjkl zxcvbnm 123456 1234567 12345678 123456789
1234567890 111111 000000 abc123 abcdef secret changeme default test test123 guest root toor
access mustang soccer charlie donald computer internet cheese summer winter spring pokemon
cricket india india123 krishna ganesh iloveu 696969 654321 666666 121212 passpass
correcthorsebatterystaple
""".split())

KEYBOARD_PATTERNS = ("qwerty", "qwertz", "azerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz2wsx",
                     "qweasd", "poiuy", "lkjhg", "mnbvc", "1q2w3e", "!qaz", "wsxedc")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


@dataclass
class StrengthResult:
    score: int
    rating: str
    risk_level: str
    estimated_entropy: float
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    features: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"score": self.score, "rating": self.rating, "risk_level": self.risk_level,
                "estimated_entropy": self.estimated_entropy, "warnings": self.warnings,
                "recommendations": self.recommendations, "disclaimer": DISCLAIMER}

    def safe_features(self) -> dict:
        """Derived characteristics only. Contains NO password characters."""
        return dict(self.features)


def _has_sequence(p: str, min_run: int = 3) -> bool:
    s, run, direction = p.lower(), 1, 0
    for a, b in zip(s, s[1:]):
        diff = ord(b) - ord(a)
        ok = diff in (1, -1) and a.isalnum() and b.isalnum()
        if ok and direction in (0, diff):
            direction, run = diff, run + 1
        elif ok:
            direction, run = diff, 2
        else:
            direction, run = 0, 1
        if run >= min_run:
            return True
    return False


def _similarity(password: str, other: str) -> float:
    other = other.lower().strip()
    if len(other) < 3:
        return 0.0
    p = password.lower()
    if other in p:
        return 1.0
    return round(SequenceMatcher(None, p, other).ratio(), 2)


def _is_common(password: str) -> bool:
    low = password.lower()
    norm = low.translate(_LEET)
    for candidate in {low, norm}:
        core = re.sub(r"[\d\W_]+$", "", candidate)
        if candidate in COMMON_PASSWORDS or (core and core in COMMON_PASSWORDS):
            return True
    return False


def _rating(score: int) -> tuple[str, str]:
    if score < 25:
        return "VERY_WEAK", "HIGH"
    if score < 45:
        return "WEAK", "HIGH"
    if score < 65:
        return "FAIR", "MEDIUM"
    if score < 85:
        return "STRONG", "LOW"
    return "VERY_STRONG", "LOW"


def analyze_password(password: str, username: str = "", email: str = "") -> StrengthResult:
    n = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    classes = sum([has_lower, has_upper, has_digit, has_special])

    pool = 26 * has_lower + 26 * has_upper + 10 * has_digit + 33 * has_special
    entropy = round(n * math.log2(pool), 1) if pool and n else 0.0

    common = _is_common(password)
    repeated_chars = bool(re.search(r"(.)\1{2,}", password))
    repeated_sub = bool(re.search(r"(.{2,}?)\1", password.lower()))
    sequential = _has_sequence(password)
    keyboard = any(k in password.lower() for k in KEYBOARD_PATTERNS)
    date_like = bool(re.search(r"(19|20)\d{2}", password) or
                     re.search(r"\d{2}[./-]?\d{2}[./-]?(19|20)\d{2}", password))
    user_sim = _similarity(password, username) if username else 0.0
    email_local = email.split("@")[0] if email else ""
    email_sim = _similarity(password, email_local) if email_local else 0.0
    similar_user = user_sim >= 0.6
    similar_email = email_sim >= 0.6

    score = min(n, 20) * 3 + classes * 5 + min(entropy, 80) / 4
    if n < 8:
        score = min(score, 25)
    elif n < 12:
        score = min(score, 55)
    for flag, penalty in ((repeated_chars, 10), (repeated_sub, 10), (sequential, 10),
                          (keyboard, 15), (similar_user, 20), (similar_email, 15), (date_like, 8)):
        if flag:
            score -= penalty
    if common:
        score = min(score, 10)
    score = int(max(0, min(100, round(score))))
    rating, risk = _rating(score)

    warnings: list[str] = []
    recs: list[str] = []
    if n < 12:
        warnings.append("Password is short.")
        recs.append("Use at least 12 characters; a passphrase of 4+ random words is easy to remember.")
    if common:
        warnings.append("Matches a commonly used password (or a trivial variation).")
        recs.append("Avoid common passwords and simple substitutions like 'p@ssw0rd'.")
    if repeated_chars:
        warnings.append("Contains repeated characters.")
    if repeated_sub:
        warnings.append("Contains a repeated substring.")
    if sequential:
        warnings.append("Contains a sequential pattern (abc, 123).")
    if keyboard:
        warnings.append("Contains a keyboard pattern (qwerty, asdf).")
    if similar_user:
        warnings.append("Too similar to the username.")
    if similar_email:
        warnings.append("Too similar to the email address.")
    if date_like:
        warnings.append("Contains a date-like pattern.")
    if warnings and not recs:
        recs.append("Remove predictable patterns; prefer random words or a password-manager password.")
    recs.append("Use a unique password for every account and enable MFA where available.")

    features = {
        "length": n, "has_uppercase": has_upper, "has_lowercase": has_lower,
        "has_numbers": has_digit, "has_special": has_special,
        "repeated_pattern": repeated_chars or repeated_sub, "sequential_pattern": sequential,
        "keyboard_pattern": keyboard, "date_pattern": date_like, "common_password_match": common,
        "username_similarity": max(user_sim, email_sim), "entropy_estimate": entropy,
        "strength_score": score,
    }
    return StrengthResult(score, rating, risk, entropy, warnings, recs, features)
