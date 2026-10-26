"""Password policy. Follows NIST 800-63B ideas: length matters most, no forced
character-class rules, block common passwords, no periodic forced rotation."""
from __future__ import annotations

from exceptions import PasswordPolicyError
from security.password_strength import StrengthResult, analyze_password


class PasswordPolicy:
    def __init__(self, min_length: int = 12, min_score: int = 40, max_length: int = 128) -> None:
        self.min_length, self.min_score, self.max_length = min_length, min_score, max_length

    def evaluate(self, password: str, username: str = "", email: str = "") -> StrengthResult:
        return analyze_password(password, username, email)

    def enforce(self, password: str, username: str = "", email: str = "") -> StrengthResult:
        result = self.evaluate(password, username, email)
        reasons: list[str] = []
        if len(password) < self.min_length:
            reasons.append(f"Must be at least {self.min_length} characters.")
        if len(password) > self.max_length:
            reasons.append(f"Must be at most {self.max_length} characters.")
        if result.features["common_password_match"]:
            reasons.append("Is too common.")
        if result.score < self.min_score:
            reasons.append("Is too predictable (strength score too low).")
        if reasons:
            raise PasswordPolicyError(reasons=reasons)
        return result
