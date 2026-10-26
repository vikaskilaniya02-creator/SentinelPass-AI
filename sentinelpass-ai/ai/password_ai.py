"""AI Password Risk Advisor. Sends derived features only, never the password."""
from __future__ import annotations

from ai.base_provider import AIAssessment, AISecurityProvider
from ai.gateway import AIGateway
from security.password_strength import StrengthResult


class PasswordAI:
    def __init__(self, provider: AISecurityProvider) -> None:
        self.gateway = AIGateway(provider)

    def analyze(self, result: StrengthResult) -> AIAssessment:
        return self.gateway.assess_password(result.safe_features())
