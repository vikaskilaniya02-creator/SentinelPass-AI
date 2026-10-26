"""AI Authentication Risk Explainer + AI Security Analyst.

Input is built from the risk ENGINE's output (signal names + weights) and
aggregate counts. No usernames, IPs, hashes or tokens are ever included.
"""
from __future__ import annotations

from ai.base_provider import AIAssessment, AISecurityProvider
from ai.gateway import AIGateway
from security.risk_engine import RiskAssessment


class RiskExplainer:
    def __init__(self, provider: AISecurityProvider) -> None:
        self.gateway = AIGateway(provider)

    def explain_login(self, assessment: RiskAssessment) -> AIAssessment:
        return self.gateway.explain_risk({
            "score": assessment.score, "level": assessment.level,
            "signals": [{"name": s.name, "weight": s.weight} for s in assessment.signals]})

    def summarize_security(self, stats: dict) -> AIAssessment:
        return self.gateway.summarize_events(stats)
