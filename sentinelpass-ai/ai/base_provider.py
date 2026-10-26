"""AI provider interface.

Providers receive ONLY sanitised feature dictionaries and return UNTRUSTED
output (dict or JSON string). The gateway validates it before anyone sees it.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AIAssessment:
    risk: str
    explanation: str
    recommendations: list[str] = field(default_factory=list)
    source: str = "local"   # local | api:<name> | local-fallback

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class AISecurityProvider(ABC):
    name = "base"

    @abstractmethod
    def assess_password(self, features: dict) -> Any: ...

    @abstractmethod
    def explain_risk(self, summary: dict) -> Any: ...

    @abstractmethod
    def summarize_events(self, summary: dict) -> Any: ...
