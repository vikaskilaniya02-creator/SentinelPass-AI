"""AI package. `build_provider` picks a provider and ALWAYS falls back to local."""
from __future__ import annotations

from ai.api_provider import AnthropicProvider, OpenAIProvider
from ai.base_provider import AISecurityProvider
from ai.local_provider import LocalRuleBasedProvider


def build_provider(settings) -> AISecurityProvider:
    name, key = settings.ai_provider, settings.ai_api_key
    if name == "anthropic" and key:
        return AnthropicProvider(key, settings.ai_model)
    if name == "openai" and key:
        return OpenAIProvider(key, settings.ai_model)
    return LocalRuleBasedProvider()  # default, missing key, or unsupported name
