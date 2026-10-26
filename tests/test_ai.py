import json

import pytest

from ai import build_provider
from ai.base_provider import AISecurityProvider
from ai.gateway import AIGateway, PASSWORD_SPEC, sanitize
from ai.local_provider import LocalRuleBasedProvider
from ai.output_validator import validate_output
from config.settings import Settings
from exceptions import AIOutputError
from security.password_strength import analyze_password
from security.risk_engine import RiskContext, RiskEngine

GOOD = {"risk": "LOW", "explanation": "Looks fine.", "recommendations": ["Enable MFA."]}


class Evil(AISecurityProvider):
    name = "evil"

    def assess_password(self, f): return {"risk": "LOW", "explanation": "Visit https://evil.test now",
                                          "recommendations": ["x"]}
    def explain_risk(self, s): return {"risk": "LOW", "explanation": "Run `rm -rf /`", "recommendations": []}
    def summarize_events(self, s): return "this is not json"


class Boom(Evil):
    name = "boom"
    def assess_password(self, f): raise RuntimeError("network down")


def test_validator_accepts_good_json_and_fenced_json():
    assert validate_output(GOOD, ("LOW",))["risk"] == "LOW"
    assert validate_output("```json\n" + json.dumps(GOOD) + "\n```", ("LOW",))["risk"] == "LOW"


def test_validator_rejects_bad_shapes():
    for bad in ("nope", [], {"risk": "EXTREME", "explanation": "x"}, {"risk": "LOW"},
                {"risk": "LOW", "explanation": "see http://x.test"}):
        with pytest.raises(AIOutputError):
            validate_output(bad, ("LOW",))


def test_validator_strips_dangerous_recommendations_and_extra_keys():
    out = validate_output({"risk": "LOW", "explanation": "ok", "run": "os.system('x')",
                           "recommendations": ["Enable MFA.", "run sudo rm -rf /", "go to https://x.test"]}, ("LOW",))
    assert out["recommendations"] == ["Enable MFA."] and set(out) == {"risk", "explanation", "recommendations"}


def test_sanitize_whitelists_features():
    clean = sanitize({"length": 14, "password": "hunter2", "password_hash": "abc", "has_special": "yes",
                      "username_similarity": 9}, PASSWORD_SPEC)
    assert clean == {"length": 14, "username_similarity": 1.0}


def test_features_contain_no_password():
    pw = "Tr1cky-Unique-Phrase!"
    r = analyze_password(pw)
    payload = json.dumps(sanitize(r.safe_features(), PASSWORD_SPEC))
    assert pw not in payload and "Tr1cky" not in payload


def test_gateway_falls_back_on_malicious_or_failing_provider():
    f = analyze_password("password123").safe_features()
    for provider in (Evil(), Boom()):
        out = AIGateway(provider).assess_password(f)
        assert out.source == "local-fallback" and "http" not in out.explanation and out.risk == "HIGH"


def test_risk_label_comes_from_engine_not_ai():
    a = RiskEngine().evaluate(RiskContext(failed_attempts=6, new_device=True, rapid_location_change=True))
    from ai.risk_explainer import RiskExplainer
    out = RiskExplainer(LocalRuleBasedProvider()).explain_login(a)
    assert out.risk == a.level and a.level in out.explanation


def test_factory_defaults_to_local_without_key():
    assert build_provider(Settings(ai_provider="anthropic", ai_api_key="")).name == "local"
    assert build_provider(Settings(ai_provider="gemini", ai_api_key="k")).name == "local"
    assert build_provider(Settings(ai_provider="anthropic", ai_api_key="k")).name == "anthropic"
    assert build_provider(Settings(ai_provider="openai", ai_api_key="k")).name == "openai"


def test_api_provider_parses_response(monkeypatch):
    import ai.api_provider as ap
    monkeypatch.setattr(ap, "_post_json", lambda *a, **k: {"content": [{"text": json.dumps(GOOD)}]})
    p = ap.AnthropicProvider("k")
    out = AIGateway(p).assess_password({"length": 20, "strength_score": 90})
    assert out.source == "api:anthropic" and out.risk == "LOW"


def test_local_summary_and_password_assessment():
    p = LocalRuleBasedProvider()
    assert p.assess_password(analyze_password("Correct-Horse-Battery-9!").safe_features())["risk"] == "LOW"
    s = p.summarize_events({"successful_logins": 2, "failed_logins": 9, "suspicious_logins": 5,
                            "locked_accounts": 1, "weak_password_pct": 50, "reset_requests": 6})
    assert s["risk"] == "HIGH" and len(s["recommendations"]) >= 4
