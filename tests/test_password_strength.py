from security.password_policy import PasswordPolicy
from security.password_strength import analyze_password
from exceptions import PasswordPolicyError
import pytest


def test_common_password_is_weak():
    r = analyze_password("password123")
    assert r.features["common_password_match"] and r.score <= 10 and r.risk_level == "HIGH"


def test_leet_variant_is_detected_as_common():
    assert analyze_password("P@ssw0rd!").features["common_password_match"]


def test_short_password_capped():
    assert analyze_password("aB3$xY").score <= 25


def test_strong_passphrase():
    r = analyze_password("Correct-Horse-Battery-9!")
    assert r.score >= 85 and r.rating == "VERY_STRONG"


def test_username_similarity_penalised():
    base = analyze_password("vikash-secure-77X!").score
    sim = analyze_password("vikash-secure-77X!", username="vikash")
    assert sim.score < base and sim.features["username_similarity"] == 1.0


def test_patterns_detected():
    r = analyze_password("abc123qwertyAAA")
    f = r.features
    assert f["sequential_pattern"] and f["keyboard_pattern"] and f["repeated_pattern"]


def test_date_pattern():
    assert analyze_password("Summer-2024-Trip!").features["date_pattern"]


def test_result_structure_and_no_password_leak():
    r = analyze_password("My-Unique-Pass-77!")
    d = r.to_dict()
    assert {"score", "rating", "risk_level", "estimated_entropy", "warnings", "recommendations"} <= d.keys()
    assert "My-Unique-Pass-77!" not in str(r.safe_features()) + str(d)


def test_policy_enforce_rejects_and_accepts():
    p = PasswordPolicy(12, 40)
    with pytest.raises(PasswordPolicyError) as e:
        p.enforce("short1!")
    assert e.value.details["reasons"]
    assert p.enforce("Correct-Horse-Battery-9!").score >= 40
