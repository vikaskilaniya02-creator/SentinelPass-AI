from datetime import timedelta

import pytest

from exceptions import (AccountLockedError, AuthenticationError, PasswordPolicyError,
                        RateLimitExceededError, UserAlreadyExistsError, ValidationError)
from tests.conftest import GOOD_PW, OTHER_PW


def test_register_stores_hash_not_plaintext(ctx, alice):
    assert alice.password_hash != GOOD_PW and GOOD_PW not in alice.password_hash
    assert alice.password_salt and alice.password_algorithm == "pbkdf2_sha256"
    assert "password_hash" not in alice.to_public_dict()


def test_duplicate_username_and_email(ctx, alice):
    with pytest.raises(UserAlreadyExistsError):
        ctx.registration.register("ALICE", "other@example.test", OTHER_PW, ip_label="t")
    with pytest.raises(UserAlreadyExistsError):
        ctx.registration.register("alice2", "alice@example.test", OTHER_PW, ip_label="t")


def test_weak_password_and_bad_input_rejected(ctx):
    with pytest.raises(PasswordPolicyError):
        ctx.registration.register("bob", "bob@example.test", "password123", ip_label="t")
    with pytest.raises(ValidationError):
        ctx.registration.register("b!", "bob@example.test", GOOD_PW, ip_label="t")
    with pytest.raises(ValidationError):
        ctx.registration.register("bobby", "not-an-email", GOOD_PW, ip_label="t")


def test_login_success_creates_session(ctx, alice):
    res = ctx.auth.login("alice", GOOD_PW)
    assert res.status == "SUCCESS" and res.session_token
    assert ctx.sessions.validate_session(res.session_token).user_id == alice.id


def test_errors_are_identical_for_unknown_user_and_wrong_password(ctx, alice):
    with pytest.raises(AuthenticationError) as a:
        ctx.auth.login("alice", "wrong")
    with pytest.raises(AuthenticationError) as b:
        ctx.auth.login("nobody", "wrong")
    assert str(a.value) == str(b.value)


def test_lockout_after_max_failures_and_expiry(ctx, alice, clock):
    for i in range(5):
        with pytest.raises(AuthenticationError):
            ctx.auth.login("alice", f"wrong{i}")
    assert ctx.users.get_by_id(alice.id).locked_until is not None
    clock.advance(seconds=61)  # rate-limit window over, account still locked
    with pytest.raises(AccountLockedError):
        ctx.auth.login("alice", GOOD_PW)
    clock.advance(minutes=16)
    assert ctx.auth.login("alice", GOOD_PW).status == "SUCCESS"


def test_rate_limit_blocks_sixth_attempt(ctx, alice):
    for i in range(4):
        with pytest.raises(AuthenticationError):
            ctx.auth.login("alice", f"wrong{i}")
    ctx.auth.login("alice", GOOD_PW)  # 5th attempt (maybe step-up) still allowed
    with pytest.raises(RateLimitExceededError):
        ctx.auth.login("alice", GOOD_PW)


def test_failed_counter_resets_on_success(ctx, alice, clock):
    for i in range(2):
        with pytest.raises(AuthenticationError):
            ctx.auth.login("alice", f"wrong{i}")
    clock.advance(seconds=61)
    assert ctx.auth.login("alice", GOOD_PW).status == "SUCCESS"
    assert ctx.users.get_by_id(alice.id).failed_login_attempts == 0


def test_medium_risk_requires_step_up(ctx, alice, clock):
    for i in range(4):
        with pytest.raises(AuthenticationError):
            ctx.auth.login("alice", f"wrong{i}")
    clock.advance(seconds=61)
    res = ctx.auth.login("alice", GOOD_PW)
    assert res.status == "STEP_UP_REQUIRED" and res.demo_step_up_code and not res.session_token
    bad = ctx.auth.login("alice", GOOD_PW, step_up_code="nope")
    assert bad.status == "STEP_UP_REQUIRED"  # wrong code does not log in
    res = ctx.auth.login("alice", GOOD_PW)
    ok = ctx.auth.login("alice", GOOD_PW, step_up_code=res.demo_step_up_code)
    assert ok.status == "SUCCESS"


def test_high_risk_restricts_login(ctx, alice, clock):
    ctx.auth.login("alice", GOOD_PW, device_id="home", ip_label="IN-RJ")
    clock.advance(minutes=2)
    res = ctx.auth.login("alice", GOOD_PW, device_id="far", ip_label="US-NY")
    assert res.status == "RESTRICTED" and res.risk.level == "HIGH"
    clock.advance(seconds=61)
    with pytest.raises(AccountLockedError):
        ctx.auth.login("alice", GOOD_PW, device_id="home", ip_label="IN-RJ")
    clock.advance(minutes=6)
    assert ctx.auth.login("alice", GOOD_PW, device_id="home", ip_label="IN-RJ").status in ("SUCCESS", "STEP_UP_REQUIRED")


def test_change_password_flow(ctx, alice, clock):
    with pytest.raises(AuthenticationError):
        ctx.auth.change_password("alice", "wrong", OTHER_PW)
    with pytest.raises(PasswordPolicyError):
        ctx.auth.change_password("alice", GOOD_PW, "password123")
    with pytest.raises(PasswordPolicyError):  # same as current
        ctx.auth.change_password("alice", GOOD_PW, GOOD_PW)
    ctx.auth.change_password("alice", GOOD_PW, OTHER_PW)
    assert ctx.auth.login("alice", OTHER_PW).status == "SUCCESS"
    clock.advance(seconds=61)
    with pytest.raises(AuthenticationError):
        ctx.auth.login("alice", GOOD_PW)


def test_password_history_blocks_reuse_and_new_salt(ctx, alice):
    old_salt = alice.password_salt
    ctx.auth.change_password("alice", GOOD_PW, OTHER_PW)
    user = ctx.users.get_by_id(alice.id)
    assert user.password_salt != old_salt
    with pytest.raises(PasswordPolicyError) as e:
        ctx.auth.change_password("alice", OTHER_PW, GOOD_PW)  # previous password
    assert "recently" in e.value.details["reasons"][0]
    assert len(ctx.history.recent(alice.id, 10)) == 1


def test_history_is_pruned(ctx, alice):
    pws = [f"Unique-Phrase-Number-{i}-Zq!" for i in range(8)]
    cur = GOOD_PW
    for p in pws:
        ctx.auth.change_password("alice", cur, p)
        cur = p
        ctx.rate_limiter.reset()
    assert len(ctx.history.recent(alice.id, 50)) == ctx.settings.password_history_count


def test_changing_password_destroys_sessions(ctx, alice):
    token = ctx.auth.login("alice", GOOD_PW).session_token
    ctx.auth.change_password("alice", GOOD_PW, OTHER_PW)
    from exceptions import SessionExpiredError
    with pytest.raises(SessionExpiredError):
        ctx.sessions.validate_session(token)
