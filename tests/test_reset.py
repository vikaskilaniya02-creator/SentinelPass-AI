import pytest

from exceptions import InvalidResetTokenError, PasswordPolicyError, RateLimitExceededError, AuthenticationError
from tests.conftest import GOOD_PW, OTHER_PW


def _token(mailbox):
    return mailbox.messages[-1][1]


def test_unknown_account_gets_no_mail_and_no_error(ctx, mailbox):
    ctx.reset.request_reset("ghost", ip_label="t")
    assert mailbox.messages == []


def test_token_is_hashed_in_db(ctx, alice, mailbox):
    ctx.reset.request_reset("alice", ip_label="t")
    token = _token(mailbox)
    with ctx.db.connect() as c:
        stored = c.execute("SELECT token_hash FROM password_reset_tokens").fetchone()[0]
    assert token not in stored and len(stored) == 64 and len(token) >= 40


def test_reset_works_once_only(ctx, alice, mailbox):
    ctx.reset.request_reset("alice@example.test", ip_label="t")
    t = _token(mailbox)
    ctx.reset.reset_password(t, OTHER_PW, ip_label="t")
    with pytest.raises(InvalidResetTokenError):
        ctx.reset.reset_password(t, "Another-Fresh-Phrase-55#", ip_label="t")
    assert ctx.auth.login("alice", OTHER_PW).status == "SUCCESS"


def test_token_expires_after_10_minutes(ctx, alice, mailbox, clock):
    ctx.reset.request_reset("alice", ip_label="t")
    clock.advance(minutes=11)
    with pytest.raises(InvalidResetTokenError):
        ctx.reset.reset_password(_token(mailbox), OTHER_PW, ip_label="t")


def test_garbage_token_rejected(ctx, alice):
    with pytest.raises(InvalidResetTokenError):
        ctx.reset.reset_password("not-a-real-token", OTHER_PW, ip_label="t")


def test_weak_password_does_not_burn_token(ctx, alice, mailbox):
    ctx.reset.request_reset("alice", ip_label="t")
    t = _token(mailbox)
    with pytest.raises(PasswordPolicyError):
        ctx.reset.reset_password(t, "password123", ip_label="t")
    ctx.reset.reset_password(t, OTHER_PW, ip_label="t")


def test_reset_cannot_reuse_current_password(ctx, alice, mailbox):
    ctx.reset.request_reset("alice", ip_label="t")
    with pytest.raises(PasswordPolicyError):
        ctx.reset.reset_password(_token(mailbox), GOOD_PW, ip_label="t")


def test_new_request_invalidates_old_token(ctx, alice, mailbox):
    ctx.reset.request_reset("alice", ip_label="t")
    first = _token(mailbox)
    ctx.reset.request_reset("alice", ip_label="t")
    with pytest.raises(InvalidResetTokenError):
        ctx.reset.reset_password(first, OTHER_PW, ip_label="t")
    ctx.reset.reset_password(_token(mailbox), OTHER_PW, ip_label="t")


def test_rate_limit_and_per_account_cap(ctx, alice, mailbox):
    for _ in range(3):
        ctx.reset.request_reset("alice", ip_label="t")
    with pytest.raises(RateLimitExceededError):
        ctx.reset.request_reset("alice", ip_label="t")
    # Alternating identifiers must not bypass the cap: only 3 mails ever sent.
    ctx.reset.request_reset("alice@example.test", ip_label="t")
    assert len(mailbox.messages) == 3


def test_reset_clears_lock_and_sessions(ctx, alice, mailbox, clock):
    token = ctx.auth.login("alice", GOOD_PW).session_token
    clock.advance(seconds=61)  # keep the 5 failures inside a fresh rate-limit window
    for i in range(5):
        with pytest.raises(AuthenticationError):
            ctx.auth.login("alice", f"bad{i}")
    ctx.reset.request_reset("alice", ip_label="t")
    ctx.reset.reset_password(_token(mailbox), OTHER_PW, ip_label="t")
    assert ctx.users.get_by_id(alice.id).locked_until is None
    from exceptions import SessionExpiredError
    with pytest.raises(SessionExpiredError):
        ctx.sessions.validate_session(token)
