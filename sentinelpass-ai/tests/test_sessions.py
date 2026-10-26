import pytest

from exceptions import SessionExpiredError


def test_create_validate_destroy(ctx, alice):
    t = ctx.sessions.create_session(alice.id)
    assert ctx.sessions.validate_session(t).user_id == alice.id
    ctx.sessions.destroy_session(t)
    with pytest.raises(SessionExpiredError):
        ctx.sessions.validate_session(t)


def test_expires_after_30_minutes(ctx, alice, clock):
    t = ctx.sessions.create_session(alice.id)
    clock.advance(minutes=31)
    with pytest.raises(SessionExpiredError):
        ctx.sessions.validate_session(t)


def test_refresh_extends_session(ctx, alice, clock):
    t = ctx.sessions.create_session(alice.id)
    clock.advance(minutes=20)
    ctx.sessions.refresh_session(t)
    clock.advance(minutes=20)
    assert ctx.sessions.validate_session(t)


def test_token_not_stored_in_plaintext(ctx, alice):
    t = ctx.sessions.create_session(alice.id)
    with ctx.db.connect() as c:
        stored = c.execute("SELECT session_hash FROM sessions").fetchone()[0]
    assert t != stored and t not in stored and len(t) >= 40


def test_garbage_token_rejected(ctx):
    with pytest.raises(SessionExpiredError):
        ctx.sessions.validate_session("")
