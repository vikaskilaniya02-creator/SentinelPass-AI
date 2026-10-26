import pytest

from exceptions import RateLimitExceededError
from security.rate_limiter import Limit, SlidingWindowRateLimiter


def make(clock):
    return SlidingWindowRateLimiter({"login": Limit(3, 60)}, clock)


def test_blocks_after_limit(clock):
    rl = make(clock)
    for _ in range(3):
        rl.consume("login", "k")
    with pytest.raises(RateLimitExceededError) as e:
        rl.consume("login", "k")
    assert e.value.details["retry_after"] > 0


def test_window_slides(clock):
    rl = make(clock)
    for _ in range(3):
        rl.consume("login", "k")
    clock.advance(seconds=61)
    rl.consume("login", "k")


def test_keys_are_independent_and_reset(clock):
    rl = make(clock)
    for _ in range(3):
        rl.consume("login", "a")
    rl.consume("login", "b")
    assert rl.is_blocked("login", "a") and not rl.is_blocked("login", "b")
    rl.reset("login", "a")
    assert not rl.is_blocked("login", "a")
