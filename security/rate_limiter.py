"""In-memory sliding-window rate limiter.

LIMITATION: state lives in this process only. A real deployment needs a shared
store (e.g. Redis) so limits hold across workers and restarts.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from exceptions import RateLimitExceededError
from utils import Clock, utcnow


@dataclass(frozen=True)
class Limit:
    max_attempts: int
    window_seconds: int


class SlidingWindowRateLimiter:
    def __init__(self, limits: dict[str, Limit], clock: Clock = utcnow) -> None:
        self.limits = limits
        self.clock = clock
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def _prune(self, bucket: deque[float], now: float, window: int) -> None:
        while bucket and now - bucket[0] >= window:
            bucket.popleft()

    def is_blocked(self, action: str, key: str) -> bool:
        limit, now = self.limits[action], self.clock().timestamp()
        bucket = self._hits[(action, key)]
        self._prune(bucket, now, limit.window_seconds)
        return len(bucket) >= limit.max_attempts

    def consume(self, action: str, key: str) -> None:
        """Record an attempt; raise if the window is already full."""
        limit, now = self.limits[action], self.clock().timestamp()
        bucket = self._hits[(action, key)]
        self._prune(bucket, now, limit.window_seconds)
        if len(bucket) >= limit.max_attempts:
            retry = int(limit.window_seconds - (now - bucket[0])) + 1
            raise RateLimitExceededError(action=action, retry_after=retry)
        bucket.append(now)

    def reset(self, action: str | None = None, key: str | None = None) -> None:
        for k in [k for k in self._hits if (action is None or k[0] == action) and (key is None or k[1] == key)]:
            del self._hits[k]
