"""Small time helpers shared by every module.

All timestamps are timezone-aware UTC and stored as ISO-8601 strings with a
fixed format, so string comparison in SQL matches chronological order.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable

Clock = Callable[[], datetime]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def parse_iso(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class ManualClock:
    """A controllable clock used by tests and the simulator (callable like utcnow)."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or utcnow()

    def __call__(self) -> datetime:
        return self._now

    def set(self, value: datetime) -> None:
        self._now = value

    def advance(self, **kwargs: float) -> None:
        self._now += timedelta(**kwargs)
