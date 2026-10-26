"""Structured security audit logging (DB + JSON-lines file).

Metadata is sanitised: any key that looks sensitive is redacted, so passwords,
tokens, session IDs, hashes and API keys cannot end up in logs even by mistake.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from database.repositories import SecurityEventRepository
from utils import Clock, iso, utcnow


class EventType:
    USER_REGISTERED = "USER_REGISTERED"
    REGISTRATION_FAILED = "REGISTRATION_FAILED"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    LOGIN_RESTRICTED = "LOGIN_RESTRICTED"
    STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
    STEP_UP_SUCCESS = "STEP_UP_SUCCESS"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    PASSWORD_CHANGE_FAILED = "PASSWORD_CHANGE_FAILED"
    PASSWORD_REUSE_BLOCKED = "PASSWORD_REUSE_BLOCKED"
    PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED"
    PASSWORD_RESET_SUCCESS = "PASSWORD_RESET_SUCCESS"
    PASSWORD_RESET_FAILED = "PASSWORD_RESET_FAILED"
    SESSION_CREATED = "SESSION_CREATED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    SESSION_DESTROYED = "SESSION_DESTROYED"
    SUSPICIOUS_LOGIN = "SUSPICIOUS_LOGIN"
    RATE_LIMIT_TRIGGERED = "RATE_LIMIT_TRIGGERED"


_FORBIDDEN_KEY_PARTS = ("password", "passwd", "token", "secret", "api_key", "apikey",
                        "authorization", "session", "hash", "salt", "cookie")


def sanitize_metadata(value: Any, _depth: int = 0) -> Any:
    if _depth > 4:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if any(part in str(k).lower() for part in _FORBIDDEN_KEY_PARTS):
                out[str(k)] = "[REDACTED]"
            else:
                out[str(k)] = sanitize_metadata(v, _depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [sanitize_metadata(v, _depth + 1) for v in value[:50]]
    if isinstance(value, str):
        return value[:200]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:200]


class AuditLogger:
    def __init__(self, repo: SecurityEventRepository, log_path: str | Path | None = None,
                 clock: Clock = utcnow) -> None:
        self.repo, self.clock = repo, clock
        self.log_path = Path(log_path) if log_path else None
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event_type: str, severity: str = "INFO", user_id: int | None = None,
            **metadata: Any) -> dict:
        now = self.clock()
        safe = sanitize_metadata(metadata)
        self.repo.add(user_id, event_type, severity, now, safe)
        record = {"timestamp": iso(now), "event_type": event_type, "severity": severity,
                  "user_id": user_id, "metadata": safe}
        if self.log_path:
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True) + "\n")
        return record
