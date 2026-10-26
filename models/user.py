"""Plain data models. `User.to_public_dict()` never includes hash or salt."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from utils import parse_iso


@dataclass
class User:
    id: int
    username: str
    email: str
    password_hash: str
    password_salt: str
    password_algorithm: str
    password_iterations: int
    password_score: int
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None
    password_changed_at: datetime
    failed_login_attempts: int
    locked_until: datetime | None
    is_active: bool

    @classmethod
    def from_row(cls, r: sqlite3.Row) -> "User":
        return cls(
            id=r["id"], username=r["username"], email=r["email"],
            password_hash=r["password_hash"], password_salt=r["password_salt"],
            password_algorithm=r["password_algorithm"],
            password_iterations=r["password_iterations"],
            password_score=r["password_score"],
            created_at=parse_iso(r["created_at"]), updated_at=parse_iso(r["updated_at"]),
            last_login_at=parse_iso(r["last_login_at"]),
            password_changed_at=parse_iso(r["password_changed_at"]),
            failed_login_attempts=r["failed_login_attempts"],
            locked_until=parse_iso(r["locked_until"]), is_active=bool(r["is_active"]),
        )

    def is_locked(self, now: datetime) -> bool:
        return self.locked_until is not None and self.locked_until > now

    def to_public_dict(self) -> dict:
        return {
            "id": self.id, "username": self.username, "email": self.email,
            "created_at": self.created_at.isoformat(),
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "is_active": self.is_active,
        }


@dataclass
class Session:
    id: int
    user_id: int
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
