"""Repository layer: the ONLY place that contains SQL. Services never write SQL.
All queries are parameterised (no string-built SQL => no SQL injection)."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from database.connection import Database
from exceptions import UserAlreadyExistsError
from models.user import Session, User
from utils import iso, parse_iso


class UserRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, *, username: str, email: str, password_hash: str, password_salt: str,
               algorithm: str, iterations: int, score: int, now: datetime) -> User:
        ts = iso(now)
        try:
            with self.db.connect() as conn:
                cur = conn.execute(
                    """INSERT INTO users (username, email, password_hash, password_salt,
                       password_algorithm, password_iterations, password_score,
                       created_at, updated_at, password_changed_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (username, email, password_hash, password_salt, algorithm,
                     iterations, score, ts, ts, ts))
                row = conn.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
        except sqlite3.IntegrityError as exc:
            raise UserAlreadyExistsError() from exc
        return User.from_row(row)

    def _one(self, sql: str, params: tuple) -> User | None:
        with self.db.connect() as conn:
            row = conn.execute(sql, params).fetchone()
        return User.from_row(row) if row else None

    def get_by_id(self, user_id: int) -> User | None:
        return self._one("SELECT * FROM users WHERE id=?", (user_id,))

    def get_by_username(self, username: str) -> User | None:
        return self._one("SELECT * FROM users WHERE username=?", (username,))

    def get_by_email(self, email: str) -> User | None:
        return self._one("SELECT * FROM users WHERE email=?", (email,))

    def list_all(self) -> list[User]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
        return [User.from_row(r) for r in rows]

    def update_password(self, user_id: int, *, password_hash: str, password_salt: str,
                        algorithm: str, iterations: int, score: int, now: datetime) -> None:
        ts = iso(now)
        with self.db.connect() as conn:
            conn.execute(
                """UPDATE users SET password_hash=?, password_salt=?, password_algorithm=?,
                   password_iterations=?, password_score=?, password_changed_at=?, updated_at=?
                   WHERE id=?""",
                (password_hash, password_salt, algorithm, iterations, score, ts, ts, user_id))

    def set_failed_attempts(self, user_id: int, attempts: int, now: datetime) -> None:
        with self.db.connect() as conn:
            conn.execute("UPDATE users SET failed_login_attempts=?, updated_at=? WHERE id=?",
                         (attempts, iso(now), user_id))

    def lock(self, user_id: int, until: datetime, now: datetime, reset_attempts: bool = True) -> None:
        with self.db.connect() as conn:
            if reset_attempts:
                conn.execute("UPDATE users SET locked_until=?, failed_login_attempts=0, updated_at=? WHERE id=?",
                             (iso(until), iso(now), user_id))
            else:
                conn.execute("UPDATE users SET locked_until=?, updated_at=? WHERE id=?",
                             (iso(until), iso(now), user_id))

    def clear_lock(self, user_id: int, now: datetime) -> None:
        with self.db.connect() as conn:
            conn.execute("UPDATE users SET locked_until=NULL, failed_login_attempts=0, updated_at=? WHERE id=?",
                         (iso(now), user_id))

    def mark_login_success(self, user_id: int, now: datetime) -> None:
        ts = iso(now)
        with self.db.connect() as conn:
            conn.execute("""UPDATE users SET failed_login_attempts=0, last_login_at=?,
                            locked_until=NULL, updated_at=? WHERE id=?""", (ts, ts, user_id))

    def set_active(self, user_id: int, active: bool, now: datetime) -> None:
        with self.db.connect() as conn:
            conn.execute("UPDATE users SET is_active=?, updated_at=? WHERE id=?",
                         (1 if active else 0, iso(now), user_id))


class PasswordHistoryRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def add(self, user_id: int, password_hash: str, salt: str, algorithm: str,
            iterations: int, now: datetime) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO password_history (user_id, password_hash, password_salt,
                   password_algorithm, password_iterations, created_at) VALUES (?,?,?,?,?,?)""",
                (user_id, password_hash, salt, algorithm, iterations, iso(now)))

    def recent(self, user_id: int, limit: int) -> list[sqlite3.Row]:
        with self.db.connect() as conn:
            return conn.execute(
                "SELECT * FROM password_history WHERE user_id=? ORDER BY id DESC LIMIT ?",
                (user_id, limit)).fetchall()

    def prune(self, user_id: int, keep: int) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """DELETE FROM password_history WHERE user_id=? AND id NOT IN
                   (SELECT id FROM password_history WHERE user_id=? ORDER BY id DESC LIMIT ?)""",
                (user_id, user_id, keep))


class LoginEventRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def add(self, *, user_id: int | None, username_attempted: str, timestamp: datetime,
            success: bool, risk_score: int | None, risk_level: str | None, device_id: str,
            ip_label: str, user_agent_label: str, reason: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO login_events (user_id, username_attempted, timestamp, success,
                   risk_score, risk_level, device_id, ip_label, user_agent_label, reason)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (user_id, username_attempted, iso(timestamp), 1 if success else 0, risk_score,
                 risk_level, device_id, ip_label, user_agent_label, reason))

    def history_for_user(self, user_id: int, limit: int = 200) -> list[sqlite3.Row]:
        """Last `limit` events for a user, oldest first."""
        with self.db.connect() as conn:
            return conn.execute(
                """SELECT * FROM (SELECT * FROM login_events WHERE user_id=? ORDER BY id DESC LIMIT ?)
                   ORDER BY id ASC""", (user_id, limit)).fetchall()

    def recent(self, limit: int = 20) -> list[sqlite3.Row]:
        with self.db.connect() as conn:
            return conn.execute("SELECT * FROM login_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def stats(self) -> dict:
        with self.db.connect() as conn:
            ok = conn.execute("SELECT COUNT(*) FROM login_events WHERE success=1").fetchone()[0]
            bad = conn.execute("SELECT COUNT(*) FROM login_events WHERE success=0").fetchone()[0]
            dist = {r[0]: r[1] for r in conn.execute(
                "SELECT risk_level, COUNT(*) FROM login_events WHERE risk_level IS NOT NULL GROUP BY risk_level")}
        return {"successful": ok, "failed": bad,
                "risk_distribution": {k: dist.get(k, 0) for k in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}}

    def suspicious(self, limit: int = 10) -> list[sqlite3.Row]:
        with self.db.connect() as conn:
            return conn.execute(
                """SELECT * FROM login_events WHERE risk_level IN ('MEDIUM','HIGH','CRITICAL')
                   ORDER BY id DESC LIMIT ?""", (limit,)).fetchall()


class ResetTokenRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, user_id: int, token_hash: str, expires_at: datetime, now: datetime) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, created_at) VALUES (?,?,?,?)",
                (user_id, token_hash, iso(expires_at), iso(now)))

    def get_by_hash(self, token_hash: str) -> sqlite3.Row | None:
        with self.db.connect() as conn:
            return conn.execute("SELECT * FROM password_reset_tokens WHERE token_hash=?",
                                (token_hash,)).fetchone()

    def mark_used(self, token_id: int, now: datetime) -> bool:
        """Atomic one-time use: only the first caller can flip used_at from NULL."""
        with self.db.connect() as conn:
            cur = conn.execute("UPDATE password_reset_tokens SET used_at=? WHERE id=? AND used_at IS NULL",
                               (iso(now), token_id))
            return cur.rowcount == 1

    def invalidate_unused(self, user_id: int, now: datetime) -> None:
        with self.db.connect() as conn:
            conn.execute("UPDATE password_reset_tokens SET used_at=? WHERE user_id=? AND used_at IS NULL",
                         (iso(now), user_id))

    def count_since(self, user_id: int, since: datetime) -> int:
        with self.db.connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id=? AND created_at>=?",
                (user_id, iso(since))).fetchone()[0]


class SessionRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, user_id: int, session_hash: str, now: datetime, expires_at: datetime) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO sessions (user_id, session_hash, created_at, expires_at, last_activity) VALUES (?,?,?,?,?)",
                (user_id, session_hash, iso(now), iso(expires_at), iso(now)))

    def get_by_hash(self, session_hash: str) -> Session | None:
        with self.db.connect() as conn:
            r = conn.execute("SELECT * FROM sessions WHERE session_hash=?", (session_hash,)).fetchone()
        if not r:
            return None
        return Session(r["id"], r["user_id"], parse_iso(r["created_at"]),
                       parse_iso(r["expires_at"]), parse_iso(r["last_activity"]))

    def touch(self, session_id: int, now: datetime, expires_at: datetime) -> None:
        with self.db.connect() as conn:
            conn.execute("UPDATE sessions SET last_activity=?, expires_at=? WHERE id=?",
                         (iso(now), iso(expires_at), session_id))

    def delete_by_hash(self, session_hash: str) -> None:
        with self.db.connect() as conn:
            conn.execute("DELETE FROM sessions WHERE session_hash=?", (session_hash,))

    def delete_for_user(self, user_id: int) -> None:
        with self.db.connect() as conn:
            conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))


class SecurityEventRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def add(self, user_id: int | None, event_type: str, severity: str,
            timestamp: datetime, details: dict) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO security_events (user_id, event_type, severity, timestamp, details_json) VALUES (?,?,?,?,?)",
                (user_id, event_type, severity, iso(timestamp), json.dumps(details, sort_keys=True)))

    def recent(self, limit: int = 20, event_type: str | None = None) -> list[sqlite3.Row]:
        with self.db.connect() as conn:
            if event_type:
                return conn.execute(
                    "SELECT * FROM security_events WHERE event_type=? ORDER BY id DESC LIMIT ?",
                    (event_type, limit)).fetchall()
            return conn.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def count_by_type(self) -> dict[str, int]:
        with self.db.connect() as conn:
            return {r[0]: r[1] for r in conn.execute(
                "SELECT event_type, COUNT(*) FROM security_events GROUP BY event_type")}

    def count_for_user_since(self, user_id: int, event_type: str, since: datetime) -> int:
        with self.db.connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM security_events WHERE user_id=? AND event_type=? AND timestamp>=?",
                (user_id, event_type, iso(since))).fetchone()[0]
