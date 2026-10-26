"""Demo session management. The plaintext token is returned ONCE to the caller;
only its SHA-256 hash is stored, so a DB leak does not hand out live sessions."""
from __future__ import annotations

from datetime import timedelta

from audit.audit_logger import AuditLogger, EventType
from database.repositories import SessionRepository
from exceptions import SessionExpiredError
from models.user import Session
from security.token_manager import generate_token, hash_token
from utils import Clock, utcnow


class SessionManager:
    def __init__(self, repo: SessionRepository, audit: AuditLogger, expiry_minutes: int = 30,
                 clock: Clock = utcnow) -> None:
        self.repo, self.audit, self.clock = repo, audit, clock
        self.expiry = timedelta(minutes=expiry_minutes)

    def create_session(self, user_id: int) -> str:
        token = generate_token(32)
        now = self.clock()
        self.repo.create(user_id, hash_token(token), now, now + self.expiry)
        self.audit.log(EventType.SESSION_CREATED, "INFO", user_id)
        return token

    def validate_session(self, token: str) -> Session:
        session = self.repo.get_by_hash(hash_token(token or ""))
        if session is None:
            raise SessionExpiredError()
        if session.expires_at <= self.clock():
            self.repo.delete_by_hash(hash_token(token))
            self.audit.log(EventType.SESSION_EXPIRED, "INFO", session.user_id)
            raise SessionExpiredError()
        return session

    def refresh_session(self, token: str) -> Session:
        session = self.validate_session(token)
        now = self.clock()
        self.repo.touch(session.id, now, now + self.expiry)
        return self.repo.get_by_hash(hash_token(token))

    def destroy_session(self, token: str) -> None:
        session = self.repo.get_by_hash(hash_token(token or ""))
        self.repo.delete_by_hash(hash_token(token or ""))
        if session:
            self.audit.log(EventType.SESSION_DESTROYED, "INFO", session.user_id)

    def destroy_user_sessions(self, user_id: int) -> None:
        self.repo.delete_for_user(user_id)
