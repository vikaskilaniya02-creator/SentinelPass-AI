"""Secure password reset.

* Token = secrets.token_urlsafe(32); only its SHA-256 is stored.
* 10-minute expiry, strictly one-time use (atomic UPDATE).
* The caller always gets the same neutral outcome, whether or not the account exists.
* DEMO ONLY: the "email" goes to a local demo mailbox file, not a real mail server.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Protocol

from audit.audit_logger import AuditLogger, EventType
from auth.password_service import PasswordService
from auth.session_manager import SessionManager
from config.settings import Settings
from database.repositories import ResetTokenRepository, UserRepository
from exceptions import InvalidResetTokenError, PasswordPolicyError, RateLimitExceededError
from security.rate_limiter import SlidingWindowRateLimiter
from security.token_manager import generate_token, hash_token
from utils import Clock, iso, parse_iso, utcnow


class Mailbox(Protocol):
    def deliver(self, to_email: str, token: str) -> None: ...


class FileMailbox:
    """DEMO ONLY mailbox: appends the 'email' to a local text file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def deliver(self, to_email: str, token: str) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(f"=== DEMO ONLY - NOT A REAL EMAIL ===\nTo: {to_email}\n"
                     f"Subject: Password reset\nReset token (valid 10 minutes, one use): {token}\n\n")


class ListMailbox:
    """In-memory mailbox for tests/simulation."""

    def __init__(self) -> None:
        self.messages: list[tuple[str, str]] = []

    def deliver(self, to_email: str, token: str) -> None:
        self.messages.append((to_email, token))


class ResetService:
    def __init__(self, settings: Settings, users: UserRepository, tokens: ResetTokenRepository,
                 passwords: PasswordService, sessions: SessionManager,
                 rate_limiter: SlidingWindowRateLimiter, audit: AuditLogger, mailbox: Mailbox,
                 clock: Clock = utcnow) -> None:
        self.settings, self.users, self.tokens, self.passwords = settings, users, tokens, passwords
        self.sessions, self.rate_limiter, self.audit = sessions, rate_limiter, audit
        self.mailbox, self.clock = mailbox, clock

    def request_reset(self, identifier: str, ip_label: str = "local") -> None:
        """Always returns None. Callers must show a neutral message."""
        ident = (identifier or "").strip().lower()
        try:
            self.rate_limiter.consume("reset", f"{ident}|{ip_label}")
        except RateLimitExceededError:
            self.audit.log(EventType.RATE_LIMIT_TRIGGERED, "WARNING", None, action="reset_request", ip_label=ip_label)
            raise
        now = self.clock()
        user = self.users.get_by_username(ident) or self.users.get_by_email(ident)
        if user is None or not user.is_active:
            hash_token(generate_token())  # similar work either way
            self.audit.log(EventType.PASSWORD_RESET_REQUESTED, "INFO", None, outcome="no_matching_account", ip_label=ip_label)
            return
        window = timedelta(seconds=self.settings.reset_rate_window_seconds)
        if self.tokens.count_since(user.id, now - window) >= self.settings.reset_rate_limit:
            # Per-ACCOUNT cap: stops bypassing the per-identifier limit by alternating username/email.
            self.audit.log(EventType.RATE_LIMIT_TRIGGERED, "WARNING", user.id, action="reset_account_cap")
            return
        self.tokens.invalidate_unused(user.id, now)
        token = generate_token(32)
        self.tokens.create(user.id, hash_token(token), now + timedelta(minutes=self.settings.reset_token_expiry_minutes), now)
        self.mailbox.deliver(user.email, token)
        self.audit.log(EventType.PASSWORD_RESET_REQUESTED, "INFO", user.id, outcome="token_issued", ip_label=ip_label)

    def reset_password(self, token: str, new_password: str, ip_label: str = "local") -> None:
        try:
            self.rate_limiter.consume("reset_confirm", ip_label)  # slows token guessing
        except RateLimitExceededError:
            self.audit.log(EventType.RATE_LIMIT_TRIGGERED, "WARNING", None, action="reset_confirm")
            raise
        now = self.clock()
        row = self.tokens.get_by_hash(hash_token(token or ""))
        if row is None or row["used_at"] is not None or parse_iso(row["expires_at"]) <= now:
            self.audit.log(EventType.PASSWORD_RESET_FAILED, "WARNING", row["user_id"] if row else None,
                           reason="invalid_or_expired", ip_label=ip_label)
            raise InvalidResetTokenError()
        user = self.users.get_by_id(row["user_id"])
        if user is None or not user.is_active:
            raise InvalidResetTokenError()
        try:
            result = self.passwords.validate(user, new_password)  # policy first: don't burn token on a weak password
        except PasswordPolicyError:
            self.audit.log(EventType.PASSWORD_RESET_FAILED, "INFO", user.id, reason="policy")
            raise
        if not self.tokens.mark_used(row["id"], now):  # atomic: loses the race => invalid
            raise InvalidResetTokenError()
        self.passwords.apply(user, new_password, result)
        self.users.clear_lock(user.id, now)
        self.sessions.destroy_user_sessions(user.id)
        self.audit.log(EventType.PASSWORD_RESET_SUCCESS, "INFO", user.id)
