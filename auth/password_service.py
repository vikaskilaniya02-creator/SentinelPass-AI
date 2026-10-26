"""Shared password-setting logic used by change-password and reset-password:
policy check -> reuse check (current + history) -> archive old hash -> store new hash."""
from __future__ import annotations

from audit.audit_logger import AuditLogger, EventType
from config.settings import Settings
from database.repositories import PasswordHistoryRepository, UserRepository
from exceptions import PasswordPolicyError
from models.user import User
from security.password_hasher import PasswordHasher, hasher_for
from security.password_policy import PasswordPolicy
from security.password_strength import StrengthResult
from utils import Clock, utcnow


class PasswordService:
    def __init__(self, settings: Settings, users: UserRepository, history: PasswordHistoryRepository,
                 hasher: PasswordHasher, policy: PasswordPolicy, audit: AuditLogger,
                 clock: Clock = utcnow) -> None:
        self.settings, self.users, self.history = settings, users, history
        self.hasher, self.policy, self.audit, self.clock = hasher, policy, audit, clock

    def validate(self, user: User, new_password: str) -> StrengthResult:
        result = self.policy.enforce(new_password, user.username, user.email)
        self._ensure_not_reused(user, new_password)
        return result

    def _ensure_not_reused(self, user: User, new_password: str) -> None:
        candidates = [(user.password_hash, user.password_salt, user.password_algorithm, user.password_iterations)]
        for row in self.history.recent(user.id, self.settings.password_history_count):
            candidates.append((row["password_hash"], row["password_salt"],
                               row["password_algorithm"], row["password_iterations"]))
        for stored_hash, salt, algorithm, iterations in candidates:
            if hasher_for(algorithm, iterations).verify_password(new_password, stored_hash, salt):
                self.audit.log(EventType.PASSWORD_REUSE_BLOCKED, "WARNING", user.id)
                raise PasswordPolicyError(reasons=["This password was used recently."])

    def apply(self, user: User, new_password: str, result: StrengthResult) -> None:
        now = self.clock()
        self.history.add(user.id, user.password_hash, user.password_salt,
                         user.password_algorithm, user.password_iterations, now)
        hashed = self.hasher.hash_password(new_password)  # fresh random salt every time
        self.users.update_password(user.id, password_hash=hashed.hash, password_salt=hashed.salt,
                                   algorithm=hashed.algorithm, iterations=hashed.iterations,
                                   score=result.score, now=now)
        self.history.prune(user.id, self.settings.password_history_count)

    def set_password(self, user: User, new_password: str) -> StrengthResult:
        result = self.validate(user, new_password)
        self.apply(user, new_password, result)
        return result
