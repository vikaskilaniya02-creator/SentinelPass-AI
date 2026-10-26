"""User registration."""
from __future__ import annotations

import re

from audit.audit_logger import AuditLogger, EventType
from database.repositories import UserRepository
from exceptions import UserAlreadyExistsError, ValidationError
from models.user import User
from security.password_hasher import PasswordHasher
from security.password_policy import PasswordPolicy
from security.rate_limiter import SlidingWindowRateLimiter
from utils import Clock, utcnow

USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_username(username: str) -> str:
    return (username or "").strip().lower()


class RegistrationService:
    def __init__(self, users: UserRepository, hasher: PasswordHasher, policy: PasswordPolicy,
                 rate_limiter: SlidingWindowRateLimiter, audit: AuditLogger, clock: Clock = utcnow) -> None:
        self.users, self.hasher, self.policy = users, hasher, policy
        self.rate_limiter, self.audit, self.clock = rate_limiter, audit, clock

    def register(self, username: str, email: str, password: str, ip_label: str = "local") -> User:
        self.rate_limiter.consume("register", ip_label)
        uname, mail = normalize_username(username), (email or "").strip().lower()
        if not USERNAME_RE.match(uname):
            raise ValidationError("Username must be 3-32 characters: letters, digits, '_', '.', '-'.")
        if not EMAIL_RE.match(mail) or len(mail) > 254:
            raise ValidationError("Please enter a valid email address.")
        result = self.policy.enforce(password, uname, mail)
        hashed = self.hasher.hash_password(password)
        try:
            user = self.users.create(username=uname, email=mail, password_hash=hashed.hash,
                                     password_salt=hashed.salt, algorithm=hashed.algorithm,
                                     iterations=hashed.iterations, score=result.score, now=self.clock())
        except UserAlreadyExistsError:
            self.audit.log(EventType.REGISTRATION_FAILED, "INFO", None, reason="duplicate", ip_label=ip_label)
            raise
        self.audit.log(EventType.USER_REGISTERED, "INFO", user.id, ip_label=ip_label)
        return user
