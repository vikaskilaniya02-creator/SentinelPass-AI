"""Custom exceptions.

`public_message` is the ONLY text that may be shown to end users. Technical
detail goes in `details` and is logged through the audit logger, never printed.
"""
from __future__ import annotations


class SentinelPassError(Exception):
    public_message = "Something went wrong."

    def __init__(self, message: str | None = None, **details: object) -> None:
        super().__init__(message or self.public_message)
        self.details = details


class AuthenticationError(SentinelPassError):
    # Deliberately identical for unknown user / wrong password / locked account,
    # so error text cannot be used for account enumeration.
    public_message = "Invalid credentials or account temporarily unavailable."


class AccountLockedError(AuthenticationError):
    pass


class UserAlreadyExistsError(SentinelPassError):
    public_message = "That username or email is not available."


class InvalidResetTokenError(SentinelPassError):
    public_message = "The reset token is invalid or has expired."


class RateLimitExceededError(SentinelPassError):
    public_message = "Too many attempts. Please wait and try again later."


class PasswordPolicyError(SentinelPassError):
    public_message = "The password does not meet the security policy."


class SessionExpiredError(SentinelPassError):
    public_message = "Your session is invalid or has expired. Please log in again."


class ValidationError(SentinelPassError):
    public_message = "Some of the supplied information is invalid."


class AIOutputError(SentinelPassError):
    public_message = "AI output failed validation."
