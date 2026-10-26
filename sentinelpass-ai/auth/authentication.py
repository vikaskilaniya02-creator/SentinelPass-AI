"""Login, adaptive authentication and password change.

Decisions are made by deterministic code (rate limiter, lockout, risk engine).
AI is never consulted here and cannot influence the outcome.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from audit.audit_logger import AuditLogger, EventType
from auth.password_service import PasswordService
from auth.registration import normalize_username
from auth.session_manager import SessionManager
from config.settings import Settings
from database.repositories import (LoginEventRepository, ResetTokenRepository,
                                   SecurityEventRepository, UserRepository)
from exceptions import AccountLockedError, AuthenticationError, RateLimitExceededError
from models.user import User
from security.anomaly_detector import AnomalyDetector, AuthEvent
from security.password_hasher import PasswordHasher, hasher_for
from security.rate_limiter import SlidingWindowRateLimiter
from security.risk_engine import RiskAssessment, RiskContext, RiskEngine
from security.token_manager import generate_step_up_code, hash_token, tokens_match
from utils import Clock, parse_iso, utcnow


@dataclass
class LoginResult:
    status: str  # SUCCESS | STEP_UP_REQUIRED | RESTRICTED | LOCKED
    message: str
    user_id: int | None = None
    session_token: str | None = None
    risk: RiskAssessment | None = None
    demo_step_up_code: str | None = None  # DEMO ONLY: a real system sends this out-of-band


class AuthService:
    def __init__(self, *, settings: Settings, users: UserRepository, login_events: LoginEventRepository,
                 security_events: SecurityEventRepository, reset_tokens: ResetTokenRepository,
                 hasher: PasswordHasher, rate_limiter: SlidingWindowRateLimiter, risk_engine: RiskEngine,
                 anomaly: AnomalyDetector, sessions: SessionManager, audit: AuditLogger,
                 passwords: PasswordService, clock: Clock = utcnow) -> None:
        self.settings, self.users, self.login_events = settings, users, login_events
        self.security_events, self.reset_tokens, self.hasher = security_events, reset_tokens, hasher
        self.rate_limiter, self.risk_engine, self.anomaly = rate_limiter, risk_engine, anomaly
        self.sessions, self.audit, self.passwords, self.clock = sessions, audit, passwords, clock
        self._dummy = hasher.hash_password("sentinelpass-dummy-password")
        self._step_up: dict[int, tuple[str, datetime]] = {}

    # ---------------- helpers ----------------
    def _dummy_verify(self, password: str) -> None:
        """Burn the same CPU time for unknown users so timing does not reveal existence."""
        self.hasher.verify_password(password, self._dummy.hash, self._dummy.salt)

    def _verify(self, user: User, password: str) -> bool:
        h = hasher_for(user.password_algorithm, user.password_iterations)
        return h.verify_password(password, user.password_hash, user.password_salt)

    def _record(self, user: User | None, uname: str, now: datetime, success: bool,
                risk: RiskAssessment | None, device: str, ip: str, ua: str, reason: str) -> None:
        self.login_events.add(user_id=user.id if user else None, username_attempted=uname,
                              timestamp=now, success=success,
                              risk_score=risk.score if risk else None,
                              risk_level=risk.level if risk else None,
                              device_id=device, ip_label=ip, user_agent_label=ua, reason=reason)

    def _assess(self, user: User, now: datetime, failed_attempts: int, success: bool,
                device: str, ip: str, ua: str) -> RiskAssessment:
        rows = self.login_events.history_for_user(user.id, 200)
        held_back = ("step_up_required", "restricted", "critical_risk")  # password was correct
        history = [AuthEvent(parse_iso(r["timestamp"]), bool(r["success"]), r["device_id"] or "",
                             r["ip_label"] or "", r["user_agent_label"] or "",
                             credentials_ok=bool(r["success"]) or r["reason"] in held_back) for r in rows]
        successes = [e for e in history if e.success]
        last = successes[-1] if successes else None
        current = AuthEvent(now, success, device, ip, ua)
        anomaly = self.anomaly.analyze(history, current)
        ctx = RiskContext(
            failed_attempts=failed_attempts,
            new_device=bool(successes) and device not in {e.device_id for e in successes},
            new_region=bool(successes) and ip not in {e.ip_label for e in successes},
            rapid_location_change=last is not None and last.ip_label != ip
            and (now - last.timestamp) <= timedelta(minutes=60),
            unusual_hour=anomaly.unusual_hour,
            recent_attempts_5min=sum(1 for e in history if e.timestamp >= now - timedelta(minutes=5)),
            password_age_days=(now - user.password_changed_at).days,
            recent_lockouts_24h=self.security_events.count_for_user_since(
                user.id, EventType.ACCOUNT_LOCKED, now - timedelta(hours=24)),
            reset_requests_24h=self.reset_tokens.count_since(user.id, now - timedelta(hours=24)),
            anomaly_score=anomaly.ml_score,  # hour/burst/failure evidence is scored by explicit rules
        )
        return self.risk_engine.evaluate(ctx)

    # ---------------- login ----------------
    def login(self, username: str, password: str, *, device_id: str = "cli-device",
              ip_label: str = "local", user_agent_label: str = "cli",
              step_up_code: str | None = None) -> LoginResult:
        uname, now = normalize_username(username), self.clock()
        user = self.users.get_by_username(uname)
        try:
            self.rate_limiter.consume("login", f"{uname}|{ip_label}")
        except RateLimitExceededError:
            self._record(user, uname, now, False, None, device_id, ip_label, user_agent_label, "rate_limited")
            self.audit.log(EventType.RATE_LIMIT_TRIGGERED, "WARNING", user.id if user else None,
                           action="login", ip_label=ip_label)
            raise

        if user is None or not user.is_active:
            self._dummy_verify(password)
            self._record(user, uname, now, False, None, device_id, ip_label, user_agent_label,
                         "unknown_user" if user is None else "inactive")
            self.audit.log(EventType.LOGIN_FAILURE, "INFO", user.id if user else None,
                           reason="unknown_or_inactive", ip_label=ip_label)
            raise AuthenticationError()

        if user.is_locked(now):
            self._dummy_verify(password)
            self._record(user, uname, now, False, None, device_id, ip_label, user_agent_label, "account_locked")
            self.audit.log(EventType.LOGIN_FAILURE, "WARNING", user.id, reason="account_locked", ip_label=ip_label)
            raise AccountLockedError(locked_until=user.locked_until)

        if not self._verify(user, password):
            return self._handle_failure(user, uname, now, device_id, ip_label, user_agent_label)

        risk = self._assess(user, now, user.failed_login_attempts, True, device_id, ip_label, user_agent_label)

        if risk.level == "CRITICAL":
            self._lock(user, now, self.settings.lockout_duration_minutes)
            self._record(user, uname, now, False, risk, device_id, ip_label, user_agent_label, "critical_risk")
            self.audit.log(EventType.SUSPICIOUS_LOGIN, "CRITICAL", user.id, score=risk.score, level=risk.level)
            self.audit.log(EventType.ACCOUNT_LOCKED, "CRITICAL", user.id, reason="critical_risk")
            return LoginResult("LOCKED", "Account locked for security reasons. Try again later.",
                               user.id, risk=risk)
        if risk.level == "HIGH":
            self.users.lock(user.id, now + timedelta(minutes=self.settings.restriction_duration_minutes),
                            now, reset_attempts=False)
            self._record(user, uname, now, False, risk, device_id, ip_label, user_agent_label, "restricted")
            self.audit.log(EventType.SUSPICIOUS_LOGIN, "HIGH", user.id, score=risk.score, level=risk.level)
            self.audit.log(EventType.LOGIN_RESTRICTED, "HIGH", user.id,
                           minutes=self.settings.restriction_duration_minutes)
            return LoginResult("RESTRICTED", "Login temporarily restricted. Try again later.",
                               user.id, risk=risk)

        reason = "ok"
        if risk.level == "MEDIUM":
            if not self._step_up_valid(user.id, step_up_code, now):
                code = generate_step_up_code()
                self._step_up[user.id] = (hash_token(code),
                                          now + timedelta(minutes=self.settings.step_up_expiry_minutes))
                self._record(user, uname, now, False, risk, device_id, ip_label, user_agent_label, "step_up_required")
                self.audit.log(EventType.SUSPICIOUS_LOGIN, "WARNING", user.id, score=risk.score, level=risk.level)
                self.audit.log(EventType.STEP_UP_REQUIRED, "WARNING", user.id)
                return LoginResult("STEP_UP_REQUIRED", "Additional verification required.",
                                   user.id, risk=risk, demo_step_up_code=code)
            reason = "step_up_verified"
            self.audit.log(EventType.STEP_UP_SUCCESS, "INFO", user.id)

        self.users.mark_login_success(user.id, now)
        token = self.sessions.create_session(user.id)
        self._record(user, uname, now, True, risk, device_id, ip_label, user_agent_label, reason)
        self.audit.log(EventType.LOGIN_SUCCESS, "INFO", user.id, score=risk.score, level=risk.level)
        return LoginResult("SUCCESS", "Login successful.", user.id, session_token=token, risk=risk)

    def _step_up_valid(self, user_id: int, code: str | None, now: datetime) -> bool:
        entry = self._step_up.pop(user_id, None)  # single use, even on failure
        if not code or entry is None:
            return False
        stored_hash, expires = entry
        return expires > now and tokens_match(stored_hash, hash_token(code))

    def _lock(self, user: User, now: datetime, minutes: int) -> None:
        self.users.lock(user.id, now + timedelta(minutes=minutes), now, reset_attempts=True)

    def _handle_failure(self, user: User, uname: str, now: datetime, device: str, ip: str, ua: str) -> LoginResult:
        attempts = user.failed_login_attempts + 1
        risk = self._assess(user, now, attempts, False, device, ip, ua)
        lock = attempts >= self.settings.max_failed_attempts or risk.level == "CRITICAL"
        if lock:
            self._lock(user, now, self.settings.lockout_duration_minutes)
        else:
            self.users.set_failed_attempts(user.id, attempts, now)
        self._record(user, uname, now, False, risk, device, ip, ua, "bad_password")
        self.audit.log(EventType.LOGIN_FAILURE, "WARNING", user.id, attempts=attempts,
                       score=risk.score, level=risk.level, ip_label=ip)
        if risk.level != "LOW":
            self.audit.log(EventType.SUSPICIOUS_LOGIN, "HIGH" if risk.level != "MEDIUM" else "WARNING",
                           user.id, score=risk.score, level=risk.level)
        if lock:
            self.audit.log(EventType.ACCOUNT_LOCKED, "CRITICAL", user.id, attempts=attempts)
            raise AccountLockedError(attempts=attempts)
        # Message stays generic on purpose (a "3 attempts left" hint would confirm the account exists).
        raise AuthenticationError(attempts=attempts)

    # ---------------- password change ----------------
    def change_password(self, username: str, current_password: str, new_password: str,
                        *, ip_label: str = "local") -> None:
        uname = normalize_username(username)
        try:
            self.rate_limiter.consume("change_password", f"{uname}|{ip_label}")
        except RateLimitExceededError:
            self.audit.log(EventType.RATE_LIMIT_TRIGGERED, "WARNING", None, action="change_password")
            raise
        user = self.users.get_by_username(uname)
        if user is None or not user.is_active:
            self._dummy_verify(current_password)
            raise AuthenticationError()
        if not self._verify(user, current_password):
            self.audit.log(EventType.PASSWORD_CHANGE_FAILED, "WARNING", user.id, reason="bad_current_password")
            raise AuthenticationError()
        self.passwords.set_password(user, new_password)
        self.sessions.destroy_user_sessions(user.id)  # old sessions must not survive a credential change
        self.audit.log(EventType.PASSWORD_CHANGED, "INFO", user.id)
