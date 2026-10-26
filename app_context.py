"""Wires every component together (simple dependency injection).

Services receive their collaborators explicitly, which keeps them testable and
lets tests/simulator swap the clock and the mailbox.
"""
from __future__ import annotations

from dataclasses import dataclass

from ai import build_provider
from ai.password_ai import PasswordAI
from ai.risk_explainer import RiskExplainer
from audit.audit_logger import AuditLogger
from auth.authentication import AuthService
from auth.password_reset import FileMailbox, Mailbox, ResetService
from auth.password_service import PasswordService
from auth.registration import RegistrationService
from auth.session_manager import SessionManager
from config.settings import Settings, load_settings
from database.connection import Database
from database.repositories import (LoginEventRepository, PasswordHistoryRepository,
                                   ResetTokenRepository, SecurityEventRepository,
                                   SessionRepository, UserRepository)
from database.schema import init_schema
from security.anomaly_detector import AnomalyDetector
from security.password_hasher import hasher_for
from security.password_policy import PasswordPolicy
from security.rate_limiter import Limit, SlidingWindowRateLimiter
from security.risk_engine import RiskEngine
from utils import Clock, utcnow


@dataclass
class AppContext:
    settings: Settings
    clock: Clock
    db: Database
    users: UserRepository
    history: PasswordHistoryRepository
    login_events: LoginEventRepository
    security_events: SecurityEventRepository
    reset_tokens: ResetTokenRepository
    policy: PasswordPolicy
    rate_limiter: SlidingWindowRateLimiter
    audit: AuditLogger
    risk_engine: RiskEngine
    sessions: SessionManager
    registration: RegistrationService
    auth: AuthService
    reset: ResetService
    password_ai: PasswordAI
    risk_explainer: RiskExplainer
    mailbox: Mailbox


def build_context(settings: Settings | None = None, *, clock: Clock = utcnow,
                  mailbox: Mailbox | None = None) -> AppContext:
    s = settings or load_settings()
    db = Database(s.database_path)
    init_schema(db)
    users, history = UserRepository(db), PasswordHistoryRepository(db)
    login_events, sec_events = LoginEventRepository(db), SecurityEventRepository(db)
    reset_tokens, session_repo = ResetTokenRepository(db), SessionRepository(db)

    hasher = hasher_for(s.password_hash_algorithm, s.password_hash_iterations, s.salt_length)
    policy = PasswordPolicy(s.min_password_length, s.min_password_score)
    limiter = SlidingWindowRateLimiter({
        "login": Limit(s.login_rate_limit, s.login_rate_window_seconds),
        "change_password": Limit(s.login_rate_limit, s.login_rate_window_seconds),
        "reset": Limit(s.reset_rate_limit, s.reset_rate_window_seconds),
        "reset_confirm": Limit(s.reset_confirm_rate_limit, s.reset_rate_window_seconds),
        "register": Limit(s.register_rate_limit, s.register_rate_window_seconds),
    }, clock)
    audit = AuditLogger(sec_events, s.audit_log_path, clock)
    engine = RiskEngine()
    sessions = SessionManager(session_repo, audit, s.session_expiry_minutes, clock)
    passwords = PasswordService(s, users, history, hasher, policy, audit, clock)
    registration = RegistrationService(users, hasher, policy, limiter, audit, clock)
    auth = AuthService(settings=s, users=users, login_events=login_events, security_events=sec_events,
                       reset_tokens=reset_tokens, hasher=hasher, rate_limiter=limiter, risk_engine=engine,
                       anomaly=AnomalyDetector(use_ml=s.enable_ml_anomaly), sessions=sessions, audit=audit,
                       passwords=passwords, clock=clock)
    mb = mailbox if mailbox is not None else FileMailbox(s.mailbox_path)
    reset = ResetService(s, users, reset_tokens, passwords, sessions, limiter, audit, mb, clock)
    provider = build_provider(s)
    return AppContext(s, clock, db, users, history, login_events, sec_events, reset_tokens, policy,
                      limiter, audit, engine, sessions, registration, auth, reset,
                      PasswordAI(provider), RiskExplainer(provider), mb)
