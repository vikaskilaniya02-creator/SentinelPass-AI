"""Central configuration. Everything is overridable by environment variables
(or a local .env file). No secrets are hard-coded."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    app_env: str = "development"
    database_url: str = "sqlite:///data/sentinelpass.db"

    password_hash_algorithm: str = "pbkdf2_sha256"  # or "argon2id" (optional dependency)
    password_hash_iterations: int = 600_000
    salt_length: int = 16
    password_history_count: int = 5
    min_password_length: int = 12
    min_password_score: int = 40

    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 15
    restriction_duration_minutes: int = 5
    reset_token_expiry_minutes: int = 10
    session_expiry_minutes: int = 30
    step_up_expiry_minutes: int = 5

    login_rate_limit: int = 5
    login_rate_window_seconds: int = 60
    reset_rate_limit: int = 3
    reset_rate_window_seconds: int = 600
    reset_confirm_rate_limit: int = 10
    register_rate_limit: int = 5
    register_rate_window_seconds: int = 600

    ai_provider: str = "local"
    ai_api_key: str = ""
    ai_model: str = ""
    enable_ml_anomaly: bool = False

    report_dir: str = "reports/output"
    audit_log_path: str = "data/audit.log"
    mailbox_path: str = "data/demo_mailbox.txt"

    @property
    def database_path(self) -> Path:
        prefix = "sqlite:///"
        if not self.database_url.startswith(prefix):
            raise ValueError("Only sqlite:/// URLs are supported in this version.")
        return Path(self.database_url[len(prefix):])

    @property
    def simulation_results_path(self) -> Path:
        return self.database_path.parent / "simulation_results.json"


def _load_dotenv(path: str = ".env") -> None:
    """Tiny .env reader (no dependency). Real environment variables win."""
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _int(env: dict[str, str], name: str, default: int, minimum: int = 1) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return value


def load_settings(env: dict[str, str] | None = None) -> Settings:
    if env is None:
        _load_dotenv()
        env = dict(os.environ)
    app_env = env.get("APP_ENV", "development")
    # Guard against accidentally weak hashing outside tests.
    min_iter = 1_000 if app_env == "test" else 100_000
    d = Settings()
    return Settings(
        app_env=app_env,
        database_url=env.get("DATABASE_URL", d.database_url),
        password_hash_algorithm=env.get("PASSWORD_HASH_ALGORITHM", d.password_hash_algorithm),
        password_hash_iterations=_int(env, "PASSWORD_HASH_ITERATIONS", d.password_hash_iterations, min_iter),
        password_history_count=_int(env, "PASSWORD_HISTORY_COUNT", d.password_history_count),
        max_failed_attempts=_int(env, "MAX_FAILED_ATTEMPTS", d.max_failed_attempts),
        lockout_duration_minutes=_int(env, "LOCKOUT_DURATION", d.lockout_duration_minutes),
        reset_token_expiry_minutes=_int(env, "RESET_TOKEN_EXPIRY", d.reset_token_expiry_minutes),
        session_expiry_minutes=_int(env, "SESSION_EXPIRY", d.session_expiry_minutes),
        ai_provider=env.get("AI_PROVIDER", d.ai_provider).lower(),
        ai_api_key=env.get("AI_API_KEY", ""),
        ai_model=env.get("AI_MODEL", ""),
        enable_ml_anomaly=env.get("ENABLE_ML_ANOMALY", "false").lower() == "true",
    )
