"""Secure token helpers. Uses `secrets` (CSPRNG), never `random`."""
from __future__ import annotations

import hashlib
import hmac
import secrets


def generate_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def generate_step_up_code() -> str:
    return secrets.token_urlsafe(6)  # 8 URL-safe chars (demo step-up verification)


def hash_token(token: str) -> str:
    """Tokens are high-entropy, so a fast SHA-256 is fine (no salt/slow hash needed)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_match(a_hash: str, b_hash: str) -> bool:
    return hmac.compare_digest(a_hash, b_hash)
