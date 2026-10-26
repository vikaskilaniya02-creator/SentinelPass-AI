"""Password hashing behind an interface.

The rest of the app depends on `PasswordHasher`, never on a specific algorithm,
so PBKDF2 can be swapped for Argon2id without touching authentication code.
Every stored hash keeps its own algorithm + iterations, so old hashes stay
verifiable after you raise the cost.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class HashedPassword:
    hash: str        # hex
    salt: str        # hex
    algorithm: str
    iterations: int  # PBKDF2 iterations or Argon2 time_cost


def _normalise(password: str) -> bytes:
    # NFKC so visually identical Unicode passwords hash the same (NIST 800-63B).
    return unicodedata.normalize("NFKC", password).encode("utf-8")


class PasswordHasher(ABC):
    algorithm: str

    def __init__(self, iterations: int, salt_length: int = 16) -> None:
        self.iterations = iterations
        self.salt_length = salt_length

    def generate_salt(self) -> bytes:
        """Unique random value per password (CSPRNG)."""
        return secrets.token_bytes(self.salt_length)

    @abstractmethod
    def _derive(self, password: bytes, salt: bytes) -> bytes: ...

    def hash_password(self, password: str, salt: bytes | None = None) -> HashedPassword:
        salt = salt if salt is not None else self.generate_salt()
        digest = self._derive(_normalise(password), salt)
        return HashedPassword(digest.hex(), salt.hex(), self.algorithm, self.iterations)

    def verify_password(self, password: str, stored_hash: str, salt_hex: str) -> bool:
        try:
            salt = bytes.fromhex(salt_hex)
        except ValueError:
            return False
        candidate = self._derive(_normalise(password), salt).hex()
        return hmac.compare_digest(candidate, stored_hash)  # constant-time compare

    def password_hash_metadata(self) -> dict:
        return {"algorithm": self.algorithm, "iterations": self.iterations,
                "salt_length": self.salt_length}


class PBKDF2Hasher(PasswordHasher):
    algorithm = "pbkdf2_sha256"

    def _derive(self, password: bytes, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password, salt, self.iterations)


class Argon2Hasher(PasswordHasher):
    """Optional: needs `pip install argon2-cffi`. Memory-hard, so GPU cracking is costlier."""
    algorithm = "argon2id"
    MEMORY_KIB = 65_536
    PARALLELISM = 2

    def __init__(self, iterations: int = 3, salt_length: int = 16) -> None:
        super().__init__(iterations, salt_length)
        try:
            from argon2.low_level import Type, hash_secret_raw  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("argon2-cffi is not installed (pip install argon2-cffi)") from exc

    def _derive(self, password: bytes, salt: bytes) -> bytes:  # pragma: no cover
        from argon2.low_level import Type, hash_secret_raw
        return hash_secret_raw(password, salt, time_cost=self.iterations,
                               memory_cost=self.MEMORY_KIB, parallelism=self.PARALLELISM,
                               hash_len=32, type=Type.ID)


def hasher_for(algorithm: str, iterations: int, salt_length: int = 16) -> PasswordHasher:
    if algorithm == "pbkdf2_sha256":
        return PBKDF2Hasher(iterations, salt_length)
    if algorithm == "argon2id":  # pragma: no cover
        return Argon2Hasher(iterations, salt_length)
    raise ValueError(f"Unsupported password algorithm: {algorithm}")
