import pytest

from security.password_hasher import PBKDF2Hasher, hasher_for


def test_hash_and_verify():
    h = PBKDF2Hasher(1000)
    r = h.hash_password("secret-pass-123")
    assert h.verify_password("secret-pass-123", r.hash, r.salt)


def test_wrong_password_fails():
    h = PBKDF2Hasher(1000)
    r = h.hash_password("secret-pass-123")
    assert not h.verify_password("secret-pass-124", r.hash, r.salt)


def test_salts_are_unique_so_hashes_differ():
    h = PBKDF2Hasher(1000)
    a, b = h.hash_password("same"), h.hash_password("same")
    assert a.salt != b.salt and a.hash != b.hash


def test_hash_is_not_plaintext():
    r = PBKDF2Hasher(1000).hash_password("plaintext-pw")
    assert "plaintext-pw" not in r.hash and len(bytes.fromhex(r.salt)) == 16


def test_bad_salt_hex_returns_false():
    assert PBKDF2Hasher(1000).verify_password("x", "00", "not-hex") is False


def test_unicode_normalisation():
    h = PBKDF2Hasher(1000)
    r = h.hash_password("caf\u00e9-pass")           # precomposed
    assert h.verify_password("cafe\u0301-pass", r.hash, r.salt)  # decomposed


def test_metadata_and_factory():
    h = hasher_for("pbkdf2_sha256", 1234)
    assert h.password_hash_metadata()["iterations"] == 1234
    with pytest.raises(ValueError):
        hasher_for("md5", 1)


def test_iterations_stored_with_hash_allow_cost_upgrade():
    old = PBKDF2Hasher(1000).hash_password("pw-for-upgrade")
    assert hasher_for(old.algorithm, old.iterations).verify_password("pw-for-upgrade", old.hash, old.salt)
