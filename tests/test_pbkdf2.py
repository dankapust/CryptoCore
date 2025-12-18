import os

import pytest

from pycryptocore.kdf import (
    PBKDF2_ITERATIONS,
    SALT_SIZE,
    derive_key,
    pbkdf2_hmac_sha256,
    generate_salt,
)


def test_pbkdf2_rfc6070_sha256_vectors():
    # SHA-256 variants of RFC 6070 vectors
    cases = [
        (b"password", b"salt", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
        (b"password", b"salt", 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
        (b"password", b"salt", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
        (
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            40,
            # Проверено against hashlib.pbkdf2_hmac('sha256', ...), Python 3.12
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9",
        ),
    ]
    for pwd, salt, iterations, dklen, expected_hex in cases:
        derived = pbkdf2_hmac_sha256(pwd, salt, iterations, dklen)
        assert derived.hex() == expected_hex


def test_pbkdf2_reproducible_and_length():
    salt = generate_salt()
    pwd = "example-password"
    key1 = pbkdf2_hmac_sha256(pwd, salt, PBKDF2_ITERATIONS, 32)
    key2 = pbkdf2_hmac_sha256(pwd, salt, PBKDF2_ITERATIONS, 32)
    assert key1 == key2
    assert len(key1) == 32
    short_key = pbkdf2_hmac_sha256(pwd, salt, PBKDF2_ITERATIONS, 1)
    assert len(short_key) == 1


def test_pbkdf2_salt_randomness():
    salts = {generate_salt().hex() for _ in range(100)}
    assert len(salts) == 100  # no duplicates across 100 draws
    for s in salts:
        assert len(bytes.fromhex(s)) == SALT_SIZE


def test_derive_key_context_separation():
    master = os.urandom(32)
    key_enc = derive_key(master, "encryption", 32)
    key_auth = derive_key(master, "authentication", 32)
    assert len(key_enc) == 32
    assert len(key_auth) == 32
    assert key_enc != key_auth

