from __future__ import annotations

import math
from typing import Union

from ..crypto_core import KEY_SIZE
from ..csprng import generate_random_bytes
from ..mac import HMAC

# Default parameters
SALT_SIZE = 16
PBKDF2_ITERATIONS = 100_000
HASH_LEN = 32  # SHA-256 output size in bytes


def _to_bytes(data: Union[str, bytes]) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("utf-8")
    raise TypeError("password must be str or bytes")


def generate_salt(size: int = SALT_SIZE) -> bytes:
    if size <= 0:
        raise ValueError("salt size must be positive")
    return generate_random_bytes(size)


def _prf(password: bytes, msg: bytes) -> bytes:
    # HMAC-SHA256(PRF) using our own implementation
    return HMAC(password, "sha256").compute(msg)


def pbkdf2_hmac_sha256(password: Union[str, bytes], salt: bytes, iterations: int, dklen: int) -> bytes:
    """
    PBKDF2-HMAC-SHA256 implementation (RFC 2898).
    """
    pwd_bytes_raw = _to_bytes(password)
    pwd_bytes = bytearray(pwd_bytes_raw)
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    if dklen <= 0:
        raise ValueError("dklen must be positive")

    blocks_needed = math.ceil(dklen / HASH_LEN)
    derived = bytearray()

    for block_index in range(1, blocks_needed + 1):
        u = _prf(pwd_bytes, salt + block_index.to_bytes(4, "big"))
        t = bytearray(u)
        for _ in range(1, iterations):
            u = _prf(pwd_bytes, u)
            t = bytearray(a ^ b for a, b in zip(t, u))
        derived.extend(t)

    # Clear password bytes from memory (best effort)
    for i in range(len(pwd_bytes)):
        pwd_bytes[i] = 0

    return bytes(derived[:dklen])


def derive_key_from_password(
    password: Union[str, bytes],
    salt: bytes,
    iterations: int = PBKDF2_ITERATIONS,
    length: int = KEY_SIZE,
) -> bytes:
    """
    Convenience wrapper that enforces default iterations/length.
    """
    if len(salt) != SALT_SIZE:
        raise ValueError(f"salt must be {SALT_SIZE} bytes")
    return pbkdf2_hmac_sha256(password, salt, iterations, length)

