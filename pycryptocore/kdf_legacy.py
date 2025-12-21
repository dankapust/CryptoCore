from typing import Tuple

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from .csprng import generate_random_bytes


KEY_SIZE = 16
SALT_SIZE = 16
PBKDF2_ITERATIONS = 10_000


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if len(salt) != SALT_SIZE:
        raise ValueError("salt must be 16 bytes")
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)


def generate_salt() -> bytes:
    return generate_random_bytes(SALT_SIZE)


