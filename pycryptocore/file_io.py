from __future__ import annotations

from pathlib import Path
from typing import Tuple


def read_all_bytes(file_path: str | Path) -> bytes:
    path = Path(file_path)
    return path.read_bytes()


def write_all_bytes(file_path: str | Path, data: bytes) -> None:
    path = Path(file_path)
    path.write_bytes(data)


def write_with_salt_iv(file_path: str | Path, salt: bytes, iv: bytes, ciphertext: bytes) -> None:
    write_all_bytes(file_path, salt + iv + ciphertext)


def read_with_salt_iv(file_path: str | Path) -> Tuple[bytes, bytes, bytes]:
    data = read_all_bytes(file_path)
    if len(data) < 32:
        raise ValueError("file too short; missing salt/iv header")
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]
    return salt, iv, ciphertext


def write_with_iv(file_path: str | Path, iv: bytes, ciphertext: bytes) -> None:
    write_all_bytes(file_path, iv + ciphertext)


def read_with_iv(file_path: str | Path) -> Tuple[bytes, bytes]:
    data = read_all_bytes(file_path)
    if len(data) < 16:
        raise ValueError("file too short; missing iv header")
    return data[:16], data[16:]


