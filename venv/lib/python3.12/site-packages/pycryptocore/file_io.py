from __future__ import annotations

from pathlib import Path
from typing import Tuple, Optional
import tempfile
import shutil
import os


def read_all_bytes(file_path: str | Path) -> bytes:
    path = Path(file_path)
    return path.read_bytes()


def write_all_bytes(file_path: str | Path, data: bytes) -> None:
    path = Path(file_path)
    path.write_bytes(data)


def create_temp_file(suffix: str = ".tmp") -> Path:
    """Create a temporary file for intermediate storage."""
    fd, temp_path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return Path(temp_path)


def move_temp_to_final(temp_file: Path, final_file: Path) -> None:
    """Move temporary file to final location atomically."""
    shutil.move(str(temp_file), str(final_file))


def cleanup_temp_file(temp_file: Optional[Path]) -> None:
    """Clean up temporary file if it exists."""
    if temp_file and temp_file.exists():
        try:
            temp_file.unlink()
        except Exception:
            pass  # Best effort cleanup


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


def write_with_nonce_tag(file_path: str | Path, nonce: bytes, ciphertext: bytes, tag: bytes) -> None:
    """Write GCM format: nonce (12 bytes) || ciphertext || tag (16 bytes)"""
    write_all_bytes(file_path, nonce + ciphertext + tag)


def read_with_nonce_tag(file_path: str | Path) -> Tuple[bytes, bytes, bytes]:
    """Read GCM format: nonce (12 bytes) || ciphertext || tag (16 bytes)"""
    data = read_all_bytes(file_path)
    if len(data) < 28:  # 12 (nonce) + 16 (tag) minimum
        raise ValueError("file too short; missing nonce or tag")
    nonce = data[:12]
    tag = data[-16:]
    ciphertext = data[12:-16]
    return nonce, ciphertext, tag


