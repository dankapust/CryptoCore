from __future__ import annotations

import os
from typing import Optional


class CSPRNGError(Exception):
    pass


def generate_random_bytes(num_bytes: int) -> bytes:
    """Generates a cryptographically secure random byte string.

    Uses os.urandom under the hood. Validates input and raises CSPRNGError on failures.
    """
    if not isinstance(num_bytes, int):
        raise CSPRNGError("num_bytes must be an integer")
    if num_bytes < 0:
        raise CSPRNGError("num_bytes must be non-negative")
    try:
        return os.urandom(num_bytes)
    except Exception as exc:
        raise CSPRNGError(f"os.urandom failed: {exc}") from exc


def _is_sequential(data: bytes, step: int) -> bool:
    if len(data) <= 1:
        return False
    for i in range(1, len(data)):
        if (data[i - 1] + step) % 256 != data[i]:
            return False
    return True


def detect_weak_key(key_bytes: bytes) -> Optional[str]:
    """Return a description if the key looks weak; otherwise None.

    Heuristics:
    - all bytes identical
    - sequential ascending (00..0f) or descending (ff..f0)
    """
    if len(key_bytes) == 0:
        return None
    if all(b == key_bytes[0] for b in key_bytes):
        return "all bytes are identical"
    if _is_sequential(key_bytes, 1):
        return "sequential ascending bytes"
    if _is_sequential(key_bytes, 255):  # -1 mod 256
        return "sequential descending bytes"
    return None


