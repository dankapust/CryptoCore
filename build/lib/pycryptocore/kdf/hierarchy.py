from __future__ import annotations

from typing import Union

from ..mac import HMAC


def derive_key(master_key: bytes, context: Union[str, bytes], length: int = 32) -> bytes:
    """
    Derive a subkey from master_key using HMAC(master_key, context || counter).
    """
    if not isinstance(master_key, (bytes, bytearray)):
        raise TypeError("master_key must be bytes")
    if isinstance(context, str):
        context_bytes = context.encode("utf-8")
    elif isinstance(context, (bytes, bytearray)):
        context_bytes = bytes(context)
    else:
        raise TypeError("context must be str or bytes")
    if length <= 0:
        raise ValueError("length must be positive")

    derived = bytearray()
    counter = 1
    while len(derived) < length:
        block = HMAC(master_key, "sha256").compute(context_bytes + counter.to_bytes(4, "big"))
        derived.extend(block)
        counter += 1

    return bytes(derived[:length])

