from __future__ import annotations

import hashlib


class SHA3_256:
    """SHA3-256 wrapper using hashlib (vetted library)."""

    def __init__(self) -> None:
        self._h = hashlib.sha3_256()

    def update(self, data: bytes) -> None:
        if data:
            self._h.update(data)

    def digest(self) -> bytes:
        return self._h.digest()

    def hexdigest(self) -> str:
        return self._h.hexdigest()

    def hash_bytes(self, data: bytes) -> str:
        self.__init__()
        self.update(data)
        return self.hexdigest()


