from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..hash.sha256 import SHA256


class HMAC:
    """
    HMAC implementation from scratch following RFC 2104.
    Uses SHA-256 as the underlying hash function.
    """

    def __init__(self, key: bytes, hash_function: str = "sha256") -> None:
        """
        Initialize HMAC with a key.

        Args:
            key: The secret key (arbitrary length)
            hash_function: Hash function to use (currently only 'sha256' supported)
        """
        if hash_function != "sha256":
            raise ValueError(f"Unsupported hash function: {hash_function}")

        from ..hash.sha256 import SHA256

        self.hash_class = SHA256
        self.block_size = 64  # bytes, for SHA-256
        self.key = self._process_key(key)

    def _process_key(self, key: bytes) -> bytes:
        """
        Process the key according to RFC 2104:
        - If key is longer than block size, hash it
        - If key is shorter, pad with zeros

        Args:
            key: The input key

        Returns:
            Processed key of exactly block_size bytes
        """
        if len(key) > self.block_size:
            # Hash the key if it's longer than block size
            hasher = self.hash_class()
            hasher.update(key)
            key = hasher.digest()

        # Pad with zeros if shorter than block size
        if len(key) < self.block_size:
            key = key + b"\x00" * (self.block_size - len(key))

        return key

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        """XOR two byte sequences of equal length."""
        return bytes(x ^ y for x, y in zip(a, b))

    def compute(self, message: bytes) -> bytes:
        """
        Compute HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))

        Args:
            message: The message to authenticate

        Returns:
            HMAC value as bytes
        """
        # Create inner and outer pads
        ipad = b"\x36" * self.block_size
        opad = b"\x5c" * self.block_size

        # Inner hash: H((K ⊕ ipad) || message)
        inner_key = self._xor_bytes(self.key, ipad)
        inner_hasher = self.hash_class()
        inner_hasher.update(inner_key)
        inner_hasher.update(message)
        inner_hash = inner_hasher.digest()

        # Outer hash: H((K ⊕ opad) || inner_hash)
        outer_key = self._xor_bytes(self.key, opad)
        outer_hasher = self.hash_class()
        outer_hasher.update(outer_key)
        outer_hasher.update(inner_hash)
        outer_hash = outer_hasher.digest()

        return outer_hash

    def hexdigest(self, message: bytes) -> str:
        """
        Compute HMAC and return as hexadecimal string.

        Args:
            message: The message to authenticate

        Returns:
            HMAC value as lowercase hexadecimal string
        """
        return self.compute(message).hex()

    def update_compute(self, message_chunks: list[bytes]) -> bytes:
        """
        Compute HMAC for a message processed in chunks.
        This is more memory-efficient for large files.

        Args:
            message_chunks: List of message chunks

        Returns:
            HMAC value as bytes
        """
        # Create inner and outer pads
        ipad = b"\x36" * self.block_size
        opad = b"\x5c" * self.block_size

        # Inner hash: H((K ⊕ ipad) || message)
        inner_key = self._xor_bytes(self.key, ipad)
        inner_hasher = self.hash_class()
        inner_hasher.update(inner_key)
        for chunk in message_chunks:
            inner_hasher.update(chunk)
        inner_hash = inner_hasher.digest()

        # Outer hash: H((K ⊕ opad) || inner_hash)
        outer_key = self._xor_bytes(self.key, opad)
        outer_hasher = self.hash_class()
        outer_hasher.update(outer_key)
        outer_hasher.update(inner_hash)
        outer_hash = outer_hasher.digest()

        return outer_hash

    def update_compute_hex(self, message_chunks: list[bytes]) -> str:
        """
        Compute HMAC for a message processed in chunks and return as hex.

        Args:
            message_chunks: List of message chunks

        Returns:
            HMAC value as lowercase hexadecimal string
        """
        return self.update_compute(message_chunks).hex()

