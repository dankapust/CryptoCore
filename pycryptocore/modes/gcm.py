"""
GCM (Galois/Counter Mode) implementation from scratch following NIST SP 800-38D.
"""
from __future__ import annotations

import os
from typing import Optional

from Crypto.Cipher import AES

from ..csprng import generate_random_bytes


class AuthenticationError(Exception):
    """Raised when GCM authentication fails."""
    pass


class GCM:
    """
    GCM (Galois/Counter Mode) implementation from scratch.
    Follows NIST SP 800-38D specification.
    """

    BLOCK_SIZE = 16  # AES block size
    TAG_SIZE = 16  # 128-bit authentication tag
    NONCE_SIZE = 12  # Recommended nonce size (96 bits)

    def __init__(self, key: bytes, nonce: Optional[bytes] = None):
        """
        Initialize GCM with a key and optional nonce.

        Args:
            key: AES key (16 bytes for AES-128)
            nonce: Nonce (12 bytes recommended). If None, generates random nonce.
        """
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes for AES-128")
        
        self.key = key
        self.aes = AES.new(key, AES.MODE_ECB)
        self.nonce = nonce if nonce is not None else generate_random_bytes(self.NONCE_SIZE)
        
        if len(self.nonce) != self.NONCE_SIZE:
            raise ValueError(f"Nonce must be {self.NONCE_SIZE} bytes")
        
        # Precompute H = E_K(0^128) for GHASH
        self.H = self.aes.encrypt(b'\x00' * self.BLOCK_SIZE)
        self.H_int = int.from_bytes(self.H, 'big')
        
        # Precompute multiplication table for GHASH (optional optimization)
        self._precompute_table()

    def _precompute_table(self):
        """Precompute multiplication table for faster GHASH."""
        # For simplicity, we'll use direct multiplication
        # In production, you might want to use a lookup table
        pass

    def _mult_gf(self, x: int, y: int) -> int:
        """
        Multiply two elements in GF(2^128) modulo x^128 + x^7 + x^2 + x + 1.
        
        Args:
            x: First element as 128-bit integer
            y: Second element as 128-bit integer
            
        Returns:
            Product in GF(2^128) as 128-bit integer
        """
        # Irreducible polynomial: x^128 + x^7 + x^2 + x + 1
        # Represented as: 0xE1000000000000000000000000000000 (for the lower 128 bits)
        # The full polynomial is: 0x100000000000000000000000000000000E1
        # But we only need the lower 128 bits: 0xE1 << 120
        R = 0xE1000000000000000000000000000000
        
        z = 0
        v = y
        
        # Process bits from MSB to LSB
        for i in range(127, -1, -1):
            if (x >> i) & 1:
                z ^= v
            # Multiply v by x (shift left)
            if v & 1:
                v = (v >> 1) ^ R
            else:
                v >>= 1
        
        return z & ((1 << 128) - 1)  # Ensure 128 bits

    def _ghash(self, aad: bytes, ciphertext: bytes) -> bytes:
        """
        Compute GHASH: authentication function for GCM.
        
        GHASH(H, A, C) where:
        - H = E_K(0^128)
        - A = associated authenticated data
        - C = ciphertext
        
        Args:
            aad: Associated Authenticated Data
            ciphertext: Ciphertext
            
        Returns:
            16-byte authentication tag
        """
        # Convert H to integer
        H = self.H_int
        
        # Prepare input: A || C || len(A) || len(C)
        # Pad A and C to block boundaries
        def pad_to_block(data: bytes) -> bytes:
            """Pad data to multiple of block size."""
            pad_len = (self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)) % self.BLOCK_SIZE
            return data + b'\x00' * pad_len
        
        aad_padded = pad_to_block(aad)
        ciphertext_padded = pad_to_block(ciphertext)
        
        # Lengths as 64-bit big-endian integers
        aad_len_bits = len(aad) * 8
        ciphertext_len_bits = len(ciphertext) * 8
        lengths = aad_len_bits.to_bytes(8, 'big') + ciphertext_len_bits.to_bytes(8, 'big')
        
        # Combine: A || C || lengths
        input_data = aad_padded + ciphertext_padded + lengths
        
        # Process in 16-byte blocks
        y = 0
        for i in range(0, len(input_data), self.BLOCK_SIZE):
            block = input_data[i:i + self.BLOCK_SIZE]
            block_int = int.from_bytes(block, 'big')
            y = self._mult_gf(y ^ block_int, H)
        
        return y.to_bytes(self.BLOCK_SIZE, 'big')

    def _generate_j0(self, nonce: bytes) -> bytes:
        """
        Generate J0 (initial counter value) from nonce.
        
        For 96-bit nonce: J0 = nonce || 0^31 || 1
        For other sizes: J0 = GHASH(H, {}, nonce)
        
        Args:
            nonce: Nonce (12 bytes recommended)
            
        Returns:
            J0 as 16-byte block
        """
        if len(nonce) == 12:
            # 96-bit nonce: J0 = nonce || 0^31 || 1
            return nonce + b'\x00\x00\x00\x01'
        else:
            # Other sizes: J0 = GHASH(H, {}, nonce)
            # For non-96-bit nonce, we need to pad and hash
            # This is a simplified version
            nonce_padded = nonce + b'\x00' * ((16 - (len(nonce) % 16)) % 16)
            lengths = (0).to_bytes(8, 'big') + (len(nonce) * 8).to_bytes(8, 'big')
            input_data = nonce_padded + lengths
            
            H = self.H_int
            y = 0
            for i in range(0, len(input_data), self.BLOCK_SIZE):
                block = input_data[i:i + self.BLOCK_SIZE]
                block_int = int.from_bytes(block, 'big')
                y = self._mult_gf(y ^ block_int, H)
            
            return y.to_bytes(self.BLOCK_SIZE, 'big')

    def _ctr_encrypt(self, plaintext: bytes, j0: bytes) -> bytes:
        """
        Encrypt plaintext using CTR mode with counter starting from J0+1.
        
        Args:
            plaintext: Plaintext to encrypt
            j0: Initial counter value (J0)
            
        Returns:
            Ciphertext
        """
        j0_int = int.from_bytes(j0, 'big')
        counter = (j0_int + 1) % (1 << 128)
        
        ciphertext = bytearray()
        for i in range(0, len(plaintext), self.BLOCK_SIZE):
            block = plaintext[i:i + self.BLOCK_SIZE]
            # Encrypt counter
            counter_bytes = counter.to_bytes(self.BLOCK_SIZE, 'big')
            keystream = self.aes.encrypt(counter_bytes)
            # XOR with plaintext block
            ct_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            ciphertext.extend(ct_block)
            counter = (counter + 1) % (1 << 128)
        
        return bytes(ciphertext)

    def _ctr_decrypt(self, ciphertext: bytes, j0: bytes) -> bytes:
        """
        Decrypt ciphertext using CTR mode (same as encrypt).
        
        Args:
            ciphertext: Ciphertext to decrypt
            j0: Initial counter value (J0)
            
        Returns:
            Plaintext
        """
        return self._ctr_encrypt(ciphertext, j0)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """
        Encrypt plaintext with GCM mode.
        
        Output format: nonce (12 bytes) || ciphertext || tag (16 bytes)
        
        Args:
            plaintext: Plaintext to encrypt
            aad: Associated Authenticated Data
            
        Returns:
            Complete GCM output: nonce || ciphertext || tag
        """
        # Generate J0 from nonce
        j0 = self._generate_j0(self.nonce)
        
        # Encrypt using CTR mode
        ciphertext = self._ctr_encrypt(plaintext, j0)
        
        # Compute authentication tag
        # Tag = MSB_t(GHASH(H, A, C) XOR E_K(J0))
        ghash_result = self._ghash(aad, ciphertext)
        s = self.aes.encrypt(j0)
        tag = bytes(a ^ b for a, b in zip(ghash_result, s))[:self.TAG_SIZE]
        
        # Return: nonce || ciphertext || tag
        return self.nonce + ciphertext + tag

    def decrypt(self, data: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypt GCM ciphertext and verify authentication tag.
        
        Input format: nonce (12 bytes) || ciphertext || tag (16 bytes)
        
        Args:
            data: Complete GCM data (nonce || ciphertext || tag)
            aad: Associated Authenticated Data (must match encryption)
            
        Returns:
            Plaintext
            
        Raises:
            AuthenticationError: If authentication fails
        """
        if len(data) < self.NONCE_SIZE + self.TAG_SIZE:
            raise AuthenticationError("Data too short: missing nonce or tag")
        
        # Extract components
        nonce = data[:self.NONCE_SIZE]
        tag = data[-self.TAG_SIZE:]
        ciphertext = data[self.NONCE_SIZE:-self.TAG_SIZE]
        
        # Update nonce for this decryption (in case it was different)
        # But we need to use the nonce from data, not self.nonce
        # Generate J0 from nonce extracted from data
        j0 = self._generate_j0(nonce)
        
        # Verify authentication tag
        ghash_result = self._ghash(aad, ciphertext)
        s = self.aes.encrypt(j0)
        computed_tag = bytes(a ^ b for a, b in zip(ghash_result, s))[:self.TAG_SIZE]
        
        # Constant-time comparison to prevent timing attacks
        if not self._constant_time_compare(tag, computed_tag):
            raise AuthenticationError("Authentication failed: AAD mismatch or ciphertext tampered")
        
        # Decrypt using CTR mode
        plaintext = self._ctr_decrypt(ciphertext, j0)
        
        return plaintext

    @staticmethod
    def _constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison to prevent timing attacks.
        
        Args:
            a: First byte string
            b: Second byte string
            
        Returns:
            True if equal, False otherwise
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        
        return result == 0

