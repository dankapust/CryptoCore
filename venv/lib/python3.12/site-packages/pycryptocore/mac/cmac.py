"""
AES-CMAC (Cipher-based Message Authentication Code) implementation from scratch.
Follows NIST SP 800-38B specification.
"""
from __future__ import annotations

from Crypto.Cipher import AES


class CMAC:
    """
    AES-CMAC implementation from scratch.
    Follows NIST SP 800-38B specification.
    """

    BLOCK_SIZE = 16  # AES block size (128 bits)
    KEY_SIZE = 16  # AES-128 key size

    def __init__(self, key: bytes):
        """
        Initialize CMAC with an AES key.

        Args:
            key: AES key (16 bytes for AES-128)
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes for AES-128")
        
        self.key = key
        self.aes = AES.new(key, AES.MODE_ECB)
        
        # Generate subkeys K1 and K2
        self.k1, self.k2 = self._generate_subkeys()

    def _generate_subkeys(self) -> tuple[bytes, bytes]:
        """
        Generate subkeys K1 and K2 for CMAC.
        
        Algorithm:
        1. L = E_K(0^128)
        2. If MSB(L) = 0, then K1 = L << 1
           Else K1 = (L << 1) XOR Rb
        3. If MSB(K1) = 0, then K2 = K1 << 1
           Else K2 = (K1 << 1) XOR Rb
        where Rb = 0x87 (for 128-bit blocks)
        
        Returns:
            Tuple of (K1, K2) subkeys
        """
        # Step 1: L = E_K(0^128)
        L = self.aes.encrypt(b'\x00' * self.BLOCK_SIZE)
        
        # Convert to integer for bit operations
        L_int = int.from_bytes(L, 'big')
        
        # Rb = 0x87 for 128-bit blocks
        Rb = 0x87
        
        # Step 2: Generate K1
        if L_int & (1 << 127):  # MSB(L) = 1
            K1_int = ((L_int << 1) & ((1 << 128) - 1)) ^ (Rb << 120)
        else:  # MSB(L) = 0
            K1_int = (L_int << 1) & ((1 << 128) - 1)
        
        K1 = K1_int.to_bytes(self.BLOCK_SIZE, 'big')
        
        # Step 3: Generate K2
        if K1_int & (1 << 127):  # MSB(K1) = 1
            K2_int = ((K1_int << 1) & ((1 << 128) - 1)) ^ (Rb << 120)
        else:  # MSB(K1) = 0
            K2_int = (K1_int << 1) & ((1 << 128) - 1)
        
        K2 = K2_int.to_bytes(self.BLOCK_SIZE, 'big')
        
        return K1, K2

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        """XOR two byte sequences of equal length."""
        return bytes(x ^ y for x, y in zip(a, b))

    def compute(self, message: bytes) -> bytes:
        """
        Compute CMAC for a message.
        
        Algorithm:
        1. Divide message into blocks
        2. If last block is complete (16 bytes), XOR with K1 before encryption
        3. If last block is incomplete, pad with 10...0, then XOR with K2 before encryption
        4. Encrypt the result to get the MAC
        
        Args:
            message: The message to authenticate
            
        Returns:
            CMAC value as bytes (16 bytes)
        """
        if not message:
            # Empty message: use K1, encrypt
            return self.aes.encrypt(self.k1)
        
        # Divide message into blocks
        blocks = []
        for i in range(0, len(message), self.BLOCK_SIZE):
            blocks.append(message[i:i + self.BLOCK_SIZE])
        
        # Process all blocks except the last
        result = b'\x00' * self.BLOCK_SIZE
        for block in blocks[:-1]:
            result = self._xor_bytes(result, block)
            result = self.aes.encrypt(result)
        
        # Process last block
        last_block = blocks[-1]
        if len(last_block) == self.BLOCK_SIZE:
            # Complete block: XOR with K1
            result = self._xor_bytes(result, last_block)
            result = self._xor_bytes(result, self.k1)
        else:
            # Incomplete block: pad and XOR with K2
            # Padding: append 0x80, then zeros
            padded = last_block + b'\x80' + b'\x00' * (self.BLOCK_SIZE - len(last_block) - 1)
            result = self._xor_bytes(result, padded)
            result = self._xor_bytes(result, self.k2)
        
        # Final encryption
        mac = self.aes.encrypt(result)
        
        return mac

    def hexdigest(self, message: bytes) -> str:
        """
        Compute CMAC and return as hexadecimal string.
        
        Args:
            message: The message to authenticate
            
        Returns:
            CMAC value as lowercase hexadecimal string
        """
        return self.compute(message).hex()

    def update_compute(self, message_chunks: list[bytes]) -> bytes:
        """
        Compute CMAC for a message processed in chunks.
        This is more memory-efficient for large files.
        
        Args:
            message_chunks: List of message chunks
            
        Returns:
            CMAC value as bytes
        """
        if not message_chunks or all(len(chunk) == 0 for chunk in message_chunks):
            # Empty message: use K1, encrypt
            return self.aes.encrypt(self.k1)
        
        # Combine all chunks to find the last block
        # We need to know if the last block is complete or not
        total_length = sum(len(chunk) for chunk in message_chunks)
        if total_length == 0:
            return self.aes.encrypt(self.k1)
        
        # Process all chunks
        result = b'\x00' * self.BLOCK_SIZE
        processed_length = 0
        
        for chunk_idx, chunk in enumerate(message_chunks):
            if not chunk:
                continue
            
            # Process chunk in blocks
            for i in range(0, len(chunk), self.BLOCK_SIZE):
                block = chunk[i:i + self.BLOCK_SIZE]
                processed_length += len(block)
                is_last_block = (processed_length == total_length)
                
                if len(block) == self.BLOCK_SIZE and not is_last_block:
                    # Complete block, not the last one
                    result = self._xor_bytes(result, block)
                    result = self.aes.encrypt(result)
                elif len(block) == self.BLOCK_SIZE and is_last_block:
                    # Complete last block: XOR with K1
                    result = self._xor_bytes(result, block)
                    result = self._xor_bytes(result, self.k1)
                    result = self.aes.encrypt(result)
                else:
                    # Incomplete last block: pad and XOR with K2
                    padded = block + b'\x80' + b'\x00' * (self.BLOCK_SIZE - len(block) - 1)
                    result = self._xor_bytes(result, padded)
                    result = self._xor_bytes(result, self.k2)
                    result = self.aes.encrypt(result)
        
        return result

    def update_compute_hex(self, message_chunks: list[bytes]) -> str:
        """
        Compute CMAC for a message processed in chunks and return as hex.
        
        Args:
            message_chunks: List of message chunks
            
        Returns:
            CMAC value as lowercase hexadecimal string
        """
        return self.update_compute(message_chunks).hex()

