from typing import Optional, Tuple, List, BinaryIO
import os
import tempfile
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from .csprng import generate_random_bytes
from .modes.gcm import GCM, AuthenticationError


KEY_SIZE = 16  # AES-128
BLOCK_SIZE = 16
IV_SIZE = 16
CHUNK_SIZE = 64 * 1024  # 64 KB chunks for streaming


class CryptoCoreError(Exception):
    pass


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> List[bytes]:
    return [data[i : i + block_size] for i in range(0, len(data), block_size)]


def _ensure_iv(iv: Optional[bytes]) -> bytes:
    return iv if iv is not None else generate_random_bytes(IV_SIZE)


def ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext, BLOCK_SIZE)
    ciphertext_blocks: List[bytes] = []
    for block in _split_blocks(padded):
        ciphertext_blocks.append(cipher.encrypt(block))
    return b"".join(ciphertext_blocks)


def ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise CryptoCoreError("Ciphertext not multiple of block size for ECB")
    plaintext_blocks: List[bytes] = []
    for block in _split_blocks(ciphertext):
        plaintext_blocks.append(cipher.decrypt(block))
    try:
        return unpad(b"".join(plaintext_blocks), BLOCK_SIZE)
    except ValueError as exc:
        raise CryptoCoreError("Invalid padding or corrupted data") from exc


def cbc_encrypt(key: bytes, plaintext: bytes, iv: Optional[bytes]) -> Tuple[bytes, bytes]:
    iv = _ensure_iv(iv)
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext, BLOCK_SIZE)
    prev = iv
    out_blocks: List[bytes] = []
    for block in _split_blocks(padded):
        x = _xor_bytes(block, prev)
        c = cipher.encrypt(x)
        out_blocks.append(c)
        prev = c
    return b"".join(out_blocks), iv


def cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise CryptoCoreError("Ciphertext not multiple of block size for CBC")
    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    out_blocks: List[bytes] = []
    for block in _split_blocks(ciphertext):
        p = _xor_bytes(cipher.decrypt(block), prev)
        out_blocks.append(p)
        prev = block
    try:
        return unpad(b"".join(out_blocks), BLOCK_SIZE)
    except ValueError as exc:
        raise CryptoCoreError("Invalid padding or corrupted data") from exc


def cfb_encrypt(key: bytes, plaintext: bytes, iv: Optional[bytes]) -> Tuple[bytes, bytes]:
    iv = _ensure_iv(iv)
    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    out: bytearray = bytearray()
    for block in _split_blocks(plaintext):
        stream = cipher.encrypt(prev)
        ct_block = _xor_bytes(stream[: len(block)], block)
        out.extend(ct_block)
        # full-block CFB uses ciphertext block as next prev; for partial final block, still use full ct of that size
        prev = bytes(ct_block) if len(ct_block) == BLOCK_SIZE else prev[: BLOCK_SIZE - len(ct_block)] + bytes(ct_block)
    return bytes(out), iv


def cfb_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    out: bytearray = bytearray()
    for block in _split_blocks(ciphertext):
        stream = cipher.encrypt(prev)
        pt_block = _xor_bytes(stream[: len(block)], block)
        out.extend(pt_block)
        prev = block if len(block) == BLOCK_SIZE else prev[: BLOCK_SIZE - len(block)] + block
    return bytes(out)


def ofb_encrypt(key: bytes, plaintext: bytes, iv: Optional[bytes]) -> Tuple[bytes, bytes]:
    iv = _ensure_iv(iv)
    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    out: bytearray = bytearray()
    for block in _split_blocks(plaintext):
        stream = cipher.encrypt(prev)
        ct_block = _xor_bytes(stream[: len(block)], block)
        out.extend(ct_block)
        prev = stream
    return bytes(out), iv


def ofb_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    # same as encrypt
    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    out: bytearray = bytearray()
    for block in _split_blocks(ciphertext):
        stream = cipher.encrypt(prev)
        pt_block = _xor_bytes(stream[: len(block)], block)
        out.extend(pt_block)
        prev = stream
    return bytes(out)


def ctr_encrypt(key: bytes, plaintext: bytes, iv: Optional[bytes]) -> Tuple[bytes, bytes]:
    iv = _ensure_iv(iv)
    cipher = AES.new(key, AES.MODE_ECB)
    counter = int.from_bytes(iv, "big")
    out: bytearray = bytearray()
    for block in _split_blocks(plaintext):
        keystream = cipher.encrypt(counter.to_bytes(16, "big"))
        ct_block = _xor_bytes(keystream[: len(block)], block)
        out.extend(ct_block)
        counter = (counter + 1) % (1 << 128)
    return bytes(out), iv


def ctr_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    # same as encrypt
    cipher = AES.new(key, AES.MODE_ECB)
    counter = int.from_bytes(iv, "big")
    out: bytearray = bytearray()
    for block in _split_blocks(ciphertext):
        keystream = cipher.encrypt(counter.to_bytes(16, "big"))
        pt_block = _xor_bytes(keystream[: len(block)], block)
        out.extend(pt_block)
        counter = (counter + 1) % (1 << 128)
    return bytes(out)


def aes_encrypt(mode: str, key: bytes, plaintext: bytes, iv: Optional[bytes] = None, aad: Optional[bytes] = None) -> Tuple[bytes, Optional[bytes]]:
    if len(key) != KEY_SIZE:
        raise CryptoCoreError("Invalid key length; expected 16 bytes for AES-128")
    mode_lc = mode.lower()
    if mode_lc == "ecb":
        return ecb_encrypt(key, plaintext), None
    if mode_lc == "cbc":
        return cbc_encrypt(key, plaintext, iv)
    if mode_lc == "cfb":
        return cfb_encrypt(key, plaintext, iv)
    if mode_lc == "ofb":
        return ofb_encrypt(key, plaintext, iv)
    if mode_lc == "ctr":
        return ctr_encrypt(key, plaintext, iv)
    if mode_lc == "gcm":
        if aad is None:
            aad = b""
        gcm = GCM(key, nonce=iv)
        result = gcm.encrypt(plaintext, aad)
        # GCM returns nonce || ciphertext || tag, nonce is already included
        return result, None
    raise CryptoCoreError(f"Unsupported mode: {mode}")


def aes_decrypt(mode: str, key: bytes, ciphertext: bytes, iv: Optional[bytes] = None, aad: Optional[bytes] = None) -> bytes:
    if len(key) != KEY_SIZE:
        raise CryptoCoreError("Invalid key length; expected 16 bytes for AES-128")
    mode_lc = mode.lower()
    if mode_lc == "ecb":
        return ecb_decrypt(key, ciphertext)
    if mode_lc == "cbc":
        if iv is None:
            raise CryptoCoreError("IV is required for CBC")
        return cbc_decrypt(key, ciphertext, iv)
    if mode_lc == "cfb":
        if iv is None:
            raise CryptoCoreError("IV is required for CFB")
        return cfb_decrypt(key, ciphertext, iv)
    if mode_lc == "ofb":
        if iv is None:
            raise CryptoCoreError("IV is required for OFB")
        return ofb_decrypt(key, ciphertext, iv)
    if mode_lc == "ctr":
        if iv is None:
            raise CryptoCoreError("IV is required for CTR")
        return ctr_decrypt(key, ciphertext, iv)
    if mode_lc == "gcm":
        if aad is None:
            aad = b""
        # For GCM, ciphertext format is: nonce (12 bytes) || ciphertext || tag (16 bytes)
        # If iv is provided, it means nonce was provided separately via --iv
        if iv is not None:
            # Nonce was provided separately, so ciphertext is just ciphertext || tag
            # We need to prepend nonce
            data = iv + ciphertext
        else:
            # Nonce is included in ciphertext (first 12 bytes)
            data = ciphertext
        gcm = GCM(key, nonce=None)  # nonce will be extracted from data in decrypt
        try:
            return gcm.decrypt(data, aad)
        except AuthenticationError as e:
            raise CryptoCoreError(str(e))
    raise CryptoCoreError(f"Unsupported mode: {mode}")


# ============================================================================
# Streaming encryption/decryption functions for large files
# ============================================================================

def ecb_encrypt_stream(key: bytes, input_file: BinaryIO, output_file: BinaryIO, temp_file: Optional[Path] = None) -> None:
    """Streaming ECB encryption."""
    cipher = AES.new(key, AES.MODE_ECB)
    buffer = bytearray()
    
    while True:
        chunk = input_file.read(CHUNK_SIZE)
        if not chunk:
            break
        buffer.extend(chunk)
        
        # Process full blocks
        while len(buffer) >= BLOCK_SIZE:
            block = bytes(buffer[:BLOCK_SIZE])
            del buffer[:BLOCK_SIZE]
            encrypted = cipher.encrypt(block)
            output_file.write(encrypted)
            if temp_file:
                with open(temp_file, 'ab') as tf:
                    tf.write(encrypted)
    
    # Handle remaining bytes with padding
    if buffer:
        padded = pad(bytes(buffer), BLOCK_SIZE)
        for i in range(0, len(padded), BLOCK_SIZE):
            block = padded[i:i+BLOCK_SIZE]
            encrypted = cipher.encrypt(block)
            output_file.write(encrypted)
            if temp_file:
                with open(temp_file, 'ab') as tf:
                    tf.write(encrypted)


def ecb_decrypt_stream(key: bytes, input_file: BinaryIO, output_file: BinaryIO, temp_file: Optional[Path] = None) -> None:
    """Streaming ECB decryption."""
    cipher = AES.new(key, AES.MODE_ECB)
    buffer = bytearray()
    last_block = None
    
    while True:
        chunk = input_file.read(CHUNK_SIZE)
        if not chunk:
            break
        buffer.extend(chunk)
        
        # Process full blocks
        while len(buffer) >= BLOCK_SIZE:
            block = bytes(buffer[:BLOCK_SIZE])
            del buffer[:BLOCK_SIZE]
            decrypted = cipher.decrypt(block)
            if last_block is not None:
                output_file.write(last_block)
                if temp_file:
                    with open(temp_file, 'ab') as tf:
                        tf.write(last_block)
            last_block = decrypted
    
    # Handle last block (with padding)
    if buffer:
        if len(buffer) % BLOCK_SIZE != 0:
            raise CryptoCoreError("Ciphertext not multiple of block size for ECB")
        decrypted = cipher.decrypt(bytes(buffer))
        if last_block is not None:
            output_file.write(last_block)
            if temp_file:
                with open(temp_file, 'ab') as tf:
                    tf.write(last_block)
        last_block = decrypted
    
    # Remove padding from last block
    if last_block is not None:
        try:
            unpadded = unpad(last_block, BLOCK_SIZE)
            output_file.write(unpadded)
            if temp_file:
                with open(temp_file, 'ab') as tf:
                    tf.write(unpadded)
        except ValueError as exc:
            raise CryptoCoreError("Invalid padding or corrupted data") from exc


def cbc_encrypt_stream(key: bytes, input_file: BinaryIO, output_file: BinaryIO, iv: Optional[bytes] = None, temp_file: Optional[Path] = None) -> bytes:
    """Streaming CBC encryption."""
    iv = _ensure_iv(iv)
    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    buffer = bytearray()
    
    while True:
        chunk = input_file.read(CHUNK_SIZE)
        if not chunk:
            break
        buffer.extend(chunk)
        
        # Process full blocks
        while len(buffer) >= BLOCK_SIZE:
            block = bytes(buffer[:BLOCK_SIZE])
            del buffer[:BLOCK_SIZE]
            x = _xor_bytes(block, prev)
            c = cipher.encrypt(x)
            prev = c
            output_file.write(c)
            if temp_file:
                with open(temp_file, 'ab') as tf:
                    tf.write(c)
    
    # Handle remaining bytes with padding
    if buffer:
        padded = pad(bytes(buffer), BLOCK_SIZE)
        for i in range(0, len(padded), BLOCK_SIZE):
            block = padded[i:i+BLOCK_SIZE]
            x = _xor_bytes(block, prev)
            c = cipher.encrypt(x)
            prev = c
            output_file.write(c)
            if temp_file:
                with open(temp_file, 'ab') as tf:
                    tf.write(c)
    
    return iv


def cbc_decrypt_stream(key: bytes, input_file: BinaryIO, output_file: BinaryIO, iv: bytes, temp_file: Optional[Path] = None) -> None:
    """Streaming CBC decryption."""
    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    buffer = bytearray()
    last_block = None
    
    while True:
        chunk = input_file.read(CHUNK_SIZE)
        if not chunk:
            break
        buffer.extend(chunk)
        
        # Process full blocks
        while len(buffer) >= BLOCK_SIZE:
            block = bytes(buffer[:BLOCK_SIZE])
            del buffer[:BLOCK_SIZE]
            p = _xor_bytes(cipher.decrypt(block), prev)
            prev = block
            if last_block is not None:
                output_file.write(last_block)
                if temp_file:
                    with open(temp_file, 'ab') as tf:
                        tf.write(last_block)
            last_block = p
    
    # Handle last block (with padding)
    if buffer:
        if len(buffer) % BLOCK_SIZE != 0:
            raise CryptoCoreError("Ciphertext not multiple of block size for CBC")
        block = bytes(buffer)
        p = _xor_bytes(cipher.decrypt(block), prev)
        if last_block is not None:
            output_file.write(last_block)
            if temp_file:
                with open(temp_file, 'ab') as tf:
                    tf.write(last_block)
        last_block = p
    
    # Remove padding from last block
    if last_block is not None:
        try:
            unpadded = unpad(last_block, BLOCK_SIZE)
            output_file.write(unpadded)
            if temp_file:
                with open(temp_file, 'ab') as tf:
                    tf.write(unpadded)
        except ValueError as exc:
            raise CryptoCoreError("Invalid padding or corrupted data") from exc


def cfb_encrypt_stream(key: bytes, input_file: BinaryIO, output_file: BinaryIO, iv: Optional[bytes] = None, temp_file: Optional[Path] = None) -> bytes:
    """Streaming CFB encryption."""
    iv = _ensure_iv(iv)
    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    buffer = bytearray()
    
    while True:
        chunk = input_file.read(CHUNK_SIZE)
        if not chunk:
            break
        buffer.extend(chunk)
        
        # Process in blocks
        while len(buffer) >= BLOCK_SIZE:
            block = bytes(buffer[:BLOCK_SIZE])
            del buffer[:BLOCK_SIZE]
            stream = cipher.encrypt(prev)
            ct_block = _xor_bytes(stream[:len(block)], block)
            prev = ct_block
            output_file.write(ct_block)
            if temp_file:
                with open(temp_file, 'ab') as tf:
                    tf.write(ct_block)
    
    # Handle remaining bytes
    if buffer:
        stream = cipher.encrypt(prev)
        ct_block = _xor_bytes(stream[:len(buffer)], bytes(buffer))
        prev = prev[:BLOCK_SIZE - len(ct_block)] + ct_block if len(ct_block) < BLOCK_SIZE else ct_block
        output_file.write(ct_block)
        if temp_file:
            with open(temp_file, 'ab') as tf:
                tf.write(ct_block)
    
    return iv


def cfb_decrypt_stream(key: bytes, input_file: BinaryIO, output_file: BinaryIO, iv: bytes, temp_file: Optional[Path] = None) -> None:
    """Streaming CFB decryption."""
    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    buffer = bytearray()
    
    while True:
        chunk = input_file.read(CHUNK_SIZE)
        if not chunk:
            break
        buffer.extend(chunk)
        
        # Process in blocks
        while len(buffer) >= BLOCK_SIZE:
            block = bytes(buffer[:BLOCK_SIZE])
            del buffer[:BLOCK_SIZE]
            stream = cipher.encrypt(prev)
            pt_block = _xor_bytes(stream[:len(block)], block)
            prev = block
            output_file.write(pt_block)
            if temp_file:
                with open(temp_file, 'ab') as tf:
                    tf.write(pt_block)
    
    # Handle remaining bytes
    if buffer:
        stream = cipher.encrypt(prev)
        pt_block = _xor_bytes(stream[:len(buffer)], bytes(buffer))
        prev = prev[:BLOCK_SIZE - len(buffer)] + bytes(buffer) if len(buffer) < BLOCK_SIZE else bytes(buffer)
        output_file.write(pt_block)
        if temp_file:
            with open(temp_file, 'ab') as tf:
                tf.write(pt_block)


def ofb_encrypt_stream(key: bytes, input_file: BinaryIO, output_file: BinaryIO, iv: Optional[bytes] = None, temp_file: Optional[Path] = None) -> bytes:
    """Streaming OFB encryption."""
    iv = _ensure_iv(iv)
    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    buffer = bytearray()
    
    while True:
        chunk = input_file.read(CHUNK_SIZE)
        if not chunk:
            break
        buffer.extend(chunk)
        
        # Process in blocks
        while len(buffer) >= BLOCK_SIZE:
            block = bytes(buffer[:BLOCK_SIZE])
            del buffer[:BLOCK_SIZE]
            stream = cipher.encrypt(prev)
            ct_block = _xor_bytes(stream[:len(block)], block)
            prev = stream
            output_file.write(ct_block)
            if temp_file:
                with open(temp_file, 'ab') as tf:
                    tf.write(ct_block)
    
    # Handle remaining bytes
    if buffer:
        stream = cipher.encrypt(prev)
        ct_block = _xor_bytes(stream[:len(buffer)], bytes(buffer))
        prev = stream
        output_file.write(ct_block)
        if temp_file:
            with open(temp_file, 'ab') as tf:
                tf.write(ct_block)
    
    return iv


def ofb_decrypt_stream(key: bytes, input_file: BinaryIO, output_file: BinaryIO, iv: bytes, temp_file: Optional[Path] = None) -> None:
    """Streaming OFB decryption (same as encrypt)."""
    ofb_encrypt_stream(key, input_file, output_file, iv, temp_file)


def ctr_encrypt_stream(key: bytes, input_file: BinaryIO, output_file: BinaryIO, iv: Optional[bytes] = None, temp_file: Optional[Path] = None) -> bytes:
    """Streaming CTR encryption."""
    iv = _ensure_iv(iv)
    cipher = AES.new(key, AES.MODE_ECB)
    counter = int.from_bytes(iv, "big")
    buffer = bytearray()
    
    while True:
        chunk = input_file.read(CHUNK_SIZE)
        if not chunk:
            break
        buffer.extend(chunk)
        
        # Process in blocks
        while len(buffer) >= BLOCK_SIZE:
            block = bytes(buffer[:BLOCK_SIZE])
            del buffer[:BLOCK_SIZE]
            keystream = cipher.encrypt(counter.to_bytes(16, "big"))
            ct_block = _xor_bytes(keystream[:len(block)], block)
            counter = (counter + 1) % (1 << 128)
            output_file.write(ct_block)
            if temp_file:
                with open(temp_file, 'ab') as tf:
                    tf.write(ct_block)
    
    # Handle remaining bytes
    if buffer:
        keystream = cipher.encrypt(counter.to_bytes(16, "big"))
        ct_block = _xor_bytes(keystream[:len(buffer)], bytes(buffer))
        counter = (counter + 1) % (1 << 128)
        output_file.write(ct_block)
        if temp_file:
            with open(temp_file, 'ab') as tf:
                tf.write(ct_block)
    
    return iv


def ctr_decrypt_stream(key: bytes, input_file: BinaryIO, output_file: BinaryIO, iv: bytes, temp_file: Optional[Path] = None) -> None:
    """Streaming CTR decryption (same as encrypt)."""
    ctr_encrypt_stream(key, input_file, output_file, iv, temp_file)


def aes_encrypt_stream(mode: str, key: bytes, input_file: BinaryIO, output_file: BinaryIO, iv: Optional[bytes] = None, aad: Optional[bytes] = None, temp_file: Optional[Path] = None) -> Optional[bytes]:
    """Streaming encryption wrapper."""
    if len(key) != KEY_SIZE:
        raise CryptoCoreError("Invalid key length; expected 16 bytes for AES-128")
    mode_lc = mode.lower()
    
    if mode_lc == "ecb":
        ecb_encrypt_stream(key, input_file, output_file, temp_file)
        return None
    elif mode_lc == "cbc":
        return cbc_encrypt_stream(key, input_file, output_file, iv, temp_file)
    elif mode_lc == "cfb":
        return cfb_encrypt_stream(key, input_file, output_file, iv, temp_file)
    elif mode_lc == "ofb":
        return ofb_encrypt_stream(key, input_file, output_file, iv, temp_file)
    elif mode_lc == "ctr":
        return ctr_encrypt_stream(key, input_file, output_file, iv, temp_file)
    elif mode_lc == "gcm":
        # GCM requires full data for GHASH, so we'll use non-streaming for now
        # This could be optimized in the future
        raise CryptoCoreError("GCM streaming not yet implemented; use non-streaming mode for GCM")
    else:
        raise CryptoCoreError(f"Unsupported mode: {mode}")


def aes_decrypt_stream(mode: str, key: bytes, input_file: BinaryIO, output_file: BinaryIO, iv: Optional[bytes] = None, aad: Optional[bytes] = None, temp_file: Optional[Path] = None) -> None:
    """Streaming decryption wrapper."""
    if len(key) != KEY_SIZE:
        raise CryptoCoreError("Invalid key length; expected 16 bytes for AES-128")
    mode_lc = mode.lower()
    
    if mode_lc == "ecb":
        ecb_decrypt_stream(key, input_file, output_file, temp_file)
    elif mode_lc == "cbc":
        if iv is None:
            raise CryptoCoreError("IV is required for CBC")
        cbc_decrypt_stream(key, input_file, output_file, iv, temp_file)
    elif mode_lc == "cfb":
        if iv is None:
            raise CryptoCoreError("IV is required for CFB")
        cfb_decrypt_stream(key, input_file, output_file, iv, temp_file)
    elif mode_lc == "ofb":
        if iv is None:
            raise CryptoCoreError("IV is required for OFB")
        ofb_decrypt_stream(key, input_file, output_file, iv, temp_file)
    elif mode_lc == "ctr":
        if iv is None:
            raise CryptoCoreError("IV is required for CTR")
        ctr_decrypt_stream(key, input_file, output_file, iv, temp_file)
    elif mode_lc == "gcm":
        raise CryptoCoreError("GCM streaming not yet implemented; use non-streaming mode for GCM")
    else:
        raise CryptoCoreError(f"Unsupported mode: {mode}")


