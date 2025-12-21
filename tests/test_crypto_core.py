"""
Additional tests for crypto_core module to increase coverage.
"""
import os
import io
import tempfile
import pytest

from pycryptocore.crypto_core import (
    aes_encrypt,
    aes_decrypt,
    aes_encrypt_stream,
    aes_decrypt_stream,
    ecb_encrypt,
    ecb_decrypt,
    cbc_encrypt,
    cbc_decrypt,
    cfb_encrypt,
    cfb_decrypt,
    ofb_encrypt,
    ofb_decrypt,
    ctr_encrypt,
    ctr_decrypt,
    CryptoCoreError,
    KEY_SIZE,
    BLOCK_SIZE,
    IV_SIZE,
    CHUNK_SIZE,
)


def test_ecb_encrypt_decrypt_empty():
    """Test ECB with empty plaintext."""
    key = os.urandom(KEY_SIZE)
    plaintext = b""
    
    ciphertext = ecb_encrypt(key, plaintext)
    decrypted = ecb_decrypt(key, ciphertext)
    assert decrypted == plaintext


def test_ecb_decrypt_invalid_block_size():
    """Test ECB decrypt with invalid block size."""
    key = os.urandom(KEY_SIZE)
    ciphertext = b"short"  # Not multiple of block size
    
    with pytest.raises(CryptoCoreError, match="not multiple of block size"):
        ecb_decrypt(key, ciphertext)


def test_cbc_encrypt_decrypt_empty():
    """Test CBC with empty plaintext."""
    key = os.urandom(KEY_SIZE)
    plaintext = b""
    
    ciphertext, iv = cbc_encrypt(key, plaintext, None)
    decrypted = cbc_decrypt(key, ciphertext, iv)
    assert decrypted == plaintext


def test_cbc_encrypt_with_provided_iv():
    """Test CBC encrypt with provided IV."""
    key = os.urandom(KEY_SIZE)
    iv = os.urandom(IV_SIZE)
    plaintext = b"Hello, World!"
    
    ciphertext, returned_iv = cbc_encrypt(key, plaintext, iv)
    assert returned_iv == iv
    decrypted = cbc_decrypt(key, ciphertext, iv)
    assert decrypted == plaintext


def test_cbc_decrypt_invalid_block_size():
    """Test CBC decrypt with invalid block size."""
    key = os.urandom(KEY_SIZE)
    iv = os.urandom(IV_SIZE)
    ciphertext = b"short"  # Not multiple of block size
    
    with pytest.raises(CryptoCoreError, match="not multiple of block size"):
        cbc_decrypt(key, ciphertext, iv)


def test_cbc_decrypt_missing_iv():
    """Test CBC decrypt requires IV."""
    key = os.urandom(KEY_SIZE)
    plaintext = b"test"
    ciphertext, iv = cbc_encrypt(key, plaintext, None)
    
    # Should work with IV
    decrypted = cbc_decrypt(key, ciphertext, iv)
    assert decrypted == plaintext


def test_cfb_encrypt_decrypt_empty():
    """Test CFB with empty plaintext."""
    key = os.urandom(KEY_SIZE)
    plaintext = b""
    
    ciphertext, iv = cfb_encrypt(key, plaintext, None)
    decrypted = cfb_decrypt(key, ciphertext, iv)
    assert decrypted == plaintext


def test_cfb_encrypt_with_provided_iv():
    """Test CFB encrypt with provided IV."""
    key = os.urandom(KEY_SIZE)
    iv = os.urandom(IV_SIZE)
    plaintext = b"Hello, World!"
    
    ciphertext, returned_iv = cfb_encrypt(key, plaintext, iv)
    assert returned_iv == iv
    decrypted = cfb_decrypt(key, ciphertext, iv)
    assert decrypted == plaintext


def test_cfb_partial_blocks():
    """Test CFB with partial blocks."""
    key = os.urandom(KEY_SIZE)
    # Plaintext that's not a multiple of block size
    plaintext = b"Hello"  # 5 bytes
    
    ciphertext, iv = cfb_encrypt(key, plaintext, None)
    decrypted = cfb_decrypt(key, ciphertext, iv)
    assert decrypted == plaintext


def test_ofb_encrypt_decrypt_empty():
    """Test OFB with empty plaintext."""
    key = os.urandom(KEY_SIZE)
    plaintext = b""
    
    ciphertext, iv = ofb_encrypt(key, plaintext, None)
    decrypted = ofb_decrypt(key, ciphertext, iv)
    assert decrypted == plaintext


def test_ofb_encrypt_with_provided_iv():
    """Test OFB encrypt with provided IV."""
    key = os.urandom(KEY_SIZE)
    iv = os.urandom(IV_SIZE)
    plaintext = b"Hello, World!"
    
    ciphertext, returned_iv = ofb_encrypt(key, plaintext, iv)
    assert returned_iv == iv
    decrypted = ofb_decrypt(key, ciphertext, iv)
    assert decrypted == plaintext


def test_ctr_encrypt_decrypt_empty():
    """Test CTR with empty plaintext."""
    key = os.urandom(KEY_SIZE)
    plaintext = b""
    
    ciphertext, iv = ctr_encrypt(key, plaintext, None)
    decrypted = ctr_decrypt(key, ciphertext, iv)
    assert decrypted == plaintext


def test_ctr_encrypt_with_provided_iv():
    """Test CTR encrypt with provided IV."""
    key = os.urandom(KEY_SIZE)
    iv = os.urandom(IV_SIZE)
    plaintext = b"Hello, World!"
    
    ciphertext, returned_iv = ctr_encrypt(key, plaintext, iv)
    assert returned_iv == iv
    decrypted = ctr_decrypt(key, ciphertext, iv)
    assert decrypted == plaintext


def test_aes_encrypt_invalid_key_length():
    """Test aes_encrypt with invalid key length."""
    key = b"short"  # Wrong length
    plaintext = b"test"
    
    with pytest.raises(CryptoCoreError, match="Invalid key length"):
        aes_encrypt("ecb", key, plaintext)


def test_aes_decrypt_invalid_key_length():
    """Test aes_decrypt with invalid key length."""
    key = b"short"  # Wrong length
    ciphertext = b"test"
    
    with pytest.raises(CryptoCoreError, match="Invalid key length"):
        aes_decrypt("ecb", key, ciphertext)


def test_aes_encrypt_unsupported_mode():
    """Test aes_encrypt with unsupported mode."""
    key = os.urandom(KEY_SIZE)
    plaintext = b"test"
    
    with pytest.raises(CryptoCoreError, match="Unsupported mode"):
        aes_encrypt("invalid_mode", key, plaintext)


def test_aes_decrypt_unsupported_mode():
    """Test aes_decrypt with unsupported mode."""
    key = os.urandom(KEY_SIZE)
    ciphertext = b"test"
    
    with pytest.raises(CryptoCoreError, match="Unsupported mode"):
        aes_decrypt("invalid_mode", key, ciphertext)


def test_aes_decrypt_cbc_missing_iv():
    """Test aes_decrypt CBC requires IV."""
    key = os.urandom(KEY_SIZE)
    plaintext = b"test"
    ciphertext, iv = cbc_encrypt(key, plaintext, None)
    
    with pytest.raises(CryptoCoreError, match="IV is required"):
        aes_decrypt("cbc", key, ciphertext, iv=None)


def test_aes_decrypt_cfb_missing_iv():
    """Test aes_decrypt CFB requires IV."""
    key = os.urandom(KEY_SIZE)
    plaintext = b"test"
    ciphertext, iv = cfb_encrypt(key, plaintext, None)
    
    with pytest.raises(CryptoCoreError, match="IV is required"):
        aes_decrypt("cfb", key, ciphertext, iv=None)


def test_aes_decrypt_ofb_missing_iv():
    """Test aes_decrypt OFB requires IV."""
    key = os.urandom(KEY_SIZE)
    plaintext = b"test"
    ciphertext, iv = ofb_encrypt(key, plaintext, None)
    
    with pytest.raises(CryptoCoreError, match="IV is required"):
        aes_decrypt("ofb", key, ciphertext, iv=None)


def test_aes_decrypt_ctr_missing_iv():
    """Test aes_decrypt CTR requires IV."""
    key = os.urandom(KEY_SIZE)
    plaintext = b"test"
    ciphertext, iv = ctr_encrypt(key, plaintext, None)
    
    with pytest.raises(CryptoCoreError, match="IV is required"):
        aes_decrypt("ctr", key, ciphertext, iv=None)


def test_aes_encrypt_gcm_with_aad():
    """Test GCM encryption with AAD."""
    key = os.urandom(KEY_SIZE)
    plaintext = b"Hello, World!"
    aad = b"additional authenticated data"
    
    result, _ = aes_encrypt("gcm", key, plaintext, None, aad)
    assert result is not None
    
    # Decrypt with same AAD
    decrypted = aes_decrypt("gcm", key, result, None, aad)
    assert decrypted == plaintext


def test_aes_encrypt_gcm_empty_aad():
    """Test GCM encryption with empty AAD."""
    key = os.urandom(KEY_SIZE)
    plaintext = b"Hello, World!"
    
    result, _ = aes_encrypt("gcm", key, plaintext, None, None)
    assert result is not None
    
    # Decrypt with empty AAD
    decrypted = aes_decrypt("gcm", key, result, None, None)
    assert decrypted == plaintext


def test_aes_decrypt_gcm_authentication_error():
    """Test GCM decryption with wrong AAD."""
    key = os.urandom(KEY_SIZE)
    plaintext = b"Hello, World!"
    aad1 = b"aad1"
    aad2 = b"aad2"
    
    result, _ = aes_encrypt("gcm", key, plaintext, None, aad1)
    
    # Try to decrypt with wrong AAD
    with pytest.raises(CryptoCoreError):
        aes_decrypt("gcm", key, result, None, aad2)


def test_ecb_encrypt_stream_small_file(tmp_path):
    """Test ECB streaming encryption with small file."""
    key = os.urandom(KEY_SIZE)
    plaintext = b"Hello, World! " * 100
    
    input_file = tmp_path / "input.bin"
    output_file = tmp_path / "output.bin"
    input_file.write_bytes(plaintext)
    
    with open(input_file, "rb") as inf, open(output_file, "wb") as outf:
        from pycryptocore.crypto_core import ecb_encrypt_stream
        ecb_encrypt_stream(key, inf, outf)
    
    # Decrypt using non-streaming
    ciphertext = output_file.read_bytes()
    decrypted = ecb_decrypt(key, ciphertext)
    assert decrypted == plaintext


def test_cbc_encrypt_stream_small_file(tmp_path):
    """Test CBC streaming encryption with small file."""
    key = os.urandom(KEY_SIZE)
    plaintext = b"Hello, World! " * 100
    
    input_file = tmp_path / "input.bin"
    output_file = tmp_path / "output.bin"
    input_file.write_bytes(plaintext)
    
    with open(input_file, "rb") as inf, open(output_file, "wb") as outf:
        from pycryptocore.crypto_core import cbc_encrypt_stream
        iv = cbc_encrypt_stream(key, inf, outf)
        assert iv is not None
        assert len(iv) == IV_SIZE
    
    # Decrypt using non-streaming
    ciphertext = output_file.read_bytes()
    decrypted = cbc_decrypt(key, ciphertext, iv)
    assert decrypted == plaintext


def test_aes_encrypt_stream_invalid_key():
    """Test aes_encrypt_stream with invalid key."""
    key = b"short"
    input_file = io.BytesIO(b"test")
    output_file = io.BytesIO()
    
    with pytest.raises(CryptoCoreError, match="Invalid key length"):
        aes_encrypt_stream("ecb", key, input_file, output_file)


def test_aes_encrypt_stream_unsupported_mode():
    """Test aes_encrypt_stream with unsupported mode."""
    key = os.urandom(KEY_SIZE)
    input_file = io.BytesIO(b"test")
    output_file = io.BytesIO()
    
    with pytest.raises(CryptoCoreError, match="Unsupported mode"):
        aes_encrypt_stream("invalid", key, input_file, output_file)


def test_aes_encrypt_stream_gcm_not_implemented():
    """Test aes_encrypt_stream GCM not implemented."""
    key = os.urandom(KEY_SIZE)
    input_file = io.BytesIO(b"test")
    output_file = io.BytesIO()
    
    with pytest.raises(CryptoCoreError, match="GCM streaming not yet implemented"):
        aes_encrypt_stream("gcm", key, input_file, output_file)


def test_aes_decrypt_stream_invalid_key():
    """Test aes_decrypt_stream with invalid key."""
    key = b"short"
    input_file = io.BytesIO(b"test")
    output_file = io.BytesIO()
    
    with pytest.raises(CryptoCoreError, match="Invalid key length"):
        aes_decrypt_stream("ecb", key, input_file, output_file)


def test_aes_decrypt_stream_unsupported_mode():
    """Test aes_decrypt_stream with unsupported mode."""
    key = os.urandom(KEY_SIZE)
    input_file = io.BytesIO(b"test")
    output_file = io.BytesIO()
    
    with pytest.raises(CryptoCoreError, match="Unsupported mode"):
        aes_decrypt_stream("invalid", key, input_file, output_file)


def test_aes_decrypt_stream_gcm_not_implemented():
    """Test aes_decrypt_stream GCM not implemented."""
    key = os.urandom(KEY_SIZE)
    input_file = io.BytesIO(b"test")
    output_file = io.BytesIO()
    
    with pytest.raises(CryptoCoreError, match="GCM streaming not yet implemented"):
        aes_decrypt_stream("gcm", key, input_file, output_file)


def test_all_modes_round_trip():
    """Test all modes with round-trip encryption/decryption."""
    key = os.urandom(KEY_SIZE)
    plaintext = b"Test message for encryption"
    modes = ["ecb", "cbc", "cfb", "ofb", "ctr"]
    
    for mode in modes:
        ciphertext, iv = aes_encrypt(mode, key, plaintext, None)
        if mode == "ecb":
            decrypted = aes_decrypt(mode, key, ciphertext)
        else:
            decrypted = aes_decrypt(mode, key, ciphertext, iv)
        assert decrypted == plaintext, f"Mode {mode} failed"


def test_crypto_core_error():
    """Test CryptoCoreError exception."""
    error = CryptoCoreError("test error")
    assert str(error) == "test error"
    assert isinstance(error, Exception)

