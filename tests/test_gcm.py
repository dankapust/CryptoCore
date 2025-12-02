"""
Tests for GCM (Galois/Counter Mode) implementation.
"""
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from pycryptocore.modes.gcm import GCM, AuthenticationError


def test_gcm_basic_encrypt_decrypt():
    """Test basic GCM encryption and decryption."""
    key = os.urandom(16)
    plaintext = b"Hello GCM world"
    
    gcm = GCM(key)
    ciphertext = gcm.encrypt(plaintext)
    
    # Verify format: nonce (12) || ciphertext || tag (16)
    assert len(ciphertext) >= 28  # At least nonce + tag
    nonce = ciphertext[:12]
    tag = ciphertext[-16:]
    
    # Decrypt
    gcm2 = GCM(key, nonce=nonce)
    decrypted = gcm2.decrypt(ciphertext)
    
    assert decrypted == plaintext


def test_gcm_with_aad():
    """Test GCM with Associated Authenticated Data."""
    key = os.urandom(16)
    plaintext = b"Secret message"
    aad = b"associated data"
    
    gcm = GCM(key)
    ciphertext = gcm.encrypt(plaintext, aad)
    
    # Decrypt with correct AAD
    nonce = ciphertext[:12]
    gcm2 = GCM(key, nonce=nonce)
    decrypted = gcm2.decrypt(ciphertext, aad)
    
    assert decrypted == plaintext


def test_gcm_wrong_aad_fails():
    """Test that wrong AAD causes authentication failure."""
    key = os.urandom(16)
    plaintext = b"Secret message"
    aad_correct = b"correct aad"
    aad_wrong = b"wrong aad"
    
    gcm = GCM(key)
    ciphertext = gcm.encrypt(plaintext, aad_correct)
    
    # Try to decrypt with wrong AAD
    nonce = ciphertext[:12]
    gcm2 = GCM(key, nonce=nonce)
    
    with pytest.raises(AuthenticationError):
        gcm2.decrypt(ciphertext, aad_wrong)


def test_gcm_tampered_ciphertext_fails():
    """Test that tampering with ciphertext causes authentication failure."""
    key = os.urandom(16)
    plaintext = b"Another secret message"
    aad = b"associated data"
    
    gcm = GCM(key)
    ciphertext = gcm.encrypt(plaintext, aad)
    
    # Tamper with ciphertext (flip one bit)
    tampered = bytearray(ciphertext)
    tampered[20] ^= 0x01  # Flip one bit in the ciphertext part
    
    nonce = ciphertext[:12]
    gcm2 = GCM(key, nonce=nonce)
    
    with pytest.raises(AuthenticationError):
        gcm2.decrypt(bytes(tampered), aad)


def test_gcm_tampered_tag_fails():
    """Test that tampering with tag causes authentication failure."""
    key = os.urandom(16)
    plaintext = b"Secret message"
    
    gcm = GCM(key)
    ciphertext = gcm.encrypt(plaintext)
    
    # Tamper with tag (flip one bit)
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0x01  # Flip last bit of tag
    
    nonce = ciphertext[:12]
    gcm2 = GCM(key, nonce=nonce)
    
    with pytest.raises(AuthenticationError):
        gcm2.decrypt(bytes(tampered))


def test_gcm_empty_aad():
    """Test GCM with empty AAD."""
    key = os.urandom(16)
    plaintext = b"Message with empty AAD"
    
    gcm = GCM(key)
    ciphertext = gcm.encrypt(plaintext, b"")
    
    nonce = ciphertext[:12]
    gcm2 = GCM(key, nonce=nonce)
    decrypted = gcm2.decrypt(ciphertext, b"")
    
    assert decrypted == plaintext


def test_gcm_empty_plaintext():
    """Test GCM with empty plaintext."""
    key = os.urandom(16)
    plaintext = b""
    
    gcm = GCM(key)
    ciphertext = gcm.encrypt(plaintext)
    
    nonce = ciphertext[:12]
    gcm2 = GCM(key, nonce=nonce)
    decrypted = gcm2.decrypt(ciphertext)
    
    assert decrypted == plaintext


def test_gcm_nonce_uniqueness():
    """Test that each encryption generates a unique nonce."""
    key = os.urandom(16)
    plaintext = b"Test message"
    
    nonces = set()
    for _ in range(100):
        gcm = GCM(key)
        ciphertext = gcm.encrypt(plaintext)
        nonce = ciphertext[:12]
        nonces.add(nonce)
    
    # All nonces should be unique
    assert len(nonces) == 100


def test_gcm_large_plaintext():
    """Test GCM with large plaintext."""
    key = os.urandom(16)
    plaintext = b"X" * 10000  # 10KB
    
    gcm = GCM(key)
    ciphertext = gcm.encrypt(plaintext)
    
    nonce = ciphertext[:12]
    gcm2 = GCM(key, nonce=nonce)
    decrypted = gcm2.decrypt(ciphertext)
    
    assert decrypted == plaintext


def test_gcm_large_aad():
    """Test GCM with large AAD."""
    key = os.urandom(16)
    plaintext = b"Message"
    aad = b"Y" * 5000  # 5KB AAD
    
    gcm = GCM(key)
    ciphertext = gcm.encrypt(plaintext, aad)
    
    nonce = ciphertext[:12]
    gcm2 = GCM(key, nonce=nonce)
    decrypted = gcm2.decrypt(ciphertext, aad)
    
    assert decrypted == plaintext


def test_cli_gcm_encrypt_decrypt(tmp_path):
    """Test CLI GCM encryption and decryption."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello GCM")
    
    key = "00112233445566778899aabbccddeeff"
    output_file = tmp_path / "encrypted.bin"
    decrypted_file = tmp_path / "decrypted.txt"
    
    # Encrypt
    cmd_encrypt = [
        "python", "-m", "pycryptocore.cli",
        "--algorithm", "aes",
        "--mode", "gcm",
        "--encrypt",
        "--key", key,
        "--input", str(test_file),
        "--output", str(output_file)
    ]
    result = subprocess.run(cmd_encrypt, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0
    
    # Decrypt
    cmd_decrypt = [
        "python", "-m", "pycryptocore.cli",
        "--algorithm", "aes",
        "--mode", "gcm",
        "--decrypt",
        "--key", key,
        "--input", str(output_file),
        "--output", str(decrypted_file)
    ]
    result = subprocess.run(cmd_decrypt, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0
    
    assert decrypted_file.read_text() == "Hello GCM"


def test_cli_gcm_with_aad(tmp_path):
    """Test CLI GCM with AAD."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Secret message")
    
    key = "00112233445566778899aabbccddeeff"
    aad = "aabbccddeeff"
    output_file = tmp_path / "encrypted.bin"
    decrypted_file = tmp_path / "decrypted.txt"
    
    # Encrypt with AAD
    cmd_encrypt = [
        "python", "-m", "pycryptocore.cli",
        "--algorithm", "aes",
        "--mode", "gcm",
        "--encrypt",
        "--key", key,
        "--aad", aad,
        "--input", str(test_file),
        "--output", str(output_file)
    ]
    result = subprocess.run(cmd_encrypt, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0
    
    # Decrypt with correct AAD
    cmd_decrypt = [
        "python", "-m", "pycryptocore.cli",
        "--algorithm", "aes",
        "--mode", "gcm",
        "--decrypt",
        "--key", key,
        "--aad", aad,
        "--input", str(output_file),
        "--output", str(decrypted_file)
    ]
    result = subprocess.run(cmd_decrypt, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0
    
    assert decrypted_file.read_text() == "Secret message"


def test_cli_gcm_wrong_aad_fails(tmp_path):
    """Test CLI GCM fails with wrong AAD."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Secret message")
    
    key = "00112233445566778899aabbccddeeff"
    aad_correct = "aabbccddeeff"
    aad_wrong = "112233445566"
    output_file = tmp_path / "encrypted.bin"
    decrypted_file = tmp_path / "decrypted.txt"
    
    # Encrypt with AAD
    cmd_encrypt = [
        "python", "-m", "pycryptocore.cli",
        "--algorithm", "aes",
        "--mode", "gcm",
        "--encrypt",
        "--key", key,
        "--aad", aad_correct,
        "--input", str(test_file),
        "--output", str(output_file)
    ]
    subprocess.run(cmd_encrypt, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Try to decrypt with wrong AAD
    cmd_decrypt = [
        "python", "-m", "pycryptocore.cli",
        "--algorithm", "aes",
        "--mode", "gcm",
        "--decrypt",
        "--key", key,
        "--aad", aad_wrong,
        "--input", str(output_file),
        "--output", str(decrypted_file)
    ]
    result = subprocess.run(cmd_decrypt, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode != 0
    assert "Authentication failed" in result.stderr or "authentication" in result.stderr.lower()
    
    # Verify output file was not created
    assert not decrypted_file.exists()


def test_cli_gcm_tampered_file_fails(tmp_path):
    """Test CLI GCM fails with tampered file."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Original message")
    
    key = "00112233445566778899aabbccddeeff"
    output_file = tmp_path / "encrypted.bin"
    decrypted_file = tmp_path / "decrypted.txt"
    
    # Encrypt
    cmd_encrypt = [
        "python", "-m", "pycryptocore.cli",
        "--algorithm", "aes",
        "--mode", "gcm",
        "--encrypt",
        "--key", key,
        "--input", str(test_file),
        "--output", str(output_file)
    ]
    subprocess.run(cmd_encrypt, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Tamper with file
    data = output_file.read_bytes()
    tampered = bytearray(data)
    tampered[20] ^= 0x01  # Flip one bit
    output_file.write_bytes(bytes(tampered))
    
    # Try to decrypt
    cmd_decrypt = [
        "python", "-m", "pycryptocore.cli",
        "--algorithm", "aes",
        "--mode", "gcm",
        "--decrypt",
        "--key", key,
        "--input", str(output_file),
        "--output", str(decrypted_file)
    ]
    result = subprocess.run(cmd_decrypt, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode != 0
    assert "Authentication failed" in result.stderr or "authentication" in result.stderr.lower()
    
    # Verify output file was not created
    assert not decrypted_file.exists()

