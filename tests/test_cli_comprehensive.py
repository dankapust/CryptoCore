"""
Comprehensive tests for CLI module to increase coverage.
"""
import os
import subprocess
import tempfile
from pathlib import Path
import pytest

from pycryptocore.cli import main, _hex_to_bytes, _should_use_streaming, build_parser


def test_hex_to_bytes_valid():
    """Test _hex_to_bytes with valid input."""
    result = _hex_to_bytes("00112233445566778899aabbccddeeff")
    assert len(result) == 16
    assert result == bytes.fromhex("00112233445566778899aabbccddeeff")


def test_hex_to_bytes_with_expected_len():
    """Test _hex_to_bytes with expected length."""
    result = _hex_to_bytes("00112233445566778899aabbccddeeff", expected_len=16)
    assert len(result) == 16


def test_hex_to_bytes_invalid_hex():
    """Test _hex_to_bytes with invalid hex string."""
    with pytest.raises(SystemExit, match="Invalid hex string"):
        _hex_to_bytes("invalid_hex")


def test_hex_to_bytes_wrong_length():
    """Test _hex_to_bytes with wrong length."""
    with pytest.raises(SystemExit, match="Invalid length"):
        _hex_to_bytes("00112233", expected_len=16)


def test_should_use_streaming_large_file(tmp_path):
    """Test _should_use_streaming with large file."""
    large_file = tmp_path / "large.bin"
    # Create a file larger than 100 MB
    with open(large_file, "wb") as f:
        f.write(b"0" * (101 * 1024 * 1024))
    
    assert _should_use_streaming(large_file) is True


def test_should_use_streaming_small_file(tmp_path):
    """Test _should_use_streaming with small file."""
    small_file = tmp_path / "small.bin"
    small_file.write_bytes(b"small data")
    
    assert _should_use_streaming(small_file) is False


def test_should_use_streaming_nonexistent():
    """Test _should_use_streaming with nonexistent file."""
    nonexistent = Path("/nonexistent/file/path")
    # Should return True as fallback
    assert _should_use_streaming(nonexistent) is True


def test_build_parser():
    """Test build_parser function."""
    parser = build_parser()
    assert parser is not None
    # Test that parser can parse basic arguments
    args = parser.parse_args([
        "--algorithm", "aes",
        "--mode", "ecb",
        "--encrypt",
        "--key", "00112233445566778899aabbccddeeff",
        "--input", "/tmp/test"
    ])
    assert args.algorithm == "aes"
    assert args.mode == "ecb"
    assert args.encrypt is True


def test_cli_derive_password_file(tmp_path):
    """Test derive command with password file."""
    password_file = tmp_path / "pwd.txt"
    password_file.write_text("test_password_123")
    
    output_file = tmp_path / "key.bin"
    result = main([
        "derive",
        "--password-file", str(password_file),
        "--iterations", "1000",
        "--length", "32",
        "--output", str(output_file)
    ])
    
    assert result == 0
    assert output_file.exists()
    assert len(output_file.read_bytes()) == 32


def test_cli_derive_password_env(tmp_path, monkeypatch):
    """Test derive command with password from environment."""
    monkeypatch.setenv("TEST_PASSWORD", "env_password_123")
    
    output_file = tmp_path / "key.bin"
    result = main([
        "derive",
        "--password-env", "TEST_PASSWORD",
        "--iterations", "1000",
        "--length", "32",
        "--output", str(output_file)
    ])
    
    assert result == 0
    assert output_file.exists()


def test_cli_derive_password_env_not_set(tmp_path):
    """Test derive command with non-existent environment variable."""
    result = main([
        "derive",
        "--password-env", "NONEXISTENT_VAR",
        "--iterations", "1000",
        "--length", "32"
    ])
    
    assert result == 1


def test_cli_derive_multiple_password_sources(tmp_path):
    """Test derive command with multiple password sources (should fail)."""
    password_file = tmp_path / "pwd.txt"
    password_file.write_text("test")
    
    result = main([
        "derive",
        "--password", "test",
        "--password-file", str(password_file),
        "--iterations", "1000"
    ])
    
    assert result == 1


def test_cli_derive_no_password_source():
    """Test derive command with no password source."""
    result = main([
        "derive",
        "--iterations", "1000"
    ])
    
    assert result == 1


def test_cli_derive_invalid_iterations():
    """Test derive command with invalid iterations."""
    result = main([
        "derive",
        "--password", "test",
        "--iterations", "0"
    ])
    
    assert result == 1


def test_cli_derive_invalid_length():
    """Test derive command with invalid length."""
    result = main([
        "derive",
        "--password", "test",
        "--length", "0"
    ])
    
    assert result == 1


def test_cli_derive_invalid_salt():
    """Test derive command with invalid salt hex."""
    result = main([
        "derive",
        "--password", "test",
        "--salt", "invalid_hex"
    ])
    
    assert result == 1


def test_cli_derive_with_salt(tmp_path):
    """Test derive command with provided salt."""
    salt_hex = "00112233445566778899aabbccddeeff"
    result = main([
        "derive",
        "--password", "test",
        "--salt", salt_hex,
        "--iterations", "1000"
    ])
    
    assert result == 0


def test_cli_dgst_sha256(tmp_path):
    """Test dgst command with sha256."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    
    result = main([
        "dgst",
        "--algorithm", "sha256",
        "--input", str(test_file)
    ])
    
    assert result == 0


def test_cli_dgst_sha3_256(tmp_path):
    """Test dgst command with sha3-256."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    
    result = main([
        "dgst",
        "--algorithm", "sha3-256",
        "--input", str(test_file)
    ])
    
    assert result == 0


def test_cli_dgst_output_to_file(tmp_path):
    """Test dgst command with output to file."""
    test_file = tmp_path / "test.txt"
    output_file = tmp_path / "hash.txt"
    test_file.write_text("Hello, World!")
    
    result = main([
        "dgst",
        "--algorithm", "sha256",
        "--input", str(test_file),
        "--output", str(output_file)
    ])
    
    assert result == 0
    assert output_file.exists()


def test_cli_dgst_hmac(tmp_path):
    """Test dgst command with HMAC."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    key_hex = "00112233445566778899aabbccddeeff"
    
    result = main([
        "dgst",
        "--algorithm", "sha256",
        "--input", str(test_file),
        "--hmac",
        "--key", key_hex
    ])
    
    assert result == 0


def test_cli_dgst_hmac_no_key(tmp_path):
    """Test dgst command with HMAC but no key."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    
    result = main([
        "dgst",
        "--algorithm", "sha256",
        "--input", str(test_file),
        "--hmac"
    ])
    
    assert result == 1


def test_cli_dgst_hmac_wrong_algorithm(tmp_path):
    """Test dgst command with HMAC and wrong algorithm."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    key_hex = "00112233445566778899aabbccddeeff"
    
    result = main([
        "dgst",
        "--algorithm", "sha3-256",
        "--input", str(test_file),
        "--hmac",
        "--key", key_hex
    ])
    
    assert result == 1


def test_cli_dgst_cmac(tmp_path):
    """Test dgst command with CMAC."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    key_hex = "00112233445566778899aabbccddeeff"
    
    result = main([
        "dgst",
        "--algorithm", "sha256",
        "--input", str(test_file),
        "--cmac",
        "--key", key_hex
    ])
    
    assert result == 0


def test_cli_dgst_cmac_no_key(tmp_path):
    """Test dgst command with CMAC but no key."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    
    result = main([
        "dgst",
        "--algorithm", "sha256",
        "--input", str(test_file),
        "--cmac"
    ])
    
    assert result == 1


def test_cli_dgst_hmac_and_cmac_together(tmp_path):
    """Test dgst command with both HMAC and CMAC (should fail)."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    key_hex = "00112233445566778899aabbccddeeff"
    
    result = main([
        "dgst",
        "--algorithm", "sha256",
        "--input", str(test_file),
        "--hmac",
        "--cmac",
        "--key", key_hex
    ])
    
    assert result == 1


def test_cli_dgst_hmac_verify_success(tmp_path):
    """Test dgst command with HMAC verification (success)."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    key_hex = "00112233445566778899aabbccddeeff"
    verify_file = tmp_path / "verify.txt"
    
    # First generate HMAC
    result1 = main([
        "dgst",
        "--algorithm", "sha256",
        "--input", str(test_file),
        "--hmac",
        "--key", key_hex,
        "--output", str(verify_file)
    ])
    assert result1 == 0
    
    # Then verify
    result2 = main([
        "dgst",
        "--algorithm", "sha256",
        "--input", str(test_file),
        "--hmac",
        "--key", key_hex,
        "--verify", str(verify_file)
    ])
    
    assert result2 == 0


def test_cli_dgst_hmac_verify_failure(tmp_path):
    """Test dgst command with HMAC verification (failure)."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    key_hex = "00112233445566778899aabbccddeeff"
    verify_file = tmp_path / "verify.txt"
    verify_file.write_text("wrong_hmac_value_here")
    
    result = main([
        "dgst",
        "--algorithm", "sha256",
        "--input", str(test_file),
        "--hmac",
        "--key", key_hex,
        "--verify", str(verify_file)
    ])
    
    assert result == 1


def test_cli_dgst_cmac_verify_success(tmp_path):
    """Test dgst command with CMAC verification (success)."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    key_hex = "00112233445566778899aabbccddeeff"
    verify_file = tmp_path / "verify.txt"
    
    # First generate CMAC
    result1 = main([
        "dgst",
        "--algorithm", "sha256",
        "--input", str(test_file),
        "--cmac",
        "--key", key_hex,
        "--output", str(verify_file)
    ])
    assert result1 == 0
    
    # Then verify
    result2 = main([
        "dgst",
        "--algorithm", "sha256",
        "--input", str(test_file),
        "--cmac",
        "--key", key_hex,
        "--verify", str(verify_file)
    ])
    
    assert result2 == 0


def test_cli_dgst_cmac_verify_failure(tmp_path):
    """Test dgst command with CMAC verification (failure)."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    key_hex = "00112233445566778899aabbccddeeff"
    verify_file = tmp_path / "verify.txt"
    verify_file.write_text("wrong_cmac_value_here")
    
    result = main([
        "dgst",
        "--algorithm", "sha256",
        "--input", str(test_file),
        "--cmac",
        "--key", key_hex,
        "--verify", str(verify_file)
    ])
    
    assert result == 1


def test_cli_dgst_verify_file_not_found(tmp_path):
    """Test dgst command with verification file not found."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    key_hex = "00112233445566778899aabbccddeeff"
    
    result = main([
        "dgst",
        "--algorithm", "sha256",
        "--input", str(test_file),
        "--hmac",
        "--key", key_hex,
        "--verify", "/nonexistent/file"
    ])
    
    assert result == 1


def test_cli_dgst_invalid_key_hex(tmp_path):
    """Test dgst command with invalid key hex."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    
    result = main([
        "dgst",
        "--algorithm", "sha256",
        "--input", str(test_file),
        "--hmac",
        "--key", "invalid_hex"
    ])
    
    assert result == 1


def test_cli_dgst_input_file_not_found():
    """Test dgst command with input file not found."""
    result = main([
        "dgst",
        "--algorithm", "sha256",
        "--input", "/nonexistent/file"
    ])
    
    assert result == 1


def test_cli_encrypt_with_password(tmp_path):
    """Test encrypt command with password."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    output_file = tmp_path / "encrypted.bin"
    
    result = main([
        "--algorithm", "aes",
        "--mode", "cbc",
        "--encrypt",
        "--password", "test_password",
        "--input", str(test_file),
        "--output", str(output_file)
    ])
    
    assert result == 0
    assert output_file.exists()


def test_cli_encrypt_with_aad(tmp_path):
    """Test encrypt command with AAD (GCM mode)."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    output_file = tmp_path / "encrypted.bin"
    key_hex = "00112233445566778899aabbccddeeff"
    aad_hex = "aabbccdd"
    
    result = main([
        "--algorithm", "aes",
        "--mode", "gcm",
        "--encrypt",
        "--key", key_hex,
        "--aad", aad_hex,
        "--input", str(test_file),
        "--output", str(output_file)
    ])
    
    assert result == 0
    assert output_file.exists()


def test_cli_decrypt_with_aad(tmp_path):
    """Test decrypt command with AAD (GCM mode)."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    encrypted_file = tmp_path / "encrypted.bin"
    decrypted_file = tmp_path / "decrypted.txt"
    key_hex = "00112233445566778899aabbccddeeff"
    aad_hex = "aabbccdd"
    
    # First encrypt
    result1 = main([
        "--algorithm", "aes",
        "--mode", "gcm",
        "--encrypt",
        "--key", key_hex,
        "--aad", aad_hex,
        "--input", str(test_file),
        "--output", str(encrypted_file)
    ])
    assert result1 == 0
    
    # Then decrypt
    result2 = main([
        "--algorithm", "aes",
        "--mode", "gcm",
        "--decrypt",
        "--key", key_hex,
        "--aad", aad_hex,
        "--input", str(encrypted_file),
        "--output", str(decrypted_file)
    ])
    
    assert result2 == 0
    assert decrypted_file.read_text() == "Hello, World!"


def test_cli_invalid_algorithm(tmp_path):
    """Test CLI with invalid algorithm."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("test")
    
    # This will raise SystemExit, but we catch it in main
    # Actually, argparse will fail before main processes it
    # So we need to test it differently
    try:
        result = main([
            "--algorithm", "invalid",
            "--mode", "ecb",
            "--encrypt",
            "--key", "00112233445566778899aabbccddeeff",
            "--input", str(test_file)
        ])
        # If we get here, it means argparse rejected it
        assert result == 1 or result == 2
    except SystemExit:
        # argparse raises SystemExit for invalid arguments
        pass


def test_cli_input_file_not_found():
    """Test CLI with input file not found."""
    result = main([
        "--algorithm", "aes",
        "--mode", "ecb",
        "--encrypt",
        "--key", "00112233445566778899aabbccddeeff",
        "--input", "/nonexistent/file"
    ])
    
    assert result == 1


def test_cli_invalid_aad_hex(tmp_path):
    """Test CLI with invalid AAD hex string."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, World!")
    
    result = main([
        "--algorithm", "aes",
        "--mode", "gcm",
        "--encrypt",
        "--key", "00112233445566778899aabbccddeeff",
        "--aad", "invalid_hex",
        "--input", str(test_file)
    ])
    
    assert result == 1


def test_cli_decrypt_with_iv(tmp_path):
    """Test decrypt command with provided IV."""
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"Hello, World!")
    encrypted_file = tmp_path / "encrypted.bin"
    decrypted_file = tmp_path / "decrypted.bin"
    key_hex = "00112233445566778899aabbccddeeff"
    
    # First encrypt
    result1 = main([
        "--algorithm", "aes",
        "--mode", "cbc",
        "--encrypt",
        "--key", key_hex,
        "--input", str(test_file),
        "--output", str(encrypted_file)
    ])
    assert result1 == 0
    
    # Read IV from encrypted file (first 16 bytes for CBC format: IV || ciphertext)
    encrypted_data = encrypted_file.read_bytes()
    iv = encrypted_data[:16]
    iv_hex = iv.hex()
    ciphertext_only = encrypted_data[16:]  # Without IV
    
    # Create a file with just ciphertext (without IV header)
    ciphertext_file = tmp_path / "ciphertext_only.bin"
    ciphertext_file.write_bytes(ciphertext_only)
    
    # Decrypt with explicit IV (this will use the provided IV instead of reading from file)
    result2 = main([
        "--algorithm", "aes",
        "--mode", "cbc",
        "--decrypt",
        "--key", key_hex,
        "--iv", iv_hex,
        "--input", str(ciphertext_file),  # File without IV header
        "--output", str(decrypted_file)
    ])
    
    assert result2 == 0
    assert decrypted_file.read_bytes() == b"Hello, World!"

