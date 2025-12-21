"""
Tests for file_io module.
"""
import os
import tempfile
from pathlib import Path
import pytest

from pycryptocore.file_io import (
    read_all_bytes,
    write_all_bytes,
    create_temp_file,
    move_temp_to_final,
    cleanup_temp_file,
    write_with_salt_iv,
    read_with_salt_iv,
    write_with_iv,
    read_with_iv,
    write_with_nonce_tag,
    read_with_nonce_tag,
)


def test_read_all_bytes(tmp_path):
    """Test read_all_bytes function."""
    test_file = tmp_path / "test.bin"
    test_data = b"Hello, World!"
    test_file.write_bytes(test_data)
    
    result = read_all_bytes(test_file)
    assert result == test_data
    
    # Test with string path
    result2 = read_all_bytes(str(test_file))
    assert result2 == test_data


def test_write_all_bytes(tmp_path):
    """Test write_all_bytes function."""
    test_file = tmp_path / "test.bin"
    test_data = b"Hello, World!"
    
    write_all_bytes(test_file, test_data)
    assert test_file.read_bytes() == test_data
    
    # Test with string path
    test_file2 = tmp_path / "test2.bin"
    write_all_bytes(str(test_file2), test_data)
    assert test_file2.read_bytes() == test_data


def test_create_temp_file():
    """Test create_temp_file function."""
    temp_file = create_temp_file()
    assert isinstance(temp_file, Path)
    assert temp_file.exists()
    
    # Cleanup
    temp_file.unlink()
    
    # Test with suffix
    temp_file2 = create_temp_file(suffix=".test")
    assert temp_file2.suffix == ".test"
    temp_file2.unlink()


def test_move_temp_to_final(tmp_path):
    """Test move_temp_to_final function."""
    temp_file = create_temp_file()
    temp_file.write_bytes(b"test data")
    
    final_file = tmp_path / "final.bin"
    move_temp_to_final(temp_file, final_file)
    
    assert not temp_file.exists()
    assert final_file.exists()
    assert final_file.read_bytes() == b"test data"


def test_cleanup_temp_file():
    """Test cleanup_temp_file function."""
    # Test with existing file
    temp_file = create_temp_file()
    temp_file.write_bytes(b"test")
    assert temp_file.exists()
    
    cleanup_temp_file(temp_file)
    assert not temp_file.exists()
    
    # Test with None
    cleanup_temp_file(None)  # Should not raise
    
    # Test with non-existent file
    non_existent = Path("/tmp/non_existent_file_12345")
    cleanup_temp_file(non_existent)  # Should not raise


def test_write_with_salt_iv(tmp_path):
    """Test write_with_salt_iv function."""
    test_file = tmp_path / "test.bin"
    salt = b"a" * 16
    iv = b"b" * 16
    ciphertext = b"ciphertext data"
    
    write_with_salt_iv(test_file, salt, iv, ciphertext)
    
    data = test_file.read_bytes()
    assert data == salt + iv + ciphertext


def test_read_with_salt_iv(tmp_path):
    """Test read_with_salt_iv function."""
    test_file = tmp_path / "test.bin"
    salt = b"a" * 16
    iv = b"b" * 16
    ciphertext = b"ciphertext data"
    test_file.write_bytes(salt + iv + ciphertext)
    
    read_salt, read_iv, read_ciphertext = read_with_salt_iv(test_file)
    assert read_salt == salt
    assert read_iv == iv
    assert read_ciphertext == ciphertext


def test_read_with_salt_iv_too_short(tmp_path):
    """Test read_with_salt_iv with file too short."""
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"short")  # Less than 32 bytes
    
    with pytest.raises(ValueError, match="file too short"):
        read_with_salt_iv(test_file)


def test_write_with_iv(tmp_path):
    """Test write_with_iv function."""
    test_file = tmp_path / "test.bin"
    iv = b"b" * 16
    ciphertext = b"ciphertext data"
    
    write_with_iv(test_file, iv, ciphertext)
    
    data = test_file.read_bytes()
    assert data == iv + ciphertext


def test_read_with_iv(tmp_path):
    """Test read_with_iv function."""
    test_file = tmp_path / "test.bin"
    iv = b"b" * 16
    ciphertext = b"ciphertext data"
    test_file.write_bytes(iv + ciphertext)
    
    read_iv, read_ciphertext = read_with_iv(test_file)
    assert read_iv == iv
    assert read_ciphertext == ciphertext


def test_read_with_iv_too_short(tmp_path):
    """Test read_with_iv with file too short."""
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"short")  # Less than 16 bytes
    
    with pytest.raises(ValueError, match="file too short"):
        read_with_iv(test_file)


def test_write_with_nonce_tag(tmp_path):
    """Test write_with_nonce_tag function."""
    test_file = tmp_path / "test.bin"
    nonce = b"n" * 12
    ciphertext = b"ciphertext data"
    tag = b"t" * 16
    
    write_with_nonce_tag(test_file, nonce, ciphertext, tag)
    
    data = test_file.read_bytes()
    assert data == nonce + ciphertext + tag


def test_read_with_nonce_tag(tmp_path):
    """Test read_with_nonce_tag function."""
    test_file = tmp_path / "test.bin"
    nonce = b"n" * 12
    ciphertext = b"ciphertext data"
    tag = b"t" * 16
    test_file.write_bytes(nonce + ciphertext + tag)
    
    read_nonce, read_ciphertext, read_tag = read_with_nonce_tag(test_file)
    assert read_nonce == nonce
    assert read_ciphertext == ciphertext
    assert read_tag == tag


def test_read_with_nonce_tag_too_short(tmp_path):
    """Test read_with_nonce_tag with file too short."""
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"short")  # Less than 28 bytes
    
    with pytest.raises(ValueError, match="file too short"):
        read_with_nonce_tag(test_file)


def test_read_with_nonce_tag_empty_ciphertext(tmp_path):
    """Test read_with_nonce_tag with empty ciphertext."""
    test_file = tmp_path / "test.bin"
    nonce = b"n" * 12
    ciphertext = b""
    tag = b"t" * 16
    test_file.write_bytes(nonce + ciphertext + tag)
    
    read_nonce, read_ciphertext, read_tag = read_with_nonce_tag(test_file)
    assert read_nonce == nonce
    assert read_ciphertext == ciphertext
    assert read_tag == tag

