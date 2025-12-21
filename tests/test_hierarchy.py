"""Tests for key hierarchy (KDF hierarchy)."""
import pytest

from pycryptocore.kdf.hierarchy import derive_key


def test_derive_key_basic():
    """Test basic key derivation."""
    master_key = b"0123456789abcdef0123456789abcdef"
    context = "test_context"
    derived = derive_key(master_key, context, length=32)
    
    assert len(derived) == 32
    assert derived != master_key
    assert isinstance(derived, bytes)


def test_derive_key_different_contexts():
    """Test that different contexts produce different keys."""
    master_key = b"0123456789abcdef0123456789abcdef"
    key1 = derive_key(master_key, "context1", length=32)
    key2 = derive_key(master_key, "context2", length=32)
    
    assert key1 != key2


def test_derive_key_bytes_context():
    """Test derive_key with bytes context."""
    master_key = b"0123456789abcdef0123456789abcdef"
    context = b"test_context_bytes"
    derived = derive_key(master_key, context, length=32)
    
    assert len(derived) == 32
    assert isinstance(derived, bytes)


def test_derive_key_custom_length():
    """Test derive_key with custom length."""
    master_key = b"0123456789abcdef0123456789abcdef"
    context = "test"
    derived = derive_key(master_key, context, length=16)
    
    assert len(derived) == 16


def test_derive_key_invalid_master_key_type():
    """Test derive_key with invalid master_key type."""
    with pytest.raises(TypeError, match="master_key must be bytes"):
        derive_key("not_bytes", "context", length=32)


def test_derive_key_invalid_context_type():
    """Test derive_key with invalid context type."""
    master_key = b"0123456789abcdef0123456789abcdef"
    with pytest.raises(TypeError, match="context must be str or bytes"):
        derive_key(master_key, 12345, length=32)  # type: ignore


def test_derive_key_zero_length():
    """Test derive_key with zero length."""
    master_key = b"0123456789abcdef0123456789abcdef"
    with pytest.raises(ValueError, match="length must be positive"):
        derive_key(master_key, "context", length=0)


def test_derive_key_negative_length():
    """Test derive_key with negative length."""
    master_key = b"0123456789abcdef0123456789abcdef"
    with pytest.raises(ValueError, match="length must be positive"):
        derive_key(master_key, "context", length=-1)


def test_derive_key_large_length():
    """Test derive_key with large length (multiple blocks)."""
    master_key = b"0123456789abcdef0123456789abcdef"
    context = "test"
    derived = derive_key(master_key, context, length=64)  # 2 blocks of 32 bytes
    
    assert len(derived) == 64
    # First 32 bytes should be different from second 32 bytes
    assert derived[:32] != derived[32:]

