"""
Tests for legacy KDF module (kdf.py and kdf_legacy.py).
"""
import sys
import importlib.util
import pytest
from pathlib import Path

# Import kdf.py module directly (not the kdf/ package)
# Need to add to sys.modules first to handle relative imports
kdf_module_path = Path(__file__).parent.parent / "pycryptocore" / "kdf.py"
spec = importlib.util.spec_from_file_location("pycryptocore.kdf_module", kdf_module_path)
kdf_module = importlib.util.module_from_spec(spec)
sys.modules["pycryptocore.kdf_module"] = kdf_module
# Also need to add parent module
if "pycryptocore" not in sys.modules:
    import pycryptocore
spec.loader.exec_module(kdf_module)

# Import kdf_legacy.py module directly
kdf_legacy_path = Path(__file__).parent.parent / "pycryptocore" / "kdf_legacy.py"
spec_legacy = importlib.util.spec_from_file_location("pycryptocore.kdf_legacy", kdf_legacy_path)
kdf_legacy = importlib.util.module_from_spec(spec_legacy)
sys.modules["pycryptocore.kdf_legacy"] = kdf_legacy
spec_legacy.loader.exec_module(kdf_legacy)


def test_derive_key_from_password():
    """Test derive_key_from_password function from kdf.py."""
    password = "test_password_123"
    salt = kdf_module.generate_salt()
    
    # Should derive a 16-byte key
    key = kdf_module.derive_key_from_password(password, salt)
    assert len(key) == 16
    assert isinstance(key, bytes)
    
    # Same password and salt should produce same key
    key2 = kdf_module.derive_key_from_password(password, salt)
    assert key == key2
    
    # Different salt should produce different key
    salt2 = kdf_module.generate_salt()
    key3 = kdf_module.derive_key_from_password(password, salt2)
    assert key != key3


def test_derive_key_from_password_wrong_salt_size():
    """Test derive_key_from_password with wrong salt size."""
    password = "test_password"
    wrong_salt = b"short"  # Too short
    
    with pytest.raises(ValueError, match="salt must be 16 bytes"):
        kdf_module.derive_key_from_password(password, wrong_salt)


def test_derive_key_from_password_wrong_type():
    """Test derive_key_from_password with wrong password type."""
    salt = kdf_module.generate_salt()
    
    with pytest.raises(TypeError, match="password must be a string"):
        kdf_module.derive_key_from_password(b"bytes_password", salt)


def test_generate_salt():
    """Test generate_salt function."""
    salt = kdf_module.generate_salt()
    assert len(salt) == kdf_module.SALT_SIZE
    assert isinstance(salt, bytes)
    
    # Generate multiple salts - should be different
    salts = {kdf_module.generate_salt() for _ in range(100)}
    assert len(salts) == 100  # All unique


def test_legacy_derive_key_from_password():
    """Test legacy derive_key_from_password function."""
    password = "test_password_123"
    salt = kdf_legacy.generate_salt()
    
    # Should derive a 16-byte key
    key = kdf_legacy.derive_key_from_password(password, salt)
    assert len(key) == 16
    assert isinstance(key, bytes)
    
    # Same password and salt should produce same key
    key2 = kdf_legacy.derive_key_from_password(password, salt)
    assert key == key2


def test_legacy_derive_key_from_password_wrong_salt_size():
    """Test legacy derive_key_from_password with wrong salt size."""
    password = "test_password"
    wrong_salt = b"short"  # Too short
    
    with pytest.raises(ValueError, match="salt must be 16 bytes"):
        kdf_legacy.derive_key_from_password(password, wrong_salt)


def test_legacy_derive_key_from_password_wrong_type():
    """Test legacy derive_key_from_password with wrong password type."""
    salt = kdf_legacy.generate_salt()
    
    with pytest.raises(TypeError, match="password must be a string"):
        kdf_legacy.derive_key_from_password(b"bytes_password", salt)


def test_legacy_generate_salt():
    """Test legacy generate_salt function."""
    salt = kdf_legacy.generate_salt()
    assert len(salt) == kdf_legacy.SALT_SIZE
    assert isinstance(salt, bytes)
    
    # Generate multiple salts - should be different
    salts = {kdf_legacy.generate_salt() for _ in range(100)}
    assert len(salts) == 100  # All unique

