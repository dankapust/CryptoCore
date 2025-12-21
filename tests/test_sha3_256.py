"""
Tests for SHA3-256 module.
"""
import hashlib
import pytest

from pycryptocore.hash.sha3_256 import SHA3_256


def test_sha3_256_empty():
    """Test SHA3-256 with empty input."""
    sha = SHA3_256()
    sha.update(b"")
    result = sha.hexdigest()
    expected = hashlib.sha3_256(b"").hexdigest()
    assert result == expected


def test_sha3_256_known_vectors():
    """Test SHA3-256 with known test vectors."""
    # NIST FIPS 202 test vectors
    vectors = {
        b"": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        b"abc": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq": "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
    }
    
    for msg, expected in vectors.items():
        sha = SHA3_256()
        sha.update(msg)
        assert sha.hexdigest() == expected


def test_sha3_256_chunked():
    """Test SHA3-256 with chunked updates."""
    data = b"Hello, World! " * 100
    sha = SHA3_256()
    
    # Update in chunks
    chunk_size = 50
    for i in range(0, len(data), chunk_size):
        sha.update(data[i:i + chunk_size])
    
    result = sha.hexdigest()
    expected = hashlib.sha3_256(data).hexdigest()
    assert result == expected


def test_sha3_256_digest():
    """Test SHA3-256 digest method."""
    data = b"test data"
    sha = SHA3_256()
    sha.update(data)
    
    digest = sha.digest()
    assert isinstance(digest, bytes)
    assert len(digest) == 32  # SHA3-256 produces 32 bytes
    
    # Verify it matches hashlib
    expected = hashlib.sha3_256(data).digest()
    assert digest == expected


def test_sha3_256_hexdigest():
    """Test SHA3-256 hexdigest method."""
    data = b"test data"
    sha = SHA3_256()
    sha.update(data)
    
    hexdigest = sha.hexdigest()
    assert isinstance(hexdigest, str)
    assert len(hexdigest) == 64  # 32 bytes = 64 hex chars
    
    # Verify it matches hashlib
    expected = hashlib.sha3_256(data).hexdigest()
    assert hexdigest == expected


def test_sha3_256_hash_bytes():
    """Test SHA3-256 hash_bytes method."""
    data = b"test data"
    sha = SHA3_256()
    
    result = sha.hash_bytes(data)
    assert isinstance(result, str)
    assert len(result) == 64
    
    # Verify it matches hashlib
    expected = hashlib.sha3_256(data).hexdigest()
    assert result == expected


def test_sha3_256_hash_bytes_resets():
    """Test that hash_bytes resets the hash object."""
    data1 = b"first"
    data2 = b"second"
    
    sha = SHA3_256()
    sha.update(data1)
    result1 = sha.hash_bytes(data2)
    
    # Should only hash data2, not data1+data2
    expected = hashlib.sha3_256(data2).hexdigest()
    assert result1 == expected


def test_sha3_256_empty_update():
    """Test SHA3-256 with empty update (should not affect hash)."""
    sha = SHA3_256()
    sha.update(b"test")
    sha.update(b"")  # Empty update
    sha.update(b"data")
    
    result = sha.hexdigest()
    expected = hashlib.sha3_256(b"testdata").hexdigest()
    assert result == expected


def test_sha3_256_multiple_hashes():
    """Test creating multiple SHA3-256 instances."""
    data1 = b"first"
    data2 = b"second"
    
    sha1 = SHA3_256()
    sha1.update(data1)
    
    sha2 = SHA3_256()
    sha2.update(data2)
    
    result1 = sha1.hexdigest()
    result2 = sha2.hexdigest()
    
    assert result1 != result2
    assert result1 == hashlib.sha3_256(data1).hexdigest()
    assert result2 == hashlib.sha3_256(data2).hexdigest()

