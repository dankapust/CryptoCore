"""
Tests for AES-CMAC implementation.
"""
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from pycryptocore.mac.cmac import CMAC


def test_cmac_basic():
    """Test basic CMAC computation."""
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    message = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
    
    cmac = CMAC(key)
    result = cmac.compute(message)
    
    # Expected CMAC from NIST test vector
    expected = bytes.fromhex('070a16b46b4d4144f79bdd9dd04a287c')
    assert result == expected


def test_cmac_empty_message():
    """Test CMAC with empty message."""
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    
    cmac = CMAC(key)
    result = cmac.compute(b'')
    
    # Empty message should use K1
    assert len(result) == 16


def test_cmac_incomplete_block():
    """Test CMAC with message that doesn't fill a complete block."""
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    message = b'Hello'  # 5 bytes, less than 16
    
    cmac = CMAC(key)
    result = cmac.compute(message)
    
    assert len(result) == 16


def test_cmac_multiple_blocks():
    """Test CMAC with multiple complete blocks."""
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    message = b'X' * 32  # Exactly 2 blocks
    
    cmac = CMAC(key)
    result = cmac.compute(message)
    
    assert len(result) == 16


def test_cmac_chunk_processing():
    """Test CMAC with chunked message processing."""
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    message = b'Hello, world! ' * 100  # Large message
    
    # Process in chunks
    chunks = [message[i:i+8192] for i in range(0, len(message), 8192)]
    cmac = CMAC(key)
    result_chunked = cmac.update_compute(chunks)
    
    # Process as single message
    cmac2 = CMAC(key)
    result_single = cmac2.compute(message)
    
    assert result_chunked == result_single


def test_cmac_hexdigest():
    """Test CMAC hexdigest output."""
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    message = b'Test message'
    
    cmac = CMAC(key)
    result_hex = cmac.hexdigest(message)
    result_bytes = cmac.compute(message)
    
    assert result_hex == result_bytes.hex()
    assert len(result_hex) == 32  # 128 bits = 32 hex chars


def test_cmac_tamper_detection():
    """Test that changing one bit produces completely different CMAC."""
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    original_data = b"Hello, world!"
    modified_data = b"Hello, world?"  # Changed last character
    
    cmac1 = CMAC(key)
    mac1 = cmac1.compute(original_data)
    
    cmac2 = CMAC(key)
    mac2 = cmac2.compute(modified_data)
    
    # CMACs should be different
    assert mac1 != mac2
    
    # Convert to binary and count differing bits
    bin1 = bin(int.from_bytes(mac1, 'big'))[2:].zfill(128)
    bin2 = bin(int.from_bytes(mac2, 'big'))[2:].zfill(128)
    diff_count = sum(bit1 != bit2 for bit1, bit2 in zip(bin1, bin2))
    
    # Avalanche effect: should be ~64 bits changed (50%)
    assert 30 < diff_count < 98, f"Avalanche effect weak: only {diff_count} bits changed"


def test_cli_cmac_generate(tmp_path):
    """Test CLI CMAC generation."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello CMAC")
    
    cmd = [
        "python", "-m", "pycryptocore.cli", "dgst",
        "--algorithm", "sha256",  # Algorithm is ignored for CMAC
        "--cmac",
        "--key", "2b7e151628aed2a6abf7158809cf4f3c",
        "--input", str(test_file)
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.returncode == 0
    out = proc.stdout.strip()
    parts = out.split()
    assert len(parts[0]) == 32  # CMAC is 32 hex chars (128 bits)


def test_cli_cmac_verify_success(tmp_path):
    """Test CLI CMAC verification (success case)."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello CMAC")
    
    # Generate CMAC
    cmd_gen = [
        "python", "-m", "pycryptocore.cli", "dgst",
        "--algorithm", "sha256",
        "--cmac",
        "--key", "2b7e151628aed2a6abf7158809cf4f3c",
        "--input", str(test_file),
        "--output", str(tmp_path / "cmac.txt")
    ]
    subprocess.run(cmd_gen, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Verify
    cmd_verify = [
        "python", "-m", "pycryptocore.cli", "dgst",
        "--algorithm", "sha256",
        "--cmac",
        "--key", "2b7e151628aed2a6abf7158809cf4f3c",
        "--input", str(test_file),
        "--verify", str(tmp_path / "cmac.txt")
    ]
    proc = subprocess.run(cmd_verify, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.returncode == 0
    assert "[OK] CMAC verification successful" in proc.stdout


def test_cli_cmac_verify_failure_tampered_file(tmp_path):
    """Test CLI CMAC verification fails when file is tampered."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello CMAC")
    
    # Generate CMAC
    cmd_gen = [
        "python", "-m", "pycryptocore.cli", "dgst",
        "--algorithm", "sha256",
        "--cmac",
        "--key", "2b7e151628aed2a6abf7158809cf4f3c",
        "--input", str(test_file),
        "--output", str(tmp_path / "cmac.txt")
    ]
    subprocess.run(cmd_gen, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Tamper with the file
    test_file.write_text("Modified content")
    
    # Verify should fail
    cmd_verify = [
        "python", "-m", "pycryptocore.cli", "dgst",
        "--algorithm", "sha256",
        "--cmac",
        "--key", "2b7e151628aed2a6abf7158809cf4f3c",
        "--input", str(test_file),
        "--verify", str(tmp_path / "cmac.txt")
    ]
    proc = subprocess.run(cmd_verify, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.returncode != 0
    assert "CMAC verification failed" in proc.stderr or "CMAC verification failed" in proc.stdout


def test_cli_cmac_verify_failure_wrong_key(tmp_path):
    """Test CLI CMAC verification fails with wrong key."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("test message")
    
    # Generate CMAC with key1
    cmd_gen = [
        "python", "-m", "pycryptocore.cli", "dgst",
        "--algorithm", "sha256",
        "--cmac",
        "--key", "2b7e151628aed2a6abf7158809cf4f3c",
        "--input", str(test_file),
        "--output", str(tmp_path / "cmac.txt")
    ]
    subprocess.run(cmd_gen, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Verify with different key
    cmd_verify = [
        "python", "-m", "pycryptocore.cli", "dgst",
        "--algorithm", "sha256",
        "--cmac",
        "--key", "00000000000000000000000000000000",  # Different key
        "--input", str(test_file),
        "--verify", str(tmp_path / "cmac.txt")
    ]
    proc = subprocess.run(cmd_verify, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.returncode != 0
    assert "CMAC verification failed" in proc.stderr or "CMAC verification failed" in proc.stdout


def test_cli_cmac_output_to_file(tmp_path):
    """Test CLI CMAC output to file."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("test message")
    output_file = tmp_path / "cmac_output.txt"
    
    cmd = [
        "python", "-m", "pycryptocore.cli", "dgst",
        "--algorithm", "sha256",
        "--cmac",
        "--key", "2b7e151628aed2a6abf7158809cf4f3c",
        "--input", str(test_file),
        "--output", str(output_file)
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.returncode == 0
    assert output_file.exists()
    
    content = output_file.read_text()
    parts = content.strip().split()
    assert len(parts[0]) == 32  # CMAC hex string (32 chars for 128 bits)
    assert parts[-1].endswith("test.txt")

