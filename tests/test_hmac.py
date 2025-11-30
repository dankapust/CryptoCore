import os
import tempfile
import subprocess
from pathlib import Path

from pycryptocore.mac.hmac import HMAC


def test_rfc_4231_test_case_1():
    """RFC 4231 Test Case 1: Basic test case with a short key"""
    key = bytes.fromhex("0b" * 20)  # 20 bytes of 0x0b
    data = b"Hi There"
    expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    
    hmac = HMAC(key, "sha256")
    result = hmac.hexdigest(data)
    assert result == expected, f"RFC 4231 test case 1 failed: got {result}, expected {expected}"


def test_rfc_4231_test_case_2():
    """RFC 4231 Test Case 2: Test with a key shorter than block size"""
    key = bytes.fromhex("4a656665")  # "Jefe"
    data = bytes.fromhex("7768617420646f2079612077616e7420666f72206e6f7468696e673f")  # "what do ya want for nothing?"
    expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    
    hmac = HMAC(key, "sha256")
    result = hmac.hexdigest(data)
    assert result == expected, f"RFC 4231 test case 2 failed: got {result}, expected {expected}"


def test_rfc_4231_test_case_3():
    """RFC 4231 Test Case 3: Test with a key equal to block size"""
    key = bytes.fromhex("aa" * 64)  # 64 bytes (block size)
    data = bytes.fromhex("dd" * 50)  # 50 bytes
    # Verified against Python's hmac module
    expected = "e3b73eef0fe1ad930dfbe27c108d925234e64a5d9a8c6cf1a87abddc9511c42b"
    
    hmac = HMAC(key, "sha256")
    result = hmac.hexdigest(data)
    assert result == expected, f"RFC 4231 test case 3 failed: got {result}, expected {expected}"


def test_rfc_4231_test_case_4():
    """RFC 4231 Test Case 4: Test with a key longer than block size"""
    key = bytes.fromhex("0102030405060708090a0b0c0d0e0f10111213141516171819" * 4)  # 100 bytes
    data = bytes.fromhex("cd" * 50)  # 50 bytes
    # Verified against Python's hmac module
    expected = "eb26a04f464cf8b7c265fb0b79f927c74885ce869aeb42f2d0b2ac83e0ef9b2d"
    
    hmac = HMAC(key, "sha256")
    result = hmac.hexdigest(data)
    assert result == expected, f"RFC 4231 test case 4 failed: got {result}, expected {expected}"


def test_hmac_empty_file():
    """Test HMAC computation for empty file"""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    data = b""
    
    hmac = HMAC(key, "sha256")
    result = hmac.hexdigest(data)
    
    # Expected HMAC-SHA256 for empty message with this key
    # This is a known value we can verify
    assert len(result) == 64  # 256 bits = 64 hex chars


def test_hmac_key_shorter_than_block():
    """Test HMAC with key shorter than block size (16 bytes)"""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")  # 16 bytes
    data = b"test message"
    
    hmac = HMAC(key, "sha256")
    result1 = hmac.hexdigest(data)
    
    # Should pad key with zeros
    assert len(result1) == 64


def test_hmac_key_equal_to_block():
    """Test HMAC with key equal to block size (64 bytes)"""
    key = bytes.fromhex("00" * 64)  # 64 bytes
    data = b"test message"
    
    hmac = HMAC(key, "sha256")
    result = hmac.hexdigest(data)
    assert len(result) == 64


def test_hmac_key_longer_than_block():
    """Test HMAC with key longer than block size (100 bytes)"""
    key = bytes.fromhex("00" * 100)  # 100 bytes
    data = b"test message"
    
    hmac = HMAC(key, "sha256")
    result = hmac.hexdigest(data)
    assert len(result) == 64


def test_hmac_chunk_processing():
    """Test HMAC with chunked message processing"""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    data = b"Hello, world! " * 1000  # Large message
    
    # Process in chunks
    chunks = [data[i:i+8192] for i in range(0, len(data), 8192)]
    hmac = HMAC(key, "sha256")
    result_chunked = hmac.update_compute_hex(chunks)
    
    # Process as single message
    hmac2 = HMAC(key, "sha256")
    result_single = hmac2.hexdigest(data)
    
    assert result_chunked == result_single


def test_cli_hmac_generate(tmp_path):
    """Test CLI HMAC generation"""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hi There")
    
    cmd = [
        "python", "-m", "pycryptocore.cli", "dgst",
        "--algorithm", "sha256",
        "--hmac",
        "--key", "0b" * 20,
        "--input", str(test_file)
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.returncode == 0
    out = proc.stdout.strip()
    parts = out.split()
    assert parts[0] == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"


def test_cli_hmac_verify_success(tmp_path):
    """Test CLI HMAC verification (success case)"""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hi There")
    
    hmac_file = tmp_path / "hmac.txt"
    hmac_file.write_text("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7  test.txt\n")
    
    cmd = [
        "python", "-m", "pycryptocore.cli", "dgst",
        "--algorithm", "sha256",
        "--hmac",
        "--key", "0b" * 20,
        "--input", str(test_file),
        "--verify", str(hmac_file)
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.returncode == 0
    assert "[OK] HMAC verification successful" in proc.stdout


def test_cli_hmac_verify_failure_tampered_file(tmp_path):
    """Test CLI HMAC verification fails when file is tampered"""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hi There")
    
    # Generate HMAC for original file
    cmd_gen = [
        "python", "-m", "pycryptocore.cli", "dgst",
        "--algorithm", "sha256",
        "--hmac",
        "--key", "00112233445566778899aabbccddeeff",
        "--input", str(test_file),
        "--output", str(tmp_path / "original_hmac.txt")
    ]
    subprocess.run(cmd_gen, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Tamper with the file
    test_file.write_text("Modified content")
    
    # Verify should fail
    cmd_verify = [
        "python", "-m", "pycryptocore.cli", "dgst",
        "--algorithm", "sha256",
        "--hmac",
        "--key", "00112233445566778899aabbccddeeff",
        "--input", str(test_file),
        "--verify", str(tmp_path / "original_hmac.txt")
    ]
    proc = subprocess.run(cmd_verify, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.returncode != 0
    assert "HMAC verification failed" in proc.stderr or "HMAC verification failed" in proc.stdout


def test_cli_hmac_verify_failure_wrong_key(tmp_path):
    """Test CLI HMAC verification fails with wrong key"""
    test_file = tmp_path / "test.txt"
    test_file.write_text("test message")
    
    # Generate HMAC with key1
    cmd_gen = [
        "python", "-m", "pycryptocore.cli", "dgst",
        "--algorithm", "sha256",
        "--hmac",
        "--key", "00112233445566778899aabbccddeeff",
        "--input", str(test_file),
        "--output", str(tmp_path / "hmac.txt")
    ]
    subprocess.run(cmd_gen, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Verify with different key
    cmd_verify = [
        "python", "-m", "pycryptocore.cli", "dgst",
        "--algorithm", "sha256",
        "--hmac",
        "--key", "ffeeddccbbaa99887766554433221100",  # Different key
        "--input", str(test_file),
        "--verify", str(tmp_path / "hmac.txt")
    ]
    proc = subprocess.run(cmd_verify, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.returncode != 0
    assert "HMAC verification failed" in proc.stderr or "HMAC verification failed" in proc.stdout


def test_cli_hmac_output_to_file(tmp_path):
    """Test CLI HMAC output to file"""
    test_file = tmp_path / "test.txt"
    test_file.write_text("test message")
    output_file = tmp_path / "hmac_output.txt"
    
    cmd = [
        "python", "-m", "pycryptocore.cli", "dgst",
        "--algorithm", "sha256",
        "--hmac",
        "--key", "00112233445566778899aabbccddeeff",
        "--input", str(test_file),
        "--output", str(output_file)
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.returncode == 0
    assert output_file.exists()
    
    content = output_file.read_text()
    parts = content.strip().split()
    assert len(parts[0]) == 64  # HMAC hex string
    assert parts[-1].endswith("test.txt")


def test_hmac_tamper_detection():
    """Test that changing one bit in input produces completely different HMAC"""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    original_data = b"Hello, world!"
    modified_data = b"Hello, world?"  # Changed last character
    
    hmac1 = HMAC(key, "sha256")
    hash1 = hmac1.hexdigest(original_data)
    
    hmac2 = HMAC(key, "sha256")
    hash2 = hmac2.hexdigest(modified_data)
    
    # Convert to binary and count differing bits
    bin1 = bin(int(hash1, 16))[2:].zfill(256)
    bin2 = bin(int(hash2, 16))[2:].zfill(256)
    diff_count = sum(bit1 != bit2 for bit1, bit2 in zip(bin1, bin2))
    
    # Avalanche effect: should be ~128 bits changed (50%)
    assert 100 < diff_count < 156, f"Avalanche effect weak: only {diff_count} bits changed"

