from __future__ import annotations

import os

from pycryptocore.csprng import generate_random_bytes


def test_key_uniqueness():
    key_set = set()
    num_keys = 1000
    for _ in range(num_keys):
        key = generate_random_bytes(16)
        key_hex = key.hex()
        assert key_hex not in key_set, f"Duplicate key found: {key_hex}"
        key_set.add(key_hex)


def test_nist_preparation(tmp_path):
    total_size = 1_000_000  # 1 MB for CI; README suggests 10+ MB for manual run
    file_path = tmp_path / "nist_test_data.bin"
    bytes_written = 0
    with open(file_path, "wb") as f:
        while bytes_written < total_size:
            chunk_size = min(4096, total_size - bytes_written)
            random_chunk = generate_random_bytes(chunk_size)
            f.write(random_chunk)
            bytes_written += chunk_size
    assert os.path.getsize(file_path) == total_size


def test_basic_distribution():
    # Rough check: Hamming weight close to 50% for a reasonably large sample
    data = generate_random_bytes(100_000)  # 100 KB
    ones = sum(bin(byte).count("1") for byte in data)
    total_bits = len(data) * 8
    ratio = ones / total_bits
    # Accept 0.45 - 0.55 as a loose bound
    assert 0.45 <= ratio <= 0.55, f"Bit ratio out of range: {ratio}"


