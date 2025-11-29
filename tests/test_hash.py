import os
import io
import tempfile
import subprocess

from pycryptocore.hash.sha256 import SHA256


def test_sha256_known_vectors():
    vectors = {
        b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq": "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    }
    for msg, expected in vectors.items():
        sha = SHA256()
        sha.update(msg)
        assert sha.hexdigest() == expected


def test_sha256_empty_file(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    sha = SHA256()
    with open(p, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            sha.update(chunk)
    assert sha.hexdigest() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_sha256_avalanche():
    original = b"Hello, world!"
    modified = b"Hello, world?"
    s1 = SHA256(); s1.update(original)
    h1 = s1.hexdigest()
    s2 = SHA256(); s2.update(modified)
    h2 = s2.hexdigest()
    b1 = bin(int(h1, 16))[2:].zfill(256)
    b2 = bin(int(h2, 16))[2:].zfill(256)
    diff = sum(x != y for x, y in zip(b1, b2))
    assert 100 < diff < 156


def test_cli_dgst_sha256(tmp_path):
    data = b"abc"
    f = tmp_path / "abc.txt"
    f.write_bytes(data)
    cmd = ["python", "-m", "pycryptocore.cli", "dgst", "--algorithm", "sha256", "--input", str(f)]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.returncode == 0
    out = proc.stdout.strip()
    # format: <hash>  <path>
    parts = out.split()
    assert parts[0] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert parts[-1].endswith("abc.txt")
