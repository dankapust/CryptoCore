#!/usr/bin/env bash
set -euo pipefail

python - <<'PY'
import os, tempfile
from pycryptocore.cli import main

PLAINTEXT = b"Hello, CryptoCore! This is a test message for AES encryption."
KEY = "000102030405060708090a0b0c0d0e0f"
MODES = ["ecb","cbc","cfb","ofb","ctr"]

with tempfile.TemporaryDirectory() as d:
    plain = os.path.join(d, "plain.txt")
    with open(plain, "wb") as f:
        f.write(PLAINTEXT)

    for m in MODES:
        enc = os.path.join(d, f"{m}.enc")
        dec = os.path.join(d, f"{m}.dec")
        assert main(["--algorithm","aes","--mode",m,"--encrypt","--key",KEY,"--input",plain,"--output",enc]) == 0
        assert main(["--algorithm","aes","--mode",m,"--decrypt","--key",KEY,"--input",enc,"--output",dec]) == 0
        with open(dec,"rb") as f:
            assert f.read() == PLAINTEXT
print("[OK] Python tests passed")
PY


