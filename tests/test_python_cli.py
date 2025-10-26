import os
import tempfile
import io
import sys

from pycryptocore.cli import main


def run_cli(args):
    return main(args)


def test_round_trip_all_modes():
    plaintext = b"Hello, CryptoCore! This is a test message for AES encryption."
    modes = ["ecb", "cbc", "cfb", "ofb", "ctr"]
    key_hex = "000102030405060708090a0b0c0d0e0f"

    with tempfile.TemporaryDirectory() as d:
        in_path = os.path.join(d, "plain.txt")
        with open(in_path, "wb") as f:
            f.write(plaintext)

        for mode in modes:
            out_enc = os.path.join(d, f"{mode}.enc")
            out_dec = os.path.join(d, f"{mode}.dec")

            # encrypt/decrypt with key
            assert run_cli(["--algorithm","aes","--mode",mode,"--encrypt","--key",key_hex,"--input",in_path,"--output",out_enc]) == 0
            assert run_cli(["--algorithm","aes","--mode",mode,"--decrypt","--key",key_hex,"--input",out_enc,"--output",out_dec]) == 0

            with open(out_dec, "rb") as f:
                assert f.read() == plaintext


def test_encrypt_without_key_generates_key_and_encrypts():
    plaintext = b"Hello, CryptoCore! Auto-key generation test."
    mode = "ctr"

    with tempfile.TemporaryDirectory() as d:
        in_path = os.path.join(d, "plain.txt")
        with open(in_path, "wb") as f:
            f.write(plaintext)

        out_enc = os.path.join(d, f"{mode}.enc")

        # Capture stdout to read the generated key line
        old_stdout = sys.stdout
        try:
            buf = io.StringIO()
            sys.stdout = buf
            rc = run_cli(["--algorithm","aes","--mode",mode,"--encrypt","--input",in_path,"--output",out_enc])
            assert rc == 0
            out = buf.getvalue()
        finally:
            sys.stdout = old_stdout

        # Expect info line with hex key
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        info_lines = [l for l in lines if l.startswith("[INFO] Generated random key:")]
        assert len(info_lines) == 1
        key_hex = info_lines[0].split(":", 1)[1].strip()
        assert len(key_hex) == 32  # 16 bytes hex

        # Now decrypt using the captured key
        out_dec = os.path.join(d, f"{mode}.dec")
        assert run_cli(["--algorithm","aes","--mode",mode,"--decrypt","--key",key_hex,"--input",out_enc,"--output",out_dec]) == 0
        with open(out_dec, "rb") as f:
            assert f.read() == plaintext


