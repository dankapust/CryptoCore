import os
import tempfile

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


