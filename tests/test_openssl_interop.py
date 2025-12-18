"""
Тесты интероперабельности CryptoCore <-> OpenSSL для AES-128-ECB.

Покрывает задание по совместимости: шифрование одной стороной,
дешифрование другой и наоборот.
"""

import os
import shutil
import subprocess
import tempfile

import pytest


pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None,
    reason="OpenSSL not found in PATH; install `openssl` package to run these tests",
)


KEY_HEX = "000102030405060708090a0b0c0d0e0f"


def test_openssl_encrypt_cryptocore_decrypt():
    """OpenSSL шифрует, CryptoCore успешно расшифровывает (ECB)."""
    plaintext = b"Hello, CryptoCore/OpenSSL!"

    with tempfile.TemporaryDirectory() as d:
        plain_path = os.path.join(d, "plain.txt")
        cipher_path = os.path.join(d, "cipher.bin")
        decrypted_path = os.path.join(d, "decrypted.txt")

        with open(plain_path, "wb") as f:
            f.write(plaintext)

        # OpenSSL: encrypt (AES-128-ECB, PKCS#7 padding по умолчанию)
        cmd_enc = [
            "openssl",
            "enc",
            "-aes-128-ecb",
            "-K",
            KEY_HEX,
            "-in",
            plain_path,
            "-out",
            cipher_path,
        ]
        result = subprocess.run(cmd_enc, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert result.returncode == 0, result.stderr.decode("utf-8", "ignore")

        # CryptoCore: decrypt
        cmd_dec = [
            "python",
            "-m",
            "pycryptocore.cli",
            "--algorithm",
            "aes",
            "--mode",
            "ecb",
            "--decrypt",
            "--key",
            KEY_HEX,
            "--input",
            cipher_path,
            "--output",
            decrypted_path,
        ]
        result = subprocess.run(cmd_dec, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert result.returncode == 0, result.stderr

        with open(decrypted_path, "rb") as f:
            assert f.read() == plaintext


def test_cryptocore_encrypt_openssl_decrypt():
    """CryptoCore шифрует, OpenSSL успешно расшифровывает (ECB)."""
    plaintext = b"Hello, OpenSSL/CryptoCore!"

    with tempfile.TemporaryDirectory() as d:
        plain_path = os.path.join(d, "plain.txt")
        cipher_path = os.path.join(d, "cipher.bin")
        decrypted_path = os.path.join(d, "decrypted.txt")

        with open(plain_path, "wb") as f:
            f.write(plaintext)

        # CryptoCore: encrypt
        cmd_enc = [
            "python",
            "-m",
            "pycryptocore.cli",
            "--algorithm",
            "aes",
            "--mode",
            "ecb",
            "--encrypt",
            "--key",
            KEY_HEX,
            "--input",
            plain_path,
            "--output",
            cipher_path,
        ]
        result = subprocess.run(cmd_enc, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert result.returncode == 0, result.stderr

        # OpenSSL: decrypt
        cmd_dec = [
            "openssl",
            "enc",
            "-d",
            "-aes-128-ecb",
            "-K",
            KEY_HEX,
            "-in",
            cipher_path,
            "-out",
            decrypted_path,
        ]
        result = subprocess.run(cmd_dec, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert result.returncode == 0, result.stderr.decode("utf-8", "ignore")

        with open(decrypted_path, "rb") as f:
            assert f.read() == plaintext


