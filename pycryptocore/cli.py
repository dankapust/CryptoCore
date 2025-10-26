from __future__ import annotations

import argparse
import binascii
import sys
from pathlib import Path
from typing import Optional

from .crypto_core import aes_encrypt, aes_decrypt, KEY_SIZE
from .kdf import derive_key_from_password, generate_salt
from .file_io import (
    read_all_bytes,
    write_all_bytes,
    write_with_salt_iv,
    read_with_salt_iv,
    write_with_iv,
    read_with_iv,
)
from .csprng import generate_random_bytes, detect_weak_key


def _hex_to_bytes(hex_str: str, expected_len: Optional[int] = None) -> bytes:
    try:
        b = binascii.unhexlify(hex_str)
    except (binascii.Error, ValueError):
        raise SystemExit("Invalid hex string")
    if expected_len is not None and len(b) != expected_len:
        raise SystemExit(f"Invalid length: expected {expected_len} bytes")
    return b


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="CryptoCore (Python) - AES-128 modes")
    p.add_argument("--algorithm", required=True, choices=["aes"], help="Algorithm")
    p.add_argument("--mode", required=True, choices=["ecb", "cbc", "cfb", "ofb", "ctr"], help="Mode")

    op = p.add_mutually_exclusive_group(required=True)
    op.add_argument("--encrypt", action="store_true", help="Encrypt")
    op.add_argument("--decrypt", action="store_true", help="Decrypt")

    keygrp = p.add_mutually_exclusive_group(required=False)
    keygrp.add_argument("--key", help="Hex-encoded key (16 bytes)")
    keygrp.add_argument("--password", help="Password for PBKDF2")

    p.add_argument("--iv", help="Hex-encoded IV (16 bytes) [decrypt only, if needed]")
    p.add_argument("--input", required=True, help="Input file")
    p.add_argument("--output", help="Output file")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.algorithm != "aes":
        print("Invalid algorithm", file=sys.stderr)
        return 1

    in_bytes = read_all_bytes(args.input)

    try:
        if args.encrypt:
            if args.iv:
                print("--iv is not accepted during encryption; it will be ignored", file=sys.stderr)
            if args.password:
                # derive key + generate iv
                salt = generate_salt()
                key = derive_key_from_password(args.password, salt)
                ciphertext, iv = aes_encrypt(args.mode, key, in_bytes, None)
                if iv is not None:
                    write_with_salt_iv(args.output, salt, iv, ciphertext)
                else:
                    # ECB: salt + ciphertext (no iv)
                    out_path = args.output or (str(args.input) + ".enc")
                    write_all_bytes(out_path, salt + ciphertext)
            elif args.key:
                key = _hex_to_bytes(args.key, expected_len=KEY_SIZE)
                reason = detect_weak_key(key)
                if reason:
                    print(f"[WARN] Weak key detected: {reason}", file=sys.stderr)
                ciphertext, iv = aes_encrypt(args.mode, key, in_bytes, None)
                if iv is not None:
                    out_path = args.output or (str(args.input) + ".enc")
                    write_with_iv(out_path, iv, ciphertext)
                else:
                    out_path = args.output or (str(args.input) + ".enc")
                    write_all_bytes(out_path, ciphertext)
            else:
                # No key or password provided: generate random key
                key = generate_random_bytes(KEY_SIZE)
                print(f"[INFO] Generated random key: {key.hex()}")
                ciphertext, iv = aes_encrypt(args.mode, key, in_bytes, None)
                if iv is not None:
                    out_path = args.output or (str(args.input) + ".enc")
                    write_with_iv(out_path, iv, ciphertext)
                else:
                    out_path = args.output or (str(args.input) + ".enc")
                    write_all_bytes(out_path, ciphertext)
        else:  # decrypt
            if args.password:
                if args.mode == "ecb":
                    # ECB with password: file contains salt + ciphertext
                    data = read_all_bytes(args.input)
                    if len(data) < 16:
                        print("File too short", file=sys.stderr)
                        return 1
                    salt, ciphertext = data[:16], data[16:]
                    key = derive_key_from_password(args.password, salt)
                    plaintext = aes_decrypt(args.mode, key, ciphertext, None)
                else:
                    salt, iv, ciphertext = read_with_salt_iv(args.input)
                    key = derive_key_from_password(args.password, salt)
                    plaintext = aes_decrypt(args.mode, key, ciphertext, iv)
                out_path = args.output or (str(args.input) + ".dec")
                write_all_bytes(out_path, plaintext)
            else:
                if not args.key:
                    print("--key is required for decryption when --password is not provided", file=sys.stderr)
                    return 1
                key = _hex_to_bytes(args.key, expected_len=KEY_SIZE)
                reason = detect_weak_key(key)
                if reason:
                    print(f"[WARN] Weak key detected: {reason}", file=sys.stderr)
                if args.mode == "ecb":
                    plaintext = aes_decrypt(args.mode, key, in_bytes, None)
                else:
                    if args.iv:
                        iv = _hex_to_bytes(args.iv, expected_len=16)
                        plaintext = aes_decrypt(args.mode, key, in_bytes, iv)
                    else:
                        iv, ciphertext = read_with_iv(args.input)
                        plaintext = aes_decrypt(args.mode, key, ciphertext, iv)
                out_path = args.output or (str(args.input) + ".dec")
                write_all_bytes(out_path, plaintext)
    except SystemExit:
        raise
    except Exception as exc:  # keep errors similar to C version messages
        print(str(exc), file=sys.stderr)
        return 1

    final_output = args.output or ((str(args.input) + ".enc") if args.encrypt else (str(args.input) + ".dec"))
    print(f"[OK] Done. Output file: {final_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


