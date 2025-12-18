from __future__ import annotations

import argparse
import binascii
import os
import sys
from pathlib import Path
from typing import Optional

from .crypto_core import aes_encrypt, aes_decrypt, KEY_SIZE, CryptoCoreError
from .hash import SHA256, SHA3_256
from .mac import HMAC, CMAC
from .kdf import (
    PBKDF2_ITERATIONS,
    SALT_SIZE,
    derive_key_from_password,
    generate_salt,
    pbkdf2_hmac_sha256,
)
from .file_io import (
    read_all_bytes,
    write_all_bytes,
    write_with_salt_iv,
    read_with_salt_iv,
    write_with_iv,
    read_with_iv,
    write_with_nonce_tag,
    read_with_nonce_tag,
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
    sub = p.add_subparsers(dest="command", required=False)

    # encrypt/decrypt subparser (default/main path for backward compat)
    p_main = sub.add_parser("", add_help=False) if False else p  # keep same top-level args for AES
    p_main.add_argument("--algorithm", required=True, choices=["aes"], help="Algorithm")
    p_main.add_argument("--mode", required=True, choices=["ecb", "cbc", "cfb", "ofb", "ctr", "gcm"], help="Mode")
    op = p_main.add_mutually_exclusive_group(required=True)
    op.add_argument("--encrypt", action="store_true", help="Encrypt")
    op.add_argument("--decrypt", action="store_true", help="Decrypt")
    keygrp = p_main.add_mutually_exclusive_group(required=False)
    keygrp.add_argument("--key", help="Hex-encoded key (16 bytes)")
    keygrp.add_argument("--password", help="Password for PBKDF2")
    p_main.add_argument("--iv", help="Hex-encoded IV/nonce (16 bytes for modes, 12 bytes for GCM) [decrypt only, if needed]")
    p_main.add_argument("--aad", help="Associated Authenticated Data (hex string, for GCM mode)")
    p_main.add_argument("--input", required=True, help="Input file")
    p_main.add_argument("--output", help="Output file")

    # dgst subcommand
    dg = sub.add_parser("dgst", help="Compute message digest (hash)")
    dg.add_argument("--algorithm", required=True, choices=["sha256", "sha3-256"], help="Digest algorithm")
    dg.add_argument("--input", required=True, help="Input file")
    dg.add_argument("--output", help="Write hash to file instead of stdout")
    dg.add_argument("--hmac", action="store_true", help="Enable HMAC mode")
    dg.add_argument("--cmac", action="store_true", help="Enable AES-CMAC mode")
    dg.add_argument("--key", help="Hex-encoded key for HMAC/CMAC (required when --hmac or --cmac is used)")
    dg.add_argument("--verify", help="Verify HMAC/CMAC against value in specified file")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    # Handle 'derive' subcommand (KDF)
    tokens = argv if argv is not None else sys.argv[1:]
    if tokens and tokens[0] == "derive":
        derive_parser = argparse.ArgumentParser(description="CryptoCore (Python) - derive (PBKDF2-HMAC-SHA256)")
        derive_parser.add_argument("--password", help="Password string (use quotes if needed)")
        derive_parser.add_argument("--password-file", help="Read password from file")
        derive_parser.add_argument("--password-env", help="Read password from environment variable")
        derive_parser.add_argument("--salt", help="Salt as hex string (if omitted, 16 random bytes are generated)")
        derive_parser.add_argument("--iterations", type=int, default=PBKDF2_ITERATIONS, help=f"Iteration count (default: {PBKDF2_ITERATIONS})")
        derive_parser.add_argument("--length", type=int, default=32, help="Derived key length in bytes (default: 32)")
        derive_parser.add_argument("--algorithm", choices=["pbkdf2"], default="pbkdf2", help="KDF algorithm (only pbkdf2 supported)")
        derive_parser.add_argument("--output", help="Write derived key as raw bytes to file")
        derive_args = derive_parser.parse_args(tokens[1:])

        # Resolve password source
        password_sources = [x for x in [derive_args.password, derive_args.password_file, derive_args.password_env] if x]
        if len(password_sources) != 1:
            print("Provide exactly one password source: --password or --password-file or --password-env", file=sys.stderr)
            return 1

        if derive_args.password_file:
            pwd_str = Path(derive_args.password_file).read_text(encoding="utf-8")
        elif derive_args.password_env:
            env_val = os.getenv(derive_args.password_env)
            if env_val is None:
                print(f"Environment variable not set: {derive_args.password_env}", file=sys.stderr)
                return 1
            pwd_str = env_val
        else:
            pwd_str = derive_args.password or ""

        if derive_args.iterations <= 0:
            print("iterations must be positive", file=sys.stderr)
            return 1
        if derive_args.length <= 0:
            print("length must be positive", file=sys.stderr)
            return 1

        if derive_args.salt:
            try:
                salt = _hex_to_bytes(derive_args.salt)
            except SystemExit:
                print("Invalid hex string for --salt", file=sys.stderr)
                return 1
        else:
            salt = generate_salt(SALT_SIZE)

        # Derive key
        derived_key = pbkdf2_hmac_sha256(pwd_str, salt, derive_args.iterations, derive_args.length)

        # Output raw key to file if requested
        if derive_args.output:
            Path(derive_args.output).write_bytes(derived_key)

        # Print hex encodings to stdout
        print(f"{derived_key.hex()}  {salt.hex()}")

        # Best-effort cleanup
        pwd_str = ""
        return 0

    # Handle 'dgst' subcommand explicitly to keep backward compatibility for AES flags
    if tokens and tokens[0] == "dgst":
        dgst_parser = argparse.ArgumentParser(description="CryptoCore (Python) - dgst (message digests)")
        dgst_parser.add_argument("--algorithm", required=True, choices=["sha256", "sha3-256"], help="Digest algorithm")
        dgst_parser.add_argument("--input", required=True, help="Input file")
        dgst_parser.add_argument("--output", help="Write hash to file instead of stdout")
        dgst_parser.add_argument("--hmac", action="store_true", help="Enable HMAC mode")
        dgst_parser.add_argument("--cmac", action="store_true", help="Enable AES-CMAC mode")
        dgst_parser.add_argument("--key", help="Hex-encoded key for HMAC/CMAC (required when --hmac or --cmac is used)")
        dgst_parser.add_argument("--verify", help="Verify HMAC/CMAC against value in specified file")
        dgst_args = dgst_parser.parse_args(tokens[1:])
        
        try:
            # Validate HMAC/CMAC requirements
            if dgst_args.hmac and dgst_args.cmac:
                print("--hmac and --cmac cannot be used together", file=sys.stderr)
                return 1
            
            if dgst_args.hmac:
                if not dgst_args.key:
                    print("--key is required when --hmac is specified", file=sys.stderr)
                    return 1
                if dgst_args.algorithm != "sha256":
                    print("HMAC currently only supports sha256 algorithm", file=sys.stderr)
                    return 1
            
            if dgst_args.cmac:
                if not dgst_args.key:
                    print("--key is required when --cmac is specified", file=sys.stderr)
                    return 1
                # CMAC doesn't use hash algorithm, but we keep it for consistency
                if dgst_args.algorithm not in ["sha256", "sha3-256"]:
                    print("CMAC algorithm parameter is ignored (uses AES)", file=sys.stderr)
            
            algo = dgst_args.algorithm
            in_path = Path(dgst_args.input)
            
            if dgst_args.cmac:
                # CMAC mode
                try:
                    key_bytes = _hex_to_bytes(dgst_args.key, expected_len=KEY_SIZE)  # CMAC requires 16-byte key
                except SystemExit:
                    print("Invalid hex string for --key", file=sys.stderr)
                    return 1
                
                cmac = CMAC(key_bytes)
                
                # Process file in chunks for memory efficiency
                chunks = []
                with in_path.open("rb") as data_iter:
                    while True:
                        chunk = data_iter.read(8192)
                        if not chunk:
                            break
                        chunks.append(chunk)
                
                cmac_hex = cmac.update_compute_hex(chunks)
                line = f"{cmac_hex}  {str(in_path)}"
                
                # Handle verification
                if dgst_args.verify:
                    verify_path = Path(dgst_args.verify)
                    if not verify_path.exists():
                        print(f"Verification file not found: {verify_path}", file=sys.stderr)
                        return 1
                    
                    verify_content = verify_path.read_text(encoding="utf-8").strip()
                    # Parse expected CMAC (flexible: extract hex value, ignore filename/whitespace)
                    verify_parts = verify_content.split()
                    expected_cmac = None
                    for part in verify_parts:
                        if len(part) == 32 and all(c in "0123456789abcdef" for c in part.lower()):  # CMAC is 128 bits = 32 hex chars
                            expected_cmac = part.lower()
                            break
                    
                    if expected_cmac is None:
                        print("Could not parse CMAC value from verification file", file=sys.stderr)
                        return 1
                    
                    if cmac_hex.lower() == expected_cmac.lower():
                        print("[OK] CMAC verification successful")
                        return 0
                    else:
                        print("[ERROR] CMAC verification failed", file=sys.stderr)
                        return 1
                
                # Output CMAC
                if dgst_args.output:
                    Path(dgst_args.output).write_text(line + "\n", encoding="utf-8")
                else:
                    print(line)
                return 0
            elif dgst_args.hmac:
                # HMAC mode
                try:
                    key_bytes = _hex_to_bytes(dgst_args.key, expected_len=None)  # HMAC supports arbitrary key length
                except SystemExit:
                    print("Invalid hex string for --key", file=sys.stderr)
                    return 1
                
                hmac = HMAC(key_bytes, "sha256")
                
                # Process file in chunks for memory efficiency
                chunks = []
                with in_path.open("rb") as data_iter:
                    while True:
                        chunk = data_iter.read(8192)
                        if not chunk:
                            break
                        chunks.append(chunk)
                
                hmac_hex = hmac.update_compute_hex(chunks)
                line = f"{hmac_hex}  {str(in_path)}"
                
                # Handle verification
                if dgst_args.verify:
                    verify_path = Path(dgst_args.verify)
                    if not verify_path.exists():
                        print(f"Verification file not found: {verify_path}", file=sys.stderr)
                        return 1
                    
                    verify_content = verify_path.read_text(encoding="utf-8").strip()
                    # Parse expected HMAC (flexible: extract hex value, ignore filename/whitespace)
                    verify_parts = verify_content.split()
                    expected_hmac = None
                    for part in verify_parts:
                        if len(part) == 64 and all(c in "0123456789abcdef" for c in part.lower()):
                            expected_hmac = part.lower()
                            break
                    
                    if expected_hmac is None:
                        print("Could not parse HMAC value from verification file", file=sys.stderr)
                        return 1
                    
                    if hmac_hex.lower() == expected_hmac.lower():
                        print("[OK] HMAC verification successful")
                        return 0
                    else:
                        print("[ERROR] HMAC verification failed", file=sys.stderr)
                        return 1
                
                # Output HMAC
                if dgst_args.output:
                    Path(dgst_args.output).write_text(line + "\n", encoding="utf-8")
                else:
                    print(line)
                return 0
            else:
                # Regular hash mode
                with in_path.open("rb") as data_iter:
                    if algo == "sha256":
                        hasher = SHA256()
                        while True:
                            chunk = data_iter.read(8192)
                            if not chunk:
                                break
                            hasher.update(chunk)
                        digest_hex = hasher.hexdigest()
                    elif algo == "sha3-256":
                        hasher = SHA3_256()
                        while True:
                            chunk = data_iter.read(8192)
                            if not chunk:
                                break
                            hasher.update(chunk)
                        digest_hex = hasher.hexdigest()
                    else:
                        print("Unsupported digest algorithm", file=sys.stderr)
                        return 1
                line = f"{digest_hex}  {str(in_path)}"
                if dgst_args.output:
                    Path(dgst_args.output).write_text(line + "\n", encoding="utf-8")
                else:
                    print(line)
                return 0
        except FileNotFoundError:
            print("Input file not found", file=sys.stderr)
            return 1
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            return 1

    parser = build_parser()
    args = parser.parse_args(tokens)

    if args.algorithm != "aes":
        print("Invalid algorithm", file=sys.stderr)
        return 1

    in_bytes = read_all_bytes(args.input)
    
    # Parse AAD if provided
    aad_bytes = None
    if args.aad:
        try:
            aad_bytes = _hex_to_bytes(args.aad, expected_len=None)
        except SystemExit:
            print("Invalid hex string for --aad", file=sys.stderr)
            return 1

    try:
        if args.encrypt:
            if args.iv and args.mode != "gcm":
                print("--iv is not accepted during encryption; it will be ignored", file=sys.stderr)
            if args.password:
                # derive key + generate iv
                salt = generate_salt()
                key = derive_key_from_password(args.password, salt)
                ciphertext, iv = aes_encrypt(args.mode, key, in_bytes, None, aad_bytes)
                if args.mode == "gcm":
                    # GCM: nonce is included in ciphertext, format is nonce || ciphertext || tag
                    out_path = args.output or (str(args.input) + ".enc")
                    write_all_bytes(out_path, ciphertext)
                elif iv is not None:
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
                ciphertext, iv = aes_encrypt(args.mode, key, in_bytes, None, aad_bytes)
                if args.mode == "gcm":
                    # GCM: nonce is included in ciphertext
                    out_path = args.output or (str(args.input) + ".enc")
                    write_all_bytes(out_path, ciphertext)
                elif iv is not None:
                    out_path = args.output or (str(args.input) + ".enc")
                    write_with_iv(out_path, iv, ciphertext)
                else:
                    out_path = args.output or (str(args.input) + ".enc")
                    write_all_bytes(out_path, ciphertext)
            else:
                # No key or password provided: generate random key
                key = generate_random_bytes(KEY_SIZE)
                print(f"[INFO] Generated random key: {key.hex()}")
                ciphertext, iv = aes_encrypt(args.mode, key, in_bytes, None, aad_bytes)
                if args.mode == "gcm":
                    # GCM: nonce is included in ciphertext
                    out_path = args.output or (str(args.input) + ".enc")
                    write_all_bytes(out_path, ciphertext)
                elif iv is not None:
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
                    if args.mode == "gcm":
                        # GCM: nonce is included in ciphertext
                        data = read_all_bytes(args.input)
                        key = derive_key_from_password(args.password, data[:16])  # First 16 bytes are salt
                        # For GCM with password, we need to handle salt separately
                        # This is a simplified version - in practice, GCM with password needs special handling
                        salt = data[:16]
                        gcm_data = data[16:]
                        # For now, we'll treat it as if salt is prepended
                        # In a full implementation, you'd derive key and then use GCM
                        raise CryptoCoreError("GCM with password not fully implemented in this version")
                    else:
                        salt, iv, ciphertext = read_with_salt_iv(args.input)
                        key = derive_key_from_password(args.password, salt)
                        plaintext = aes_decrypt(args.mode, key, ciphertext, iv, aad_bytes)
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
                    plaintext = aes_decrypt(args.mode, key, in_bytes, None, aad_bytes)
                elif args.mode == "gcm":
                    # GCM: format is nonce (12 bytes) || ciphertext || tag (16 bytes)
                    if args.iv:
                        # Nonce provided separately via --iv, so in_bytes is ciphertext || tag
                        nonce = _hex_to_bytes(args.iv, expected_len=12)
                        plaintext = aes_decrypt(args.mode, key, in_bytes, nonce, aad_bytes)
                    else:
                        # Nonce is included in file (first 12 bytes)
                        plaintext = aes_decrypt(args.mode, key, in_bytes, None, aad_bytes)
                    out_path = args.output or (str(args.input) + ".dec")
                    write_all_bytes(out_path, plaintext)
                else:
                    if args.iv:
                        iv = _hex_to_bytes(args.iv, expected_len=16)
                        plaintext = aes_decrypt(args.mode, key, in_bytes, iv, aad_bytes)
                    else:
                        iv, ciphertext = read_with_iv(args.input)
                        plaintext = aes_decrypt(args.mode, key, ciphertext, iv, aad_bytes)
                    out_path = args.output or (str(args.input) + ".dec")
                    write_all_bytes(out_path, plaintext)
    except SystemExit:
        raise
    except CryptoCoreError as exc:
        error_msg = str(exc)
        if "Authentication failed" in error_msg or "authentication" in error_msg.lower():
            print(f"[ERROR] {error_msg}", file=sys.stderr)
            # Delete output file if it was created
            if args.output and Path(args.output).exists():
                try:
                    Path(args.output).unlink()
                except:
                    pass
        else:
            print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:  # keep errors similar to C version messages
        print(str(exc), file=sys.stderr)
        return 1

    final_output = args.output or ((str(args.input) + ".enc") if args.encrypt else (str(args.input) + ".dec"))
    print(f"[OK] Done. Output file: {final_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


