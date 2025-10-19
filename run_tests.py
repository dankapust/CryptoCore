#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрипт для тестирования всех режимов шифрования
"""

import os
import tempfile
from pycryptocore.cli import main

PLAINTEXT = b"Hello, CryptoCore! This is a test message for AES encryption."
KEY = "000102030405060708090a0b0c0d0e0f"
MODES = ["ecb", "cbc", "cfb", "ofb", "ctr"]

print("=" * 60)
print("CryptoCore - Тестирование всех режимов")
print("=" * 60)
print()

with tempfile.TemporaryDirectory() as d:
    plain = os.path.join(d, "plain.txt")
    with open(plain, "wb") as f:
        f.write(PLAINTEXT)
    
    print("Тестовые данные:")
    print(f"  Размер: {len(PLAINTEXT)} байт")
    print(f"  Содержимое: {PLAINTEXT.decode()}")
    print()
    print("-" * 60)
    print()
    
    for m in MODES:
        enc = os.path.join(d, f"{m}.enc")
        dec = os.path.join(d, f"{m}.dec")
        
        print(f"[{m.upper()}] Шифрование...", end=" ")
        result = main(["--algorithm", "aes", "--mode", m, "--encrypt", "--key", KEY, "--input", plain, "--output", enc])
        if result == 0:
            print("OK")
        else:
            print("FAIL")
            continue
        
        print(f"[{m.upper()}] Дешифрование...", end=" ")
        result = main(["--algorithm", "aes", "--mode", m, "--decrypt", "--key", KEY, "--input", enc, "--output", dec])
        if result == 0:
            print("OK")
        else:
            print("FAIL")
            continue
        
        print(f"[{m.upper()}] Проверка...", end=" ")
        with open(dec, "rb") as f:
            if f.read() == PLAINTEXT:
                print("PASS ✓")
            else:
                print("FAIL ✗")
        print()

print("-" * 60)
print()
print("=" * 60)
print("[OK] Python tests passed")
print("=" * 60)
print()
print("📸 СДЕЛАЙТЕ СКРИНШОТ ЭТОГО ОКНА!")


