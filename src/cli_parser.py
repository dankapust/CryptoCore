import argparse
import sys
import binascii
import os
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from src.modes.ecb import aes_ecb_encrypt, aes_ecb_decrypt
from src.modes.cbc import aes_cbc_encrypt, aes_cbc_decrypt
from src.modes.cfb import aes_cfb_encrypt, aes_cfb_decrypt
from src.modes.ofb import aes_ofb_encrypt, aes_ofb_decrypt
from src.modes.ctr import aes_ctr_encrypt, aes_ctr_decrypt
from src.file_io import (
    read_file, write_file, write_file_with_iv, read_file_with_iv,
    write_file_with_salt_iv, read_file_with_salt_iv
)

ALLOWED_ALGORITHMS = ['aes']
ALLOWED_MODES = ['ecb', 'cbc', 'cfb', 'ofb', 'ctr']
BLOCK_SIZE = 16
SALT_SIZE = 16
PBKDF2_ITER = 100_000


def parse_args():
    parser = argparse.ArgumentParser(description='CryptoCore: Minimalist AES-128 CLI tool')
    parser.add_argument('--algorithm', required=True, choices=ALLOWED_ALGORITHMS)
    parser.add_argument('--mode', required=True, choices=ALLOWED_MODES)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--encrypt', action='store_true')
    group.add_argument('--decrypt', action='store_true')
    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument('--key', required=False, help='16-байтный ключ в hex (32 hex-символа)')
    key_group.add_argument('--password', required=False, help='Пароль для вывода ключа (PBKDF2)')
    parser.add_argument('--input', required=True, help='Путь к входному файлу')
    parser.add_argument('--output', required=False, help='Путь к выходному файлу')
    parser.add_argument('--iv', required=False, help='IV в hex (только для дешифрования)')
    return parser.parse_args()

def validate_key(key_hex: str) -> bytes:
    try:
        key = binascii.unhexlify(key_hex)
    except binascii.Error:
        print('[ERROR] Ключ должен быть hex-строкой!', file=sys.stderr)
        sys.exit(1)
    if len(key) != BLOCK_SIZE:
        print(f'[ERROR] Ключ должен быть 16 байт (32 hex-символа), а не {len(key)} байт!', file=sys.stderr)
        sys.exit(1)
    return key

def validate_iv(iv_hex: str) -> bytes:
    try:
        iv = binascii.unhexlify(iv_hex)
    except binascii.Error:
        print('[ERROR] IV должен быть hex-строкой!', file=sys.stderr)
        sys.exit(1)
    if len(iv) != BLOCK_SIZE:
        print(f'[ERROR] IV должен быть 16 байт (32 hex-символа), а не {len(iv)} байт!', file=sys.stderr)
        sys.exit(1)
    return iv

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=BLOCK_SIZE, count=PBKDF2_ITER, hmac_hash_module=SHA256)

def main():
    args = parse_args()
    mode = args.mode
    needs_iv = mode in ['cbc', 'cfb', 'ofb', 'ctr']
    use_password = args.password is not None
    # Определяем имя выходного файла
    if args.output:
        output_path = args.output
    else:
        if args.encrypt:
            output_path = args.input + '.enc'
        else:
            output_path = args.input + '.dec'
    # ENCRYPTION
    if args.encrypt:
        if use_password:
            salt = os.urandom(SALT_SIZE)
            key = derive_key_from_password(args.password, salt)
        else:
            salt = None
            key = validate_key(args.key)
        if needs_iv:
            if args.iv:
                print('[ERROR] IV не должен указываться при шифровании, он будет сгенерирован автоматически!', file=sys.stderr)
                sys.exit(1)
            iv = os.urandom(BLOCK_SIZE)
        else:
            iv = None
        input_data = read_file(args.input)
        if mode == 'ecb':
            result = aes_ecb_encrypt(key, input_data)
            write_file(output_path, result)
        elif mode == 'cbc':
            ciphertext = aes_cbc_encrypt(key, input_data, iv)
            if use_password:
                write_file_with_salt_iv(output_path, salt, iv, ciphertext)
            else:
                write_file_with_iv(output_path, iv, ciphertext)
        elif mode == 'cfb':
            ciphertext = aes_cfb_encrypt(key, input_data, iv)
            if use_password:
                write_file_with_salt_iv(output_path, salt, iv, ciphertext)
            else:
                write_file_with_iv(output_path, iv, ciphertext)
        elif mode == 'ofb':
            ciphertext = aes_ofb_encrypt(key, input_data, iv)
            if use_password:
                write_file_with_salt_iv(output_path, salt, iv, ciphertext)
            else:
                write_file_with_iv(output_path, iv, ciphertext)
        elif mode == 'ctr':
            ciphertext = aes_ctr_encrypt(key, input_data, iv)
            if use_password:
                write_file_with_salt_iv(output_path, salt, iv, ciphertext)
            else:
                write_file_with_iv(output_path, iv, ciphertext)
        print(f'[OK] Готово. Выходной файл: {output_path}')
    # DECRYPTION
    else:
        if use_password:
            if needs_iv:
                salt, iv, ciphertext = read_file_with_salt_iv(args.input)
                key = derive_key_from_password(args.password, salt)
            else:
                salt, ciphertext = read_file_with_salt_iv(args.input)[:2]
                key = derive_key_from_password(args.password, salt)
                iv = None
        else:
            key = validate_key(args.key)
            if needs_iv:
                if args.iv:
                    iv = validate_iv(args.iv)
                    ciphertext = read_file(args.input)
                else:
                    iv, ciphertext = read_file_with_iv(args.input)
            else:
                iv = None
                ciphertext = read_file(args.input)
        try:
            if mode == 'ecb':
                result = aes_ecb_decrypt(key, ciphertext)
            elif mode == 'cbc':
                result = aes_cbc_decrypt(key, ciphertext, iv)
            elif mode == 'cfb':
                result = aes_cfb_decrypt(key, ciphertext, iv)
            elif mode == 'ofb':
                result = aes_ofb_decrypt(key, ciphertext, iv)
            elif mode == 'ctr':
                result = aes_ctr_decrypt(key, ciphertext, iv)
        except Exception as e:
            print(f'[ERROR] Ошибка при криптографической операции: {e}', file=sys.stderr)
            sys.exit(1)
        write_file(output_path, result)
        print(f'[OK] Готово. Выходной файл: {output_path}')

if __name__ == '__main__':
    main()
