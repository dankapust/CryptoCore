import sys
import os

BLOCK_SIZE = 16
SALT_SIZE = 16

# Обычное чтение файла

def read_file(path: str) -> bytes:
    try:
        with open(path, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"[ERROR] Не удалось прочитать файл {path}: {e}", file=sys.stderr)
        sys.exit(1)

def write_file(path: str, data: bytes):
    try:
        with open(path, 'wb') as f:
            f.write(data)
    except Exception as e:
        print(f"[ERROR] Не удалось записать файл {path}: {e}", file=sys.stderr)
        sys.exit(1)

# Для режима с IV (без соли)
def write_file_with_iv(path: str, iv: bytes, data: bytes):
    try:
        with open(path, 'wb') as f:
            f.write(iv)
            f.write(data)
    except Exception as e:
        print(f"[ERROR] Не удалось записать файл {path}: {e}", file=sys.stderr)
        sys.exit(1)

def read_file_with_iv(path: str):
    try:
        with open(path, 'rb') as f:
            iv = f.read(BLOCK_SIZE)
            if len(iv) < BLOCK_SIZE:
                print(f"[ERROR] Входной файл слишком короткий для IV (меньше 16 байт)", file=sys.stderr)
                sys.exit(1)
            data = f.read()
            return iv, data
    except Exception as e:
        print(f"[ERROR] Не удалось прочитать файл {path}: {e}", file=sys.stderr)
        sys.exit(1)

# Для режима с солью и IV (пароль)
def write_file_with_salt_iv(path: str, salt: bytes, iv: bytes, data: bytes):
    try:
        with open(path, 'wb') as f:
            f.write(salt)
            f.write(iv)
            f.write(data)
    except Exception as e:
        print(f"[ERROR] Не удалось записать файл {path}: {e}", file=sys.stderr)
        sys.exit(1)

def read_file_with_salt_iv(path: str):
    try:
        with open(path, 'rb') as f:
            salt = f.read(SALT_SIZE)
            if len(salt) < SALT_SIZE:
                print(f"[ERROR] Входной файл слишком короткий для соли (меньше 16 байт)", file=sys.stderr)
                sys.exit(1)
            iv = f.read(BLOCK_SIZE)
            if len(iv) < BLOCK_SIZE:
                print(f"[ERROR] Входной файл слишком короткий для IV (меньше 16 байт после соли)", file=sys.stderr)
                sys.exit(1)
            data = f.read()
            return salt, iv, data
    except Exception as e:
        print(f"[ERROR] Не удалось прочитать файл {path}: {e}", file=sys.stderr)
        sys.exit(1)
