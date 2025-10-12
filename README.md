# CryptoCore
Минималистичный криптопровайдер: AES-128 в режимах ECB, CBC, CFB, OFB, CTR. CLI-утилита на C.

## Сборка и установка

### Требования
- GCC или совместимый компилятор C
- OpenSSL библиотека (libcrypto)
- Make

### Установка зависимостей

**Ubuntu/Debian:**
```bash
sudo apt-get install build-essential libssl-dev
```

**CentOS/RHEL:**
```bash
sudo yum install gcc openssl-devel make
```

**Windows (MSYS2):**
```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl make
```

### Сборка
```bash
make
```

### Установка (опционально)
```bash
sudo make install
```

## Примеры использования

### Шифрование по паролю (PBKDF2, соль и IV сохраняются в файл)
```bash
./cryptocore --algorithm aes --mode cbc --encrypt --password 1234 --input plain.txt --output cipher.bin
```

### Дешифрование по паролю (соль и IV берутся из файла)
```bash
./cryptocore --algorithm aes --mode cbc --decrypt --password 1234 --input cipher.bin --output decrypted.txt
```

### Шифрование по ключу (старый способ)
```bash
./cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plain.txt --output cipher.bin
```

### Дешифрование по ключу (IV берётся из файла или указывается явно)
```bash
./cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cipher.bin --output decrypted.txt
```

### Поддерживаемые режимы
- **ecb** (без IV) - Electronic Codebook
- **cbc** - Cipher Block Chaining
- **cfb** - Cipher Feedback
- **ofb** - Output Feedback
- **ctr** - Counter

## Формат файла при шифровании по паролю
- Первые 16 байт: соль (salt)
- Следующие 16 байт: IV
- Остальное: ciphertext

## OpenSSL interoperability

CryptoCore полностью совместим с OpenSSL для режима ECB:

```bash
# Шифрование с OpenSSL, дешифрование с CryptoCore
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -in plain.txt -out cipher.bin -nopad
./cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input cipher.bin --output decrypted.txt

# Шифрование с CryptoCore, дешифрование с OpenSSL
./cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plain.txt --output cipher.bin
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -in cipher.bin -out decrypted.txt -d -nopad
```

## Зависимости
- C99 компилятор (GCC, Clang)
- OpenSSL libcrypto
- Make

## Тесты

Для проверки корректности реализации режимов шифрования и дешифрования предусмотрены автотесты.

### Как запустить тесты
```bash
make test
```

Или вручную:
```bash
./test_runner.sh
```

### Что проверяют тесты
- Корректность шифрования и последующего дешифрования для всех поддерживаемых режимов (ECB, CBC, CFB, OFB, CTR)
- Данные после дешифрования совпадают с исходными
- Интероперабельность с OpenSSL для режима ECB
- Работа с ключами и паролями

## Структура проекта

```
project_root/
├── src/                    # Исходный код
│   ├── main.c             # Главный файл
│   ├── cli_parser.c      # Парсер командной строки
│   ├── file_io.c         # Файловый ввод/вывод
│   ├── crypto_utils.c    # Утилитарные функции
│   └── modes/            # Реализации режимов
│       ├── ecb.c
│       ├── cbc.c
│       ├── cfb.c
│       ├── ofb.c
│       └── ctr.c
├── include/               # Заголовочные файлы
│   ├── crypto.h
│   ├── cli_parser.h
│   ├── file_io.h
│   └── modes/
│       ├── ecb.h
│       ├── cbc.h
│       ├── cfb.h
│       ├── ofb.h
│       └── ctr.h
├── tests/                 # Тесты
├── Makefile              # Система сборки
├── test_runner.sh        # Скрипт тестирования
└── README.md
```

## Технические детали

- **Алгоритм**: AES-128
- **Режимы**: ECB, CBC, CFB, OFB, CTR
- **Padding**: PKCS#7
- **Key Derivation**: PBKDF2 с SHA-256 (100,000 итераций)
- **IV Generation**: Криптографически стойкий генератор случайных чисел OpenSSL
- **Совместимость**: Полная интероперабельность с OpenSSL для ECB режима