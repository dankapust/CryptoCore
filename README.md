# CryptoCore
Минималистичный криптопровайдер: AES-128 в режимах ECB, CBC, CFB, OFB, CTR. Python-CLI.

## Сборка и установка (Python)

### Быстрый старт (Windows)
```bat
build_py.bat
```

### Быстрый старт (Linux/macOS)
```bash
python -m pip install -r requirements.txt
bash run_tests_py.sh
```

### Запуск Python-CLI
```bash
python -m pycryptocore.cli --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input test_data.txt --output test.enc
python -m pycryptocore.cli --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input test.enc --output test_dec.txt
```

CLI-скрипт также доступен как команда `cryptocore` при установке из `pyproject.toml`.

## Поддерживаемые режимы и обработка IV

- ecb — без IV; используется PKCS#7 padding
- cbc — генерируется случайный IV; padding PKCS#7
- cfb — потоковый режим; без padding
- ofb — потоковый режим; без padding
- ctr — потоковый режим; без padding

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

### Работа с IV
- При шифровании (режимы cbc/cfb/ofb/ctr) IV генерируется автоматически и записывается в начало файла
- При дешифровании: если `--iv` не указан, IV читается из первых 16 байт входного файла

## Формат файла при шифровании по паролю
- Первые 16 байт: соль (salt)
- Следующие 16 байт: IV
- Остальное: ciphertext

## OpenSSL interoperability

Интероперабельность с OpenSSL для режима ECB и режимов с IV (при ручном указании IV):

```bash
# Шифрование с OpenSSL, дешифрование с CryptoCore (ECB)
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -in plain.txt -out cipher.bin -nopad
./cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input cipher.bin --output decrypted.txt

# Шифрование с CryptoCore, дешифрование с OpenSSL (ECB)
./cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plain.txt --output cipher.bin
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -in cipher.bin -out decrypted.txt -d -nopad

# Пример для CBC: дешифрование с OpenSSL (IV извлечь из начала файла)
dd if=cipher.bin of=iv.bin bs=16 count=1
dd if=cipher.bin of=ciphertext_only.bin bs=16 skip=1
openssl enc -aes-128-cbc -d -K 000102030405060708090a0b0c0d0e0f -iv $(xxd -p iv.bin | tr -d '\n') -in ciphertext_only.bin -out decrypted.txt
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