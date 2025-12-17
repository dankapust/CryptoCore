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
- gcm — аутентифицированное шифрование (AEAD); без padding; nonce 12 байт, tag 16 байт

## Примеры использования

### Шифрование по паролю (PBKDF2, соль и IV сохраняются в файл)
```bash
python -m pycryptocore.cli --algorithm aes --mode cbc --encrypt --password 1234 --input plain.txt --output cipher.bin
```

### Дешифрование по паролю (соль и IV берутся из файла)
```bash
python -m pycryptocore.cli --algorithm aes --mode cbc --decrypt --password 1234 --input cipher.bin --output decrypted.txt
```

### Шифрование по ключу
```bash
python -m pycryptocore.cli --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plain.txt --output cipher.bin
```

### Шифрование с автоматической генерацией ключа (Sprint 3)
Если ключ `--key` не указан и не используется пароль `--password`, при шифровании генерируется случайный 16-байтовый ключ (AES‑128) и выводится в stdout:
```bash
python -m pycryptocore.cli --algorithm aes --mode ctr --encrypt --input plaintext.txt --output ciphertext.bin
> [INFO] Generated random key: 1a2b3c4d5e6f7890fedcba9876543210
```
Затем выполните дешифрование, указав напечатанный ключ:
```bash
python -m pycryptocore.cli --algorithm aes --mode ctr --decrypt --key 1a2b3c4d5e6f7890fedcba9876543210 --input ciphertext.bin --output decrypted.txt
```

### Дешифрование по ключу (IV берётся из файла или указывается явно)
```bash
python -m pycryptocore.cli --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cipher.bin --output decrypted.txt
```

## Вычисление хеш-сумм (dgst)

Новый сабкоманд `dgst` для вычисления дайджестов:

```bash
# SHA-256
python -m pycryptocore.cli dgst --algorithm sha256 --input document.pdf

# SHA3-256
python -m pycryptocore.cli dgst --algorithm sha3-256 --input backup.tar --output backup.sha3
```

Формат вывода — совместим со стандартом *sum: `HASH  PATH`.
Алгоритмы:
- sha256 — реализован с нуля (FIPS 180-4), потоковая обработка, hex в нижнем регистре
- sha3-256 — через vetted библиотеку `hashlib` (FIPS 202), потоковая обработка

## GCM (Galois/Counter Mode) - Аутентифицированное шифрование

GCM — режим аутентифицированного шифрования (AEAD), который обеспечивает одновременно конфиденциальность и аутентичность данных.

### Основные возможности

- **Аутентифицированное шифрование**: Одновременное шифрование и проверка целостности
- **AAD (Associated Authenticated Data)**: Поддержка дополнительных аутентифицированных данных
- **Катастрофический отказ**: При неправильной аутентификации дешифрование полностью блокируется

### Шифрование с GCM

```bash
# Базовое шифрование
python -m pycryptocore.cli --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input sample.txt --output ciphertext.bin

# Шифрование с AAD
python -m pycryptocore.cli --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --aad aabbccddeeff --input sample.txt --output ciphertext.bin
```

**Параметры:**
- `--mode gcm` — включает режим GCM
- `--aad DATA` — (опционально) Associated Authenticated Data в hex-формате
- `--key KEY` — ключ AES-128 в hex-формате (16 байт)

### Дешифрование с GCM

```bash
# Дешифрование с правильным AAD
python -m pycryptocore.cli --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --aad aabbccddeeff --input ciphertext.bin --output decrypted.txt

# При успешной аутентификации: [OK] Done. Output file: decrypted.txt
# При неудаче: [ERROR] Authentication failed: AAD mismatch or ciphertext tampered (exit code 1)
```

**Важно:**
- AAD при дешифровании должен точно совпадать с AAD при шифровании
- При неправильной аутентификации выходной файл **не создается**
- Любое изменение ciphertext или tag приведет к отказу аутентификации

### Примеры использования

```bash
# Пример 1: Шифрование и дешифрование с AAD
python -m pycryptocore.cli --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --aad aabbccddeeff --input sample.txt --output sample_encrypted.bin
python -m pycryptocore.cli --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --aad aabbccddeeff --input sample_encrypted.bin --output sample_decrypted.txt

# Пример 2: Обнаружение подмены данных
python -m pycryptocore.cli --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input sample.txt --output sample_encrypted.bin
# ... файл изменен (например, через hex-редактор) ...
python -m pycryptocore.cli --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --input sample_encrypted.bin --output should_fail.txt
# Вывод: [ERROR] Authentication failed: AAD mismatch or ciphertext tampered
# Файл should_fail.txt не создан
```

### Реализация GCM

- **GCM реализован с нуля** по спецификации NIST SP 800-38D
- Использует AES в CTR режиме для шифрования
- Реализует GHASH с умножением в поле Галуа GF(2^128)
- Неприводимый многочлен: x^128 + x^7 + x^2 + x + 1
- Nonce: 12 байт (96 бит, рекомендуется)
- Tag: 16 байт (128 бит)

### Безопасность GCM

GCM обеспечивает:
- **Конфиденциальность**: Данные зашифрованы с помощью AES-CTR
- **Аутентичность**: Проверка целостности через GHASH и тег
- **Защиту от подмены**: Любое изменение данных или AAD обнаруживается
- **Катастрофический отказ**: При неудачной аутентификации никакие данные не выводятся

**Предупреждения:**
- ⚠️ **Никогда не используйте один и тот же nonce дважды** с одним ключом
- ⚠️ **AAD должен точно совпадать** при шифровании и дешифровании
- ⚠️ **При неудачной аутентификации не пытайтесь использовать частично расшифрованные данные**

## HMAC и CMAC (Message Authentication Code)

Команда `dgst` поддерживает вычисление HMAC и AES-CMAC для обеспечения целостности и аутентичности данных.

### HMAC (Hash-based Message Authentication Code)

HMAC использует хеш-функцию (SHA-256) для создания MAC.

### AES-CMAC (Cipher-based Message Authentication Code)

CMAC использует блочный шифр (AES-128) для создания MAC. Реализован по NIST SP 800-38B.

**Особенности:**
- Использует AES-128 (ключ 16 байт)
- MAC размером 16 байт (128 бит)
- Более эффективен для коротких сообщений по сравнению с HMAC
- Подходит для встроенных систем с ограниченными ресурсами

### Генерация HMAC

```bash
# Генерация HMAC-SHA256
python -m pycryptocore.cli dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt

# Сохранение HMAC в файл
python -m pycryptocore.cli dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --output message.hmac
```

**Параметры для HMAC:**
- `--hmac` — включает режим HMAC (обязателен для вычисления HMAC)
- `--key KEY` — ключ в hex-формате (обязателен при использовании `--hmac`). Ключ может быть произвольной длины
- `--algorithm sha256` — поддерживается только SHA-256 для HMAC
- `--input FILE` — входной файл
- `--output FILE` — (опционально) сохранить HMAC в файл вместо вывода в stdout

**Параметры для CMAC:**
- `--cmac` — включает режим AES-CMAC (обязателен для вычисления CMAC)
- `--key KEY` — ключ AES-128 в hex-формате (обязателен при использовании `--cmac`). Ключ должен быть 16 байт (32 hex символа)
- `--algorithm` — игнорируется для CMAC (используется AES)
- `--input FILE` — входной файл
- `--output FILE` — (опционально) сохранить CMAC в файл вместо вывода в stdout

**Формат вывода:** `MAC_VALUE  INPUT_FILE_PATH` (совместим со стандартным форматом)
- HMAC: 64 hex символа (256 бит)
- CMAC: 32 hex символа (128 бит)

### Генерация CMAC

```bash
# Генерация AES-CMAC
python -m pycryptocore.cli dgst --algorithm sha256 --cmac --key 2b7e151628aed2a6abf7158809cf4f3c --input message.txt

# Сохранение CMAC в файл
python -m pycryptocore.cli dgst --algorithm sha256 --cmac --key 2b7e151628aed2a6abf7158809cf4f3c --input message.txt --output message.cmac
```

### Проверка HMAC/CMAC

```bash
# Проверка HMAC с помощью --verify
python -m pycryptocore.cli dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --verify expected.hmac

# Проверка CMAC с помощью --verify
python -m pycryptocore.cli dgst --algorithm sha256 --cmac --key 2b7e151628aed2a6abf7158809cf4f3c --input message.txt --verify expected.cmac

# При успешной проверке выводится: [OK] HMAC/CMAC verification successful
# При неудаче: [ERROR] HMAC/CMAC verification failed (exit code 1)
```

**Параметры:**
- `--verify FILE` — файл с ожидаемым значением HMAC/CMAC (в формате `MAC_VALUE  FILENAME`)

### Примеры использования

```bash
# Пример 1: Генерация и проверка HMAC
python -m pycryptocore.cli dgst --algorithm sha256 --hmac --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b --input test.txt > test.hmac
python -m pycryptocore.cli dgst --algorithm sha256 --hmac --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b --input test.txt --verify test.hmac

# Пример 2: Генерация и проверка CMAC
python -m pycryptocore.cli dgst --algorithm sha256 --cmac --key 2b7e151628aed2a6abf7158809cf4f3c --input test.txt > test.cmac
python -m pycryptocore.cli dgst --algorithm sha256 --cmac --key 2b7e151628aed2a6abf7158809cf4f3c --input test.txt --verify test.cmac

# Пример 3: Обнаружение изменений в файле (HMAC)
python -m pycryptocore.cli dgst --algorithm sha256 --hmac --key mykey123 --input document.pdf --output doc.hmac
# ... файл изменен ...
python -m pycryptocore.cli dgst --algorithm sha256 --hmac --key mykey123 --input document.pdf --verify doc.hmac
# Вывод: [ERROR] HMAC verification failed

# Пример 4: Обнаружение изменений в файле (CMAC)
python -m pycryptocore.cli dgst --algorithm sha256 --cmac --key 2b7e151628aed2a6abf7158809cf4f3c --input document.pdf --output doc.cmac
# ... файл изменен ...
python -m pycryptocore.cli dgst --algorithm sha256 --cmac --key 2b7e151628aed2a6abf7158809cf4f3c --input document.pdf --verify doc.cmac
# Вывод: [ERROR] CMAC verification failed
```

## derive (KDF) — PBKDF2 и иерархия ключей

### Концепты
- **Key stretching**: удлиняет/усиливает пароль через многократные итерации (PBKDF2).
- **Salt**: случайные байты, защищают от радужных таблиц; минимум 16 байт, храните рядом с выводом.
- **Iteration count**: повышает стоимость подбора. Минимум 100k; для production рассматривайте 300k–600k+ (замерьте производительность).
- **Context separation**: `derive_key(master_key, context)` выдаёт разные ключи для разных целей (например, "encryption" / "authentication").

### Команда derive (PBKDF2-HMAC-SHA256)
```bash
# Базовое использование с заданной солью
python -m pycryptocore.cli derive --password "MySecurePassword123!" --salt a1b2c3d4e5f601234567890123456789 --iterations 100000 --length 32

# Автогенерация соли (16 байт)
python -m pycryptocore.cli derive --password "AnotherPassword" --iterations 500000 --length 16

# С чтением пароля из переменной среды
python -m pycryptocore.cli derive --password-env APP_PWD --length 32

# Запись ключа в файл (сырой бинарник)
python -m pycryptocore.cli derive --password "app_key" --salt 00112233445566778899aabbccddeeff --length 32 --output app_key.bin
```

**Аргументы:**
- `--password` | `--password-file` | `--password-env` — укажите ровно один источник пароля.
- `--salt HEX` — соль в hex; если опущено, генерируется 16 байт через CSPRNG.
- `--iterations` — по умолчанию 100000; допускает большие значения (≥1e6).
- `--length` — длина выводимого ключа (байты), по умолчанию 32.
- `--algorithm` — сейчас только `pbkdf2`.
- `--output FILE` — сохранить ключ в файл (raw bytes). В stdout всегда печатается `KEY_HEX  SALT_HEX`.

**Формат stdout:** `DERIVED_KEY_HEX  SALT_HEX` (через два пробела).

**Безопасность:**
- Не переиспользуйте одну пару `(password, salt)`; соль должна быть уникальной.
- Повышайте `--iterations` на продуктиве и фиксируйте значение в конфиге.
- Соль не секретна, но пароль должен очищаться после использования (CLI делает best-effort).

### Реализация HMAC

- **HMAC реализован с нуля** по спецификации RFC 2104
- Использует SHA-256 из Sprint 4 как базовую хеш-функцию
- Поддерживает ключи произвольной длины:
  - Ключи длиннее блока (64 байта для SHA-256) хешируются
  - Ключи короче блока дополняются нулями
- Потоковая обработка файлов (обработка по частям для экономии памяти)
- Формула: `HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))`
  - `H` — SHA-256
  - `opad` — 0x5c повторенный 64 раза
  - `ipad` — 0x36 повторенный 64 раза

### Реализация AES-CMAC

- **CMAC реализован с нуля** по спецификации NIST SP 800-38B
- Использует AES-128 как базовый блочный шифр
- Ключ должен быть 16 байт (AES-128)
- Генерирует подключи K1 и K2 для обработки последнего блока
- Потоковая обработка файлов (обработка по частям для экономии памяти)
- Алгоритм:
  - Полные блоки обрабатываются через CBC-MAC
  - Последний полный блок XOR с K1 перед финальным шифрованием
  - Неполный последний блок дополняется и XOR с K2 перед финальным шифрованием

### Безопасность HMAC и CMAC

HMAC и CMAC обеспечивают:
- **Целостность данных** — любое изменение файла приведет к другому MAC
- **Аутентичность** — только владелец правильного ключа может вычислить корректный MAC
- **Защиту от подмены** — злоумышленник не может создать валидный MAC без знания ключа

**Сравнение HMAC и CMAC:**
- **HMAC**: Использует хеш-функцию, ключ произвольной длины, MAC 256 бит (SHA-256)
- **CMAC**: Использует блочный шифр, ключ 16 байт, MAC 128 бит, более эффективен для коротких сообщений

### Работа с IV и Nonce
- При шифровании (режимы cbc/cfb/ofb/ctr) IV генерируется автоматически и записывается в начало файла
- При дешифровании: если `--iv` не указан, IV читается из первых 16 байт входного файла
- Для GCM режима: nonce (12 байт) генерируется автоматически и включается в выходной файл
- Формат GCM файла: nonce (12 байт) || ciphertext || tag (16 байт)

## Формат файла при шифровании по паролю
- Первые 16 байт: соль (salt)
- Следующие 16 байт: IV
- Остальное: ciphertext

## OpenSSL interoperability

Интероперабельность с OpenSSL для режима ECB и режимов с IV (при ручном указании IV):

```bash
# Шифрование с OpenSSL, дешифрование с CryptoCore (ECB)
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -in plain.txt -out cipher.bin
python -m pycryptocore.cli --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input cipher.bin --output decrypted.txt

# Шифрование с CryptoCore, дешифрование с OpenSSL (ECB)
python -m pycryptocore.cli --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plain.txt --output cipher.bin
openssl enc -aes-128-ecb -d -K 000102030405060708090a0b0c0d0e0f -in cipher.bin -out decrypted.txt
```

**Примечание:** Для интероперабельности с OpenSSL не используйте флаг `-nopad`, так как CryptoCore использует PKCS#7 padding.

## Быстрая проверка

Для быстрой проверки работоспособности проекта:

**Windows:**
```bash
ПРОВЕРКА.bat
```

**Linux/macOS или Python:**
```bash
python run_tests.py
```

Скрипт автоматически протестирует все 6 режимов шифрования и покажет результаты.

## Зависимости
- Python 3.8 или выше
- pycryptodome (устанавливается через requirements.txt)

## Тесты

Для проверки корректности реализации режимов шифрования и дешифрования предусмотрены автотесты.

### Как запустить тесты
```bash
# Windows
python run_tests.py

# Linux/macOS
bash run_tests_py.sh

# Или просто
python run_tests.py
```

### Что проверяют тесты
- Корректность шифрования и последующего дешифрования для всех поддерживаемых режимов (ECB, CBC, CFB, OFB, CTR, GCM)
- Данные после дешифрования совпадают с исходными
- Интероперабельность с OpenSSL для режима ECB
- Работа с ключами и паролями
- Хеш-функции (SHA-256, SHA3-256) с тестовыми векторами NIST
- HMAC с тестовыми векторами RFC 4231 и проверкой целостности данных
- AES-CMAC с тестовыми векторами NIST SP 800-38B и проверкой целостности данных
- GCM с проверкой аутентификации, обнаружением подмены данных и работы с AAD

## Структура проекта

```
project_root/
├── pycryptocore/          # Python модуль
│   ├── __init__.py
│   ├── cli.py            # CLI интерфейс
│   ├── crypto_core.py    # Криптографические функции
│   ├── file_io.py        # Файловый ввод/вывод
│   ├── kdf/              # Key Derivation Functions
│   │   ├── __init__.py
│   │   ├── pbkdf2.py     # PBKDF2-HMAC-SHA256 (с нуля)
│   │   └── hierarchy.py  # HMAC-based key hierarchy derivation
│   ├── csprng.py         # CSPRNG (os.urandom)
│   ├── hash/             # Хеш-функции
│   │   ├── __init__.py
│   │   ├── sha256.py
│   │   └── sha3_256.py
│   ├── mac/              # Message Authentication Code
│   │   ├── __init__.py
│   │   ├── hmac.py
│   │   └── cmac.py
│   └── modes/            # Authenticated Encryption Modes
│       ├── __init__.py
│       └── gcm.py
├── tests/                 # Тесты
│   ├── test_python_cli.py
│   ├── test_csprng.py
│   ├── test_hash.py
│   ├── test_hmac.py
│   └── test_gcm.py
├── pyproject.toml        # Конфигурация Python
├── requirements.txt      # Зависимости
├── build_py.bat          # Скрипт сборки (Windows)
├── run_tests_py.sh       # Скрипт тестирования (Linux/macOS)
├── run_tests.py          # Скрипт тестирования (Python)
├── ПРОВЕРКА.bat          # Скрипт быстрой проверки
├── test_data.txt         # Тестовые данные
└── README.md
```

## Технические детали

- **Алгоритм**: AES-128
- **Режимы**: ECB, CBC, CFB, OFB, CTR, GCM
- **Padding**: PKCS#7
- **Key Derivation**: PBKDF2 с SHA-256 (100,000 итераций)
- **IV Generation**: Криптографически стойкий генератор случайных чисел (OS CSPRNG через `os.urandom`)
- **CSPRNG**: Модуль `pycryptocore/csprng.py`, функция `generate_random_bytes(num_bytes)` использует `os.urandom()`.
  - Ключи и все IV генерируются через этот модуль.
  - При шифровании без `--key`/`--password` генерируется 16-байтовый ключ и печатается в stdout ровно один раз.
  - При вводе слабого ключа (все байты одинаковые, последовательные байты) печатается предупреждение в stderr.

## NIST Statistical Test Suite (STS)

Для статистической проверки качества CSPRNG:

1. Сгенерируйте бинарный файл с случайными данными (пример 10 МБ):
```bash
python -c "from pycryptocore.csprng import generate_random_bytes; open('nist_test_data.bin', 'wb').write(generate_random_bytes(10_000_000))"
```
2. Скачайте и соберите NIST STS (C-версию) с сайта NIST и запустите `assess`:
```bash
./assess 10000000
```
3. Следуйте интерактивным подсказкам, укажите файл `nist_test_data.bin`.
4. Критерии успеха: большинство тестов проходит (p-value ≥ 0.01). Небольшое количество провалов статистически допустимо.

- **Хеш-функции**: SHA-256 (реализован с нуля, FIPS 180-4), SHA3-256 (hashlib, FIPS 202)
- **HMAC**: Реализован с нуля по RFC 2104, использует SHA-256, поддерживает ключи произвольной длины
- **AES-CMAC**: Реализован с нуля по NIST SP 800-38B, использует AES-128, ключ 16 байт
- **GCM**: Реализован с нуля по NIST SP 800-38D, аутентифицированное шифрование с поддержкой AAD
- **Совместимость**: Полная интероперабельность с OpenSSL для ECB режима