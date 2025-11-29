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

Скрипт автоматически протестирует все 5 режимов шифрования и покажет результаты.

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
- Корректность шифрования и последующего дешифрования для всех поддерживаемых режимов (ECB, CBC, CFB, OFB, CTR)
- Данные после дешифрования совпадают с исходными
- Интероперабельность с OpenSSL для режима ECB
- Работа с ключами и паролями

## Структура проекта

```
project_root/
├── pycryptocore/          # Python модуль
│   ├── __init__.py
│   ├── cli.py            # CLI интерфейс
│   ├── crypto_core.py    # Криптографические функции
│   ├── file_io.py        # Файловый ввод/вывод
│   └── kdf.py            # Key Derivation Function (PBKDF2)
├── tests/                 # Тесты
│   └── test_python_cli.py
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
- **Режимы**: ECB, CBC, CFB, OFB, CTR
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

- **Совместимость**: Полная интероперабельность с OpenSSL для ECB режима