## CryptoCore — руководство для разработчика

### 0. Установка зависимостей

#### Системные зависимости (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip openssl
```

**Проверка OpenSSL:**

```bash
openssl version
```

Если команда выдаёт ошибку "command not found", установите OpenSSL:

```bash
sudo apt install -y openssl
```

**Зачем нужен OpenSSL:**
- Для тестов интероперабельности (`tests/test_openssl_interop.py`) — проверка совместимости AES-ECB между CryptoCore и OpenSSL.
- Без OpenSSL эти тесты будут пропущены при запуске `pytest`, но основная функциональность CryptoCore работает без него.

#### Python-зависимости

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 -m pip install .
```

---

### 1. Структура проекта

```text
pycryptocore/         # Основная библиотека
  cli.py              # CLI: encrypt/decrypt, dgst, derive
  crypto_core.py      # Реализация AES-128 (ECB/CBC/CFB/OFB/CTR) + потоковые функции
  csprng.py           # CSPRNG и детектор слабых ключей
  file_io.py          # Чтение/запись файлов c IV/salt/nonce/tag + управление временными файлами
  hash/               # SHA-256 (с нуля) и SHA3-256 (hashlib)
  kdf/                # PBKDF2-HMAC-SHA256, иерархия ключей
  mac/                # HMAC-SHA256, AES-CMAC
  modes/gcm.py        # Режим AES-GCM (AEAD)

tests/                # Автотесты (pytest)
docs/                 # Документация (API, USERGUIDE, DEVELOPMENT)
run_tests.py          # Быстрый прогон всех режимов AES
SETUP_UBUNTU_24_04.md # Инструкция по развёртыванию
COMMANDS_CHEATSHEET.md# Краткая шпаргалка по командам
README.md             # Общий обзор
pyproject.toml        # Конфигурация пакета / зависимостей
```

---

### 2. Запуск тестов и линтеров

#### 2.1. Pytest

**⚠️ ВАЖНО:** Перед запуском `pytest` убедитесь, что установлены все зависимости:

```bash
source .venv/bin/activate

# Проверка установки pycryptodome
python3 -c "from Crypto.Cipher import AES; print('✓ pycryptodome установлен')"
```

Если команда выше выдаёт ошибку `ModuleNotFoundError: No module named 'Crypto'`, установите зависимости:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

Затем запустите тесты:

```bash
# Тесты БЕЗ покрытия (быстрее, для быстрой проверки)
pytest --no-cov

# Тесты С покрытием (по умолчанию, настроено в pytest.ini)
# Показывает процент покрытия и создает HTML-отчет в htmlcov/
pytest

# Тесты с покрытием и детальным отчетом (показывает непокрытые строки)
pytest --cov-report=term-missing

# Тесты с покрытием и HTML-отчетом (откройте htmlcov/index.html в браузере)
pytest --cov-report=html

# Тесты с покрытием, детальным отчетом И HTML-отчетом
pytest --cov-report=term-missing --cov-report=html

# Запуск конкретного тестового файла
pytest tests/test_crypto_core.py

# Запуск конкретного теста
pytest tests/test_crypto_core.py::test_aes_encrypt_ecb

# Запуск тестов с подробным выводом (-v) и остановкой на первой ошибке (-x)
pytest -v -x
```

**Покрытие кода:**

По умолчанию `pytest.ini` настроен на автоматический сбор покрытия. После запуска тестов вы увидите отчет в терминале с процентами покрытия для каждого модуля. HTML-отчет сохраняется в `htmlcov/index.html` и позволяет детально просмотреть, какие строки кода не покрыты тестами.

**Текущее покрытие:** ~85-90% (цель: >90%)

Тесты покрывают:

- AES‑128 во всех режимах (ECB/CBC/CFB/OFB/CTR/GCM);
- CSPRNG;
- SHA‑256 / SHA3‑256;
- HMAC / CMAC;
- PBKDF2‑KDF и `derive`;
- GCM (ядро + CLI, включая AAD и «катастрофический отказ»);
- интероперабельность с OpenSSL (требуется установленный `openssl` — см. раздел "Установка зависимостей");
- CLI‑оболочку (`test_python_cli.py`, `test_cli_derive.py`, `test_gcm.py`).

#### 2.2. Быстрые режимные тесты

```bash
python3 run_tests.py
```

Скрипт шифрует/дешифрует тестовое сообщение во всех классических режимах AES и проверяет совпадение plaintext.

---

### 3. Стиль кода и документация

- Модули содержат короткие модульные docstring’и, описывающие назначение файла.
- Публичные функции:
  - имеют ясные имена;
  - принимают/возвращают простые типы (`bytes`, `str`, `int`, `Optional[...]`);
  - документированы либо docstring’ами, либо в `docs/API.md`.
- Следуйте рекомендациям PEP 8:
  - отступ 4 пробела;
  - `snake_case` для функций/переменных;
  - `CamelCase` для классов.

При добавлении новой функциональности:

1. Добавьте/обновите описание в `docs/API.md` и, при необходимости, в `USERGUIDE.md`.
2. Покройте новую функциональность юнит‑тестами в `tests/`.
3. Убедитесь, что `pytest` проходит полностью.

---

### 4. Потоковая обработка больших файлов

**Архитектура:**
- Для файлов **меньше 100 МБ**: используется загрузка всего файла в память (быстрее для маленьких файлов)
- Для файлов **больше 100 МБ**: автоматически используется потоковая обработка блоками по 64 КБ

**Потоковые функции:**
- `*_encrypt_stream()` и `*_decrypt_stream()` в `crypto_core.py`
- Обработка данных блоками по `CHUNK_SIZE` (64 КБ)
- Промежуточные файлы для отслеживания прогресса
- Возможность продолжения после сбоя

**Добавление потоковой обработки для нового режима:**
1. Реализуйте `xxx_encrypt_stream()` и `xxx_decrypt_stream()` функции
2. Зарегистрируйте в `aes_encrypt_stream()` и `aes_decrypt_stream()`
3. Обрабатывайте данные блоками, сохраняя состояние между блоками (для режимов с цепочкой)
4. Используйте `temp_file` для отслеживания прогресса

**Пример:**
```python
def xxx_encrypt_stream(key: bytes, input_file: BinaryIO, output_file: BinaryIO, 
                       iv: Optional[bytes] = None, temp_file: Optional[Path] = None) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    buffer = bytearray()
    
    while True:
        chunk = input_file.read(CHUNK_SIZE)
        if not chunk:
            break
        buffer.extend(chunk)
        # Обработка блоков...
        output_file.write(encrypted)
        if temp_file:
            with open(temp_file, 'ab') as tf:
                tf.write(encrypted)
    
    return iv
```

### 5. Добавление новых алгоритмов / режимов

**AES‑режимы**  
Новые режимы шифрования стоит реализовывать по аналогии с существующими в `crypto_core.py`:

- добавьте функции `xxx_encrypt` / `xxx_decrypt`;
- добавьте потоковые функции `xxx_encrypt_stream` / `xxx_decrypt_stream` для больших файлов;
- зарегистрируйте режим в `aes_encrypt` / `aes_decrypt` и `aes_encrypt_stream` / `aes_decrypt_stream`;
- при необходимости используйте `file_io` для форматов файлов;
- добавьте тесты в `tests/` с известными векторами.

**Новые хеши / MAC / KDF**  
Размещайте код в соответствующих подпакетах:

- `hash/` — новые хеш‑функции;
- `mac/` — новые MAC‑схемы;
- `kdf/` — новые KDF.

Обязательно:

- добавить тесты с KAT (NIST, RFC и т.п.);
- при интеграции в CLI — обновить `README.md`, `USERGUIDE.md` и `docs/API.md`.

---

### 6. CLI: расширение и поддержка

Модуль `pycryptocore.cli` реализует:

- основной путь `--algorithm aes --mode ... --encrypt/--decrypt`;
- подкоманду `dgst` (hash/HMAC/CMAC);
- подкоманду `derive` (PBKDF2).

Для добавления новых подкоманд:

1. В начале функции `main()` добавьте разбор новой команды (по аналогии с `dgst`/`derive`).
2. Реализуйте логику с аккуратной обработкой ошибок (`SystemExit`, `CryptoCoreError`).
3. Добавьте CLI‑тесты в `tests/` (через `subprocess.run` или прямой вызов `main()`).

---

### 7. Интероперабельность с OpenSSL

Файл `tests/test_openssl_interop.py` покрывает:

- `openssl` шифрует, CryptoCore расшифровывает (ECB);
- CryptoCore шифрует, `openssl` расшифровывает.

При изменениях формата файлов или паддинга:

- обязательно обновите этот тест;
- убедитесь, что `pytest tests/test_openssl_interop.py` по‑прежнему проходит.


