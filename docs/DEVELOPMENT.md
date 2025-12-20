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
  crypto_core.py      # Реализация AES-128 (ECB/CBC/CFB/OFB/CTR)
  csprng.py           # CSPRNG и детектор слабых ключей
  file_io.py          # Чтение/запись файлов c IV/salt/nonce/tag
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
python3 -m pip install pytest
```

Затем запустите тесты:

```bash
pytest
```

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

### 4. Добавление новых алгоритмов / режимов

**AES‑режимы**  
Новые режимы шифрования стоит реализовывать по аналогии с существующими в `crypto_core.py`:

- добавьте функции `xxx_encrypt` / `xxx_decrypt`;
- зарегистрируйте режим в `aes_encrypt` / `aes_decrypt`;
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

### 5. CLI: расширение и поддержка

Модуль `pycryptocore.cli` реализует:

- основной путь `--algorithm aes --mode ... --encrypt/--decrypt`;
- подкоманду `dgst` (hash/HMAC/CMAC);
- подкоманду `derive` (PBKDF2).

Для добавления новых подкоманд:

1. В начале функции `main()` добавьте разбор новой команды (по аналогии с `dgst`/`derive`).
2. Реализуйте логику с аккуратной обработкой ошибок (`SystemExit`, `CryptoCoreError`).
3. Добавьте CLI‑тесты в `tests/` (через `subprocess.run` или прямой вызов `main()`).

---

### 6. Интероперабельность с OpenSSL

Файл `tests/test_openssl_interop.py` покрывает:

- `openssl` шифрует, CryptoCore расшифровывает (ECB);
- CryptoCore шифрует, `openssl` расшифровывает.

При изменениях формата файлов или паддинга:

- обязательно обновите этот тест;
- убедитесь, что `pytest tests/test_openssl_interop.py` по‑прежнему проходит.


