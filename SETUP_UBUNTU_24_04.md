## Полная установка CryptoCore на чистую Ubuntu 24.04

Ниже — минимальный, но полный сценарий, который можно запустить на «пустой» Ubuntu 24.04 (только система и Python). Предполагается, что проект уже скачан в `~/Загрузки/CryptoCore-main`.

---

### 1. Установить системные пакеты

```bash
sudo apt update
sudo apt install -y \
  python3 python3-venv python3-pip \
  git \
  openssl
```

- **python3, python3-venv, python3-pip** — сам Python, виртуальные окружения и `pip`.
- **git** — если нужно скачивать репозиторий с сервера.
- **openssl** — **обязательно** для тестов интероперабельности CryptoCore ↔ OpenSSL (файл `tests/test_openssl_interop.py`). Без OpenSSL эти тесты будут пропущены, но основная функциональность будет работать.

**Важно:** Если OpenSSL не установлен, при запуске `pytest` тесты `test_openssl_interop.py` будут пропущены с предупреждением. Для полной проверки всех спринтов OpenSSL должен быть установлен.

Проверьте версии:

```bash
python3 --version
pip3 --version
openssl version    # Должно показать версию (например, OpenSSL 3.0.x)
```

Если `openssl version` выдаёт ошибку "command not found", установите OpenSSL:

```bash
sudo apt install -y openssl
```

---

### 2. Перейти в папку проекта

Если проект уже распакован в `~/Загрузки`:

```bash
cd "$HOME/Загрузки/CryptoCore-main"
```

Если нужно клонировать из Git:

```bash
cd "$HOME/Загрузки"
git clone <URL_ВАШЕГО_РЕПОЗИТОРИЯ> CryptoCore-main
cd CryptoCore-main
```

---

### 3. Создать и активировать виртуальное окружение

Рекомендуется держать зависимости проекта изолированными:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

После активации в начале приглашения появится что‑то вроде `(.venv)` или `(venv)`.

---

### 4. Установить Python‑зависимости

Обновим `pip` и установим зависимости:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

Чтобы команда `cryptocore` была доступна глобально (внутри venv), установим пакет:

```bash
python3 -m pip install .
```

После этого можно будет вызывать:

```bash
cryptocore --help
```

---

### 5. Быстрая проверка проекта

В корне проекта:

```bash
# Скрипт, проверяющий все основные режимы AES
python3 run_tests.py
```

Либо:

```bash
bash run_tests_py.sh
```

В конце вы должны увидеть:

```text
[OK] Python tests passed
```

---

### 6. Запуск полного набора автотестов (pytest)

**⚠️ ВАЖНО:** Перед запуском `pytest` убедитесь, что установлены все зависимости из `requirements.txt`:

```bash
cd "$HOME/Загрузки/CryptoCore-main"
source .venv/bin/activate

# Проверка установки pycryptodome (обязательно!)
python3 -c "from Crypto.Cipher import AES; print('✓ pycryptodome установлен')"
```

Если команда выше выдаёт ошибку `ModuleNotFoundError: No module named 'Crypto'`, установите зависимости:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

Для проверки всех спринтов (AES‑режимы, CSPRNG, hash, HMAC/CMAC, PBKDF2/derive, GCM, CLI и интероперабельность с OpenSSL) выполните:

```bash
python3 -m pip install pytest
pytest
```

Все тесты должны завершиться без ошибок.  
Тесты включают:

- Шифрование/дешифрование AES‑128 во всех режимах (ECB, CBC, CFB, OFB, CTR, GCM).
- CSPRNG и генерацию ключей.
- SHA‑256 и SHA3‑256 (включая CLI‑команду `dgst`).
- HMAC‑SHA256 и AES‑CMAC (включая режимы `--hmac` / `--cmac` и `--verify`).
- PBKDF2‑KDF (`cryptocore derive`).
- GCM c AAD, проверкой аутентичности и «катастрофическим отказом».
- Совместимость AES‑ECB с OpenSSL (зашифровка одной стороной, расшифровка другой).

---

### 7. Примеры использования CLI

#### 7.1. Шифрование/дешифрование по ключу

Из папки проекта (или из любой, если пакет установлен через `pip install .`):

```bash
# Шифрование
python3 -m pycryptocore.cli --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plain.txt --output cipher.bin

# Дешифрование
python3 -m pycryptocore.cli --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input cipher.bin --output decrypted.txt
```

#### 7.2. Шифрование по паролю (PBKDF2)

```bash
python3 -m pycryptocore.cli --algorithm aes --mode cbc --encrypt \
  --password "MySecurePassword123!" \
  --input plain.txt --output cipher.bin

python3 -m pycryptocore.cli --algorithm aes --mode cbc --decrypt \
  --password "MySecurePassword123!" \
  --input cipher.bin --output decrypted.txt
```

#### 7.3. GCM с AAD

**Примечание:** Создайте тестовый файл `plaintext.txt` или используйте любой существующий файл.

```bash
# Создайте тестовый файл (опционально)
echo "Secret message" > plaintext.txt

# Создайте тестовый файл (опционально)
echo "Secret message" > plaintext.txt

python3 -m pycryptocore.cli --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad aabbccddeeff \
  --input plaintext.txt --output encrypted.bin

python3 -m pycryptocore.cli --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad aabbccddeeff \
  --input encrypted.bin --output decrypted.txt
```

#### 7.4. Вычисление хеша / HMAC / CMAC

```bash
# SHA-256
python3 -m pycryptocore.cli dgst --algorithm sha256 --input document.pdf

# HMAC-SHA256
python3 -m pycryptocore.cli dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input message.txt --output message.hmac

# AES-CMAC
python3 -m pycryptocore.cli dgst --algorithm sha256 --cmac \
  --key 2b7e151628aed2a6abf7158809cf4f3c \
  --input message.txt --output message.cmac
```

#### 7.5. PBKDF2‑KDF (derive)

```bash
python3 -m pycryptocore.cli derive \
  --password "MySecurePassword123!" \
  --iterations 100000 \
  --length 32
```

---

Этот файл можно использовать как «шпаргалку»: просто идти по шагам сверху вниз на любой новой Ubuntu 24.04 и получать полностью рабочий CryptoCore с тестами всех реализованных в спринтах задач (M1–M7).


