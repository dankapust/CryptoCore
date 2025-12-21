## CryptoCore — короткая шпаргалка по основным командам

---

### 0. Быстрый старт на чистой Ubuntu 24.04

**Системные пакеты:**

```bash
sudo apt update
sudo apt install -y \
  python3 python3-venv python3-pip \
  git \
  openssl
```

**Проверка установки OpenSSL:**

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

**Клонировать (или перейти в папку, если уже скачано):**

```bash
cd "$HOME/Загрузки"
git clone <URL_ВАШЕГО_РЕПОЗИТОРИЯ> CryptoCore-main    # если нужно
cd CryptoCore-main
```

**Создать и активировать виртуальное окружение:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Установить зависимости и сам пакет:**

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 -m pip install .
```

После этого все команды ниже будут работать.

---

Предполагается, что:
- вы находитесь в папке проекта: `~/Загрузки/CryptoCore-main`
- активировано виртуальное окружение: `source .venv/bin/activate`

---

### 1. Тесты

**Быстрые встроенные тесты проекта:**

```bash
python3 run_tests.py
```

**Полный набор pytest (все спринты + OpenSSL):**

**⚠️ ВАЖНО:** Перед запуском `pytest` убедитесь, что установлены все зависимости:

```bash
# Проверка установки pycryptodome
python3 -c "from Crypto.Cipher import AES; print('✓ pycryptodome установлен')"
```

Если команда выше выдаёт ошибку `ModuleNotFoundError: No module named 'Crypto'`, установите зависимости:

```bash
python3 -m pip install -r requirements.txt
```

Затем запустите тесты:

```bash
# Тесты БЕЗ покрытия (быстрее)
pytest --no-cov

# Тесты С покрытием (по умолчанию, настроено в pytest.ini)
pytest

# Тесты с покрытием и детальным отчетом (показывает непокрытые строки)
pytest --cov-report=term-missing

# Тесты с покрытием и HTML-отчетом (создается в htmlcov/index.html)
pytest --cov-report=html

# Тесты с покрытием, детальным отчетом И HTML-отчетом
pytest --cov-report=term-missing --cov-report=html

# Запуск конкретного тестового файла
pytest tests/test_crypto_core.py

# Запуск конкретного теста
pytest tests/test_crypto_core.py::test_aes_encrypt_ecb
```

---

### 2. AES: шифрование/дешифрование по ключу (CBC)

**Примечание:** В примерах `plain.txt` — это имя вашего входного файла. Создайте его или используйте любой существующий файл.

**Шифрование:**

```bash
# Создайте тестовый файл (опционально)
echo "Hello, CryptoCore!" > plain.txt

python3 -m pycryptocore.cli --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plain.txt --output cipher.bin
```

**Дешифрование:**

```bash
python3 -m pycryptocore.cli --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input cipher.bin --output decrypted.txt
```

---

### 3. AES: шифрование/дешифрование по паролю (CBC + PBKDF2)

```bash
python3 -m pycryptocore.cli --algorithm aes --mode cbc --encrypt \
  --password "MyPass" \
  --input plain.txt --output cipher.bin

python3 -m pycryptocore.cli --algorithm aes --mode cbc --decrypt \
  --password "MyPass" \
  --input cipher.bin --output decrypted.txt
```

---

### 4. AES‑GCM с AAD

**Примечание:** Создайте `plaintext.txt` или используйте любой существующий файл.

```bash
# Создайте тестовый файл (опционально)
echo "Secret message" > plaintext.txt

python3 -m pycryptocore.cli --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad aabbccddeeff \
  --input plaintext.txt --output encrypted.bin

python3 -m pycryptocore.cli --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad aabbccddeeff \
  --input sample_encrypted.bin --output sample_decrypted.txt
```

---

### 5. Хеши / HMAC / CMAC (`dgst`)

**SHA‑256:**

```bash
python3 -m pycryptocore.cli dgst --algorithm sha256 --input file.bin
```

**HMAC‑SHA256:**

```bash
python3 -m pycryptocore.cli dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input message.txt --output message.hmac
```

**AES‑CMAC:**

```bash
python3 -m pycryptocore.cli dgst --algorithm sha256 --cmac \
  --key 2b7e151628aed2a6abf7158809cf4f3c \
  --input message.txt --output message.cmac
```

---

### 6. PBKDF2‑ключ (`derive`)

```bash
python3 -m pycryptocore.cli derive \
  --password "MySecurePassword123!" \
  --iterations 100000 \
  --length 32
```


