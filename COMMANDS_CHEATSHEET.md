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

```bash
pytest
```

---

### 2. AES: шифрование/дешифрование по ключу (CBC)

**Шифрование:**

```bash
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

```bash
python3 -m pycryptocore.cli --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad aabbccddeeff \
  --input sample.txt --output sample_encrypted.bin

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


