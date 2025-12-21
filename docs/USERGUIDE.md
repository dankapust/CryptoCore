## CryptoCore — руководство пользователя

### 1. Установка

#### 1.1. Зависимости (Ubuntu 24.04)

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip openssl
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

#### 1.2. Установка проекта

```bash
cd "$HOME/Загрузки/CryptoCore-main"
python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 -m pip install .
```

После этого доступны:

- `python3 -m pycryptocore.cli ...`
- `cryptocore ...`

---

### 2. Обработка больших файлов

CryptoCore автоматически использует потоковую обработку для файлов больше 100 МБ:

- **Автоматическое определение**: система автоматически определяет размер файла и выбирает оптимальный метод обработки
- **Потоковая обработка**: файлы обрабатываются блоками по 64 КБ, что позволяет работать с файлами любого размера
- **Промежуточные файлы**: создаются временные файлы для отслеживания прогресса
- **Восстановление после сбоя**: при сбое временные файлы сохраняются, что позволяет продолжить обработку

**Пример работы с большим файлом:**
```bash
# Файл больше 100 МБ автоматически обработается потоково
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input large_file.iso --output large_file.enc
```

**Примечание:** GCM режим пока использует не-потоковую обработку (требуется полный доступ к данным для GHASH).

---

### 3. Типичные сценарии

#### 2.1. Шифрование файла по ключу (CBC)

```bash
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plain.txt --output cipher.bin
```

#### 2.2. Дешифрование файла по ключу

```bash
cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input cipher.bin --output decrypted.txt
```

#### 2.3. Шифрование по паролю (PBKDF2 + соль + IV в файле)

```bash
cryptocore --algorithm aes --mode cbc --encrypt \
  --password "MyPass" \
  --input plain.txt --output cipher.bin
```

При этом:

- в начале файла записывается 16‑байтовая соль;
- затем 16‑байтовый IV;
- затем ciphertext.

Дешифрование:

```bash
cryptocore --algorithm aes --mode cbc --decrypt \
  --password "MyPass" \
  --input cipher.bin --output decrypted.txt
```

#### 2.4. GCM с AAD

```bash
cryptocore --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad aabbccddeeff \
  --input data.txt --output data.gcm
```

Расшифровка (AAD должен совпадать):

```bash
cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad aabbccddeeff \
  --input data.gcm --output data.dec
```

При ошибке аутентификации:

- возвращается код завершения `1`;
- выводится `[ERROR] Authentication failed ...`;
- выходной файл не создаётся.

---

### 4. Хеши, HMAC и CMAC

#### 3.1. SHA‑256

```bash
cryptocore dgst --algorithm sha256 --input file.bin
```

Вывод в формате:

```text
<HEX_HASH>  <ПУТЬ_К_ФАЙЛУ>
```

#### 3.2. HMAC‑SHA256

```bash
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input message.txt --output message.hmac
```

Проверка:

```bash
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input message.txt --verify message.hmac
```

#### 3.3. AES‑CMAC

```bash
cryptocore dgst --algorithm sha256 --cmac \
  --key 2b7e151628aed2a6abf7158809cf4f3c \
  --input message.txt --output message.cmac
```

Проверка:

```bash
cryptocore dgst --algorithm sha256 --cmac \
  --key 2b7e151628aed2a6abf7158809cf4f3c \
  --input message.txt --verify message.cmac
```

---

### 5. KDF (PBKDF2‑HMAC‑SHA256)

#### 4.1. Генерация ключа из пароля

```bash
cryptocore derive \
  --password "MySecurePassword123!" \
  --iterations 200000 \
  --length 32
```

Стандартный вывод:

```text
DERIVED_KEY_HEX  SALT_HEX
```

#### 4.2. Запись ключа в файл

```bash
cryptocore derive \
  --password "app_key" \
  --salt 00112233445566778899aabbccddeeff \
  --length 32 \
  --output app_key.bin
```

---

### 6. Диагностика и тесты

**Быстрая проверка:**

```bash
python3 run_tests.py
```

**Полный набор pytest:**

**⚠️ ВАЖНО:** Перед запуском `pytest` убедитесь, что установлены все зависимости:

```bash
# Проверка установки pycryptodome
python3 -c "from Crypto.Cipher import AES; print('✓ pycryptodome установлен')"
```

Если команда выше выдаёт ошибку `ModuleNotFoundError: No module named 'Crypto'`, установите зависимости:

```bash
python3 -m pip install -r requirements.txt
python3 -m pip install pytest
```

Затем запустите тесты:

```bash
pytest
```

**Примечания:**
- Для проверки интероперабельности с OpenSSL должен быть установлен пакет `openssl` (см. раздел "Установка").
- Если `pycryptodome` не установлен, все тесты будут падать с ошибкой `ModuleNotFoundError: No module named 'Crypto'`.


