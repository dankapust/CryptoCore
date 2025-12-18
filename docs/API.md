## CryptoCore API

Этот документ описывает основное программное API библиотеки `pycryptocore`.

Библиотека разделена на несколько модулей:

- `pycryptocore.crypto_core` — низкоуровневые примитивы AES‑128 (ECB/CBC/CFB/OFB/CTR).
- `pycryptocore.modes.gcm` — реализация режима GCM (AEAD).
- `pycryptocore.hash` — SHA‑256 (с нуля) и SHA3‑256 (через `hashlib`).
- `pycryptocore.mac` — HMAC‑SHA256 и AES‑CMAC.
- `pycryptocore.kdf` — PBKDF2‑HMAC‑SHA256 и иерархия ключей.
- `pycryptocore.csprng` — CSPRNG на базе `os.urandom`.
- `pycryptocore.file_io` — вспомогательные функции чтения/записи файлов и заголовков (IV, salt, nonce, tag).
- `pycryptocore.cli` — точка входа для CLI (`python -m pycryptocore.cli` / команда `cryptocore`).

---

### 1. AES‑128 (модуль `crypto_core`)

```python
from pycryptocore.crypto_core import (
    KEY_SIZE, BLOCK_SIZE, IV_SIZE,
    aes_encrypt, aes_decrypt,
    CryptoCoreError,
)
```

- **`aes_encrypt(mode: str, key: bytes, plaintext: bytes, iv: Optional[bytes] = None, aad: Optional[bytes] = None) -> tuple[bytes, Optional[bytes]]`**
  - `mode` — `"ecb" | "cbc" | "cfb" | "ofb" | "ctr" | "gcm"`.
  - `key` — 16 байт (AES‑128).
  - `plaintext` — входные данные.
  - `iv` — IV/nonce (16 байт для CBC/CFB/OFB/CTR, 12 байт для GCM; если `None`, генерируется автоматически).
  - `aad` — дополнительные аутентифицируемые данные (только GCM).
  - Возвращает `(ciphertext, iv_or_none)`:
    - для GCM `ciphertext` уже содержит `nonce || ciphertext || tag`, поэтому `iv_or_none` всегда `None`;
    - для остальных режимов возвращается сгенерированный IV (или `None` для ECB).

- **`aes_decrypt(mode: str, key: bytes, ciphertext: bytes, iv: Optional[bytes] = None, aad: Optional[bytes] = None) -> bytes`**
  - Расшифровывает данные в указанном режиме.
  - Для GCM ожидает формат `nonce || ciphertext || tag` (12 + N + 16 байт) либо отдельный `iv` (nonce).
  - При ошибке аутентификации/паддинга выбрасывает `CryptoCoreError`.

---

### 2. GCM (модуль `modes.gcm`)

```python
from pycryptocore.modes.gcm import GCM, AuthenticationError
```

- **`GCM(key: bytes, nonce: Optional[bytes] = None)`**
  - `key` — 16‑байтовый AES ключ.
  - `nonce` — 12‑байтовый nonce; если не задан, генерируется случайно.

- **`GCM.encrypt(plaintext: bytes, aad: bytes = b"") -> bytes`**
  - Возвращает `nonce || ciphertext || tag`.

- **`GCM.decrypt(data: bytes, aad: bytes = b"") -> bytes`**
  - При успешной аутентификации — расшифрованный plaintext.
  - При ошибке выбрасывает `AuthenticationError`.

---

### 3. Хеш‑функции (модуль `hash`)

```python
from pycryptocore.hash import SHA256, SHA3_256
```

- **`SHA256()`**
  - Методы:
    - `update(data: bytes) -> None`
    - `digest() -> bytes`
    - `hexdigest() -> str`

- **`SHA3_256()`**
  - Обёртка над `hashlib.sha3_256` c тем же интерфейсом.

---

### 4. MAC (HMAC и CMAC)

```python
from pycryptocore.mac import HMAC, CMAC
```

- **`HMAC(key: bytes, algorithm: str = "sha256")`**
  - Методы:
    - `update(chunk: bytes) -> None`
    - `digest() -> bytes`
    - `hexdigest(data: bytes | None = None) -> str`
    - `update_compute_hex(chunks: Iterable[bytes]) -> str` — потоковая обработка.

- **`CMAC(key: bytes)`**
  - Ключ — 16 байт (AES‑128).
  - Методы:
    - `compute(message: bytes) -> bytes`
    - `hexdigest(message: bytes) -> str`
    - `update_compute(chunks: Iterable[bytes]) -> bytes`

---

### 5. KDF и иерархия ключей (модуль `kdf`)

```python
from pycryptocore.kdf import (
    PBKDF2_ITERATIONS,
    SALT_SIZE,
    generate_salt,
    pbkdf2_hmac_sha256,
    derive_key,
    derive_key_from_password,
)
```

- **`generate_salt(size: int = SALT_SIZE) -> bytes`** — криптографически стойкая соль.
- **`pbkdf2_hmac_sha256(password, salt: bytes, iterations: int, dklen: int) -> bytes`**
  - Реализация PBKDF2‑HMAC‑SHA256.
- **`derive_key(master_key: bytes, context: str, length: int) -> bytes`**
  - Иерархия ключей: разные `context` дают независимые ключи.
- **`derive_key_from_password(password, salt: bytes, iterations: int, length: int) -> bytes`**
  - Обёртка вокруг PBKDF2 с проверкой размера соли.

---

### 6. CSPRNG (модуль `csprng`)

```python
from pycryptocore.csprng import generate_random_bytes, detect_weak_key
```

- **`generate_random_bytes(num_bytes: int) -> bytes`** — генерация случайных байт через OS CSPRNG.
- **`detect_weak_key(key: bytes) -> str | None`**
  - Возвращает строку‑описание проблемы (`"sequential ascending bytes"` и т.п.) либо `None`.

---

### 7. CLI (модуль `cli`)

CLI можно вызывать либо как:

```bash
python3 -m pycryptocore.cli ...
```

либо через скрипт `cryptocore` (после `pip install .`).

Основные команды:

- Шифрование/дешифрование AES:

```bash
python3 -m pycryptocore.cli --algorithm aes --mode cbc --encrypt \
  --key HEX_KEY --input in.bin --output out.bin
```

- Хеши/HMAC/CMAC:

```bash
python3 -m pycryptocore.cli dgst --algorithm sha256 --input file.bin
python3 -m pycryptocore.cli dgst --algorithm sha256 --hmac --key HEX_KEY --input file.bin
python3 -m pycryptocore.cli dgst --algorithm sha256 --cmac --key HEX_AES_KEY --input file.bin
```

- KDF/PBKDF2:

```bash
python3 -m pycryptocore.cli derive --password "pwd" --length 32
```


