# CryptoCore
Минималистичный криптопровайдер: AES-128 в режимах ECB, CBC, CFB, OFB, CTR. CLI-утилита.

## Сборка и запуск

```bash
pip install -r requirements.txt
```

## Пример использования

### Шифрование по паролю (PBKDF2, соль и IV сохраняются в файл)
```bash
python -m src.cli_parser --algorithm aes --mode cbc --encrypt --password 1234 --input plain.txt --output cipher.bin
```

### Дешифрование по паролю (соль и IV берутся из файла)
```bash
python -m src.cli_parser --algorithm aes --mode cbc --decrypt --password 1234 --input cipher.bin --output decrypted.txt
```

### Шифрование по ключу (старый способ)
```bash
python -m src.cli_parser --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plain.txt --output cipher.bin
```

### Дешифрование по ключу (IV берётся из файла или указывается явно)
```bash
python -m src.cli_parser --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cipher.bin --output decrypted.txt
```

### Поддерживаемые режимы
- ecb (без IV)
- cbc
- cfb
- ofb
- ctr

## Формат файла при шифровании по паролю
- Первые 16 байт: соль (salt)
- Следующие 16 байт: IV
- Остальное: ciphertext

## OpenSSL interoperability

(Для режима по паролю interoperability с OpenSSL невозможен, используйте --key для совместимости)

## Зависимости
- Python 3.x
- pycryptodome
