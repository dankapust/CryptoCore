from Crypto.Cipher import AES

def aes_ofb_encrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_OFB, iv)
    return cipher.encrypt(data)

def aes_ofb_decrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_OFB, iv)
    return cipher.decrypt(data)
