from Crypto.Cipher import AES

BLOCK_SIZE = 16

def aes_cfb_encrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    return cipher.encrypt(data)

def aes_cfb_decrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    return cipher.decrypt(data)
