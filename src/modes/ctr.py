from Crypto.Cipher import AES
from Crypto.Util import Counter

BLOCK_SIZE = 16

def aes_ctr_encrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(data)

def aes_ctr_decrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(data)
