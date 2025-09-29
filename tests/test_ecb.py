import unittest
from src.modes.ecb import aes_ecb_encrypt, aes_ecb_decrypt

class TestECB(unittest.TestCase):
    def test_round_trip(self):
        key = b'0123456789abcdef'  # 16 bytes
        data = b'Hello, CryptoCore! AES ECB test.'
        encrypted = aes_ecb_encrypt(key, data)
        decrypted = aes_ecb_decrypt(key, encrypted)
        self.assertEqual(decrypted, data)

if __name__ == '__main__':
    unittest.main()
