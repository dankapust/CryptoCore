import unittest
import os
from src.modes.cbc import aes_cbc_encrypt, aes_cbc_decrypt
from src.modes.cfb import aes_cfb_encrypt, aes_cfb_decrypt
from src.modes.ofb import aes_ofb_encrypt, aes_ofb_decrypt
from src.modes.ctr import aes_ctr_encrypt, aes_ctr_decrypt

class TestModes(unittest.TestCase):
    def setUp(self):
        self.key = b'0123456789abcdef'
        self.iv = b'abcdef0123456789'
        self.data = b'CryptoCore test data for block ciphers!'

    def test_cbc(self):
        enc = aes_cbc_encrypt(self.key, self.data, self.iv)
        dec = aes_cbc_decrypt(self.key, enc, self.iv)
        self.assertEqual(dec, self.data)

    def test_cfb(self):
        enc = aes_cfb_encrypt(self.key, self.data, self.iv)
        dec = aes_cfb_decrypt(self.key, enc, self.iv)
        self.assertEqual(dec, self.data)

    def test_ofb(self):
        enc = aes_ofb_encrypt(self.key, self.data, self.iv)
        dec = aes_ofb_decrypt(self.key, enc, self.iv)
        self.assertEqual(dec, self.data)

    def test_ctr(self):
        enc = aes_ctr_encrypt(self.key, self.data, self.iv)
        dec = aes_ctr_decrypt(self.key, enc, self.iv)
        self.assertEqual(dec, self.data)

if __name__ == '__main__':
    unittest.main()
