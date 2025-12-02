from pycryptocore.modes.gcm import GCM

key = bytes.fromhex('00' * 16)
gcm = GCM(key)
pt = b'Hello GCM world'
print(f'Plaintext: {pt}')

ct = gcm.encrypt(pt)
print(f'Ciphertext length: {len(ct)}')
print(f'Nonce: {ct[:12].hex()}')
print(f'Tag: {ct[-16:].hex()}')

# Decrypt
gcm2 = GCM(key, nonce=ct[:12])
pt2 = gcm2.decrypt(ct)
print(f'Decrypted: {pt2}')
print(f'Match: {pt == pt2}')

