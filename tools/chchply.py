import os
from chacha20poly1305 import ChaCha20Poly1305

key = os.urandom(32)
cip = ChaCha20Poly1305(key)

nonce = os.urandom(12)
ciphertext = cip.encrypt(nonce, b'test')
print(ciphertext.hex())
plaintext = cip.decrypt(nonce, ciphertext)
print(plaintext)
