from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes
import secrets
import binascii
import os
import random
from chacha20poly1305 import ChaCha20Poly1305


#def aes_gcm():

key= get_random_bytes(32)
HexMyKey= key.hex()
nonce = os.urandom(12)

with open("README.md", "rb") as f:
    while True:
        rnd=random.randint(1,32)
        flag=f.read(rnd)

        cipher= AES.new(key, AES.MODE_GCM)
        ciphertext, tag= cipher.encrypt_and_digest(flag)
        enc= cipher.nonce + ciphertext + tag
        HexEncryptedOriginalMessage= enc.hex()
        print(HexEncryptedOriginalMessage)

        key=bytes.fromhex(HexMyKey)
        data = bytes.fromhex(HexEncryptedOriginalMessage)
        cipher = AES.new(key, AES.MODE_GCM, data[:16]) # nonce
        try:
            dec = cipher.decrypt_and_verify(data[16:-16], data[-16:]) # ciphertext, tag
            print(dec) # b'my secret data'
        except ValueError:
            print("Decryption failed")
        if not flag:
            break

        rnd=random.randint(1,32)
        ff=f.read(rnd)
        cip = ChaCha20Poly1305(key)
        ciphertext = cip.encrypt(nonce, ff)
        print(ciphertext.hex())
        plaintext = cip.decrypt(nonce, ciphertext)
        print(plaintext)

        if not ff:
            break
        

f.close()

