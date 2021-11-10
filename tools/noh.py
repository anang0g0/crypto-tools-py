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
random.seed(12897619287361897)

key= get_random_bytes(32) #
#HexMyKey= key.hex()
nonce = os.urandom(12)

def enc():
    c= open("cipher.txt","wb")
    f=open("README.md", "rb")
    key=(111111).to_bytes(32,byteorder="little") #
    while True:
        
        #rnd=random.randint(1,32)
        flag=f.read(16)
        if not flag:
            c.close()
            f.close()
            break

        cipher= AES.new(key, AES.MODE_GCM)
        ciphertext, tag= cipher.encrypt_and_digest(flag)
        enc= cipher.nonce + ciphertext + tag
        HexEncryptedOriginalMessage= enc.hex()
        #print(len(enc))
        #exit()
        c.write(enc)
        print(HexEncryptedOriginalMessage)
    
        #rnd=random.randint(1,32)
        #ff=f.read(16)
        #cip = ChaCha20Poly1305(key)
        #ciphertext = cip.encrypt(nonce, ff)
        #print(ciphertext.hex())
        #c.write(ciphertext.hex()+'\n')
        #plaintext = cip.decrypt(nonce, ciphertext)
        #print(plaintext)


        

def dec():
    c=open("cipher.txt","rb")
    f=open("plane.txt", "wb")
    key= (111111).to_bytes(32,byteorder="little") #bytes.fromhex(HexMyKey)

    while True:

        flag=c.read(48)
        if not flag:
            f.close()
            c.close()
            break

       
        data = flag #bytes.fromhex(flag)
        cipher = AES.new(key, AES.MODE_GCM, data[:16]) # nonce
        try:
            dec = cipher.decrypt_and_verify(data[16:-16], data[-16:]) # ciphertext, tag
            print(dec) # b'my secret data'
            f.write(dec)
        except ValueError:
            print("Decryption failed")
        

enc()
dec()
