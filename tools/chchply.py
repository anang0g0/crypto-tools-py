from ctypes import sizeof
import os
from sys import byteorder
from chacha20poly1305 import ChaCha20Poly1305

key = (11111111111).to_bytes(32,byteorder="little")
    #os.urandom(32)
cip = ChaCha20Poly1305(key)
nonce = (222222222).to_bytes(12,byteorder="little")

def enc():
    #os.urandom(12)
    c=open("README.md","rb")
    f=open("cipher.txt","wb")
    while True:        
        data=c.read(32)
        if not data:
            c.close()
            f.close()
            break
        ciphertext = cip.encrypt(nonce, data)
        print(len(ciphertext))
        #exit()
        f.write(ciphertext)
        print(ciphertext.hex())
        
def dec():
    c=open("cipher.txt","rb")
    f=open("plain.txt","wb")
    
    while True:
        ciphertext=c.read(32+16)
        plaintext = cip.decrypt(nonce, ciphertext)
        if not ciphertext:
            c.close()
            f.close()
            break
        f.write(plaintext)
        print(plaintext)

enc()
dec()
