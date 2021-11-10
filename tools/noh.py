from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes
import secrets
import binascii
import os,sys
import random
import getpass
from chacha20poly1305 import ChaCha20Poly1305
from Crypto.Hash import SHA3_256,SHA256,SHA3_512,SHA512


#

nonce = get_random_bytes(12)
print(nonce)
#os.urandom(12)
password = getpass.getpass('password> ')
password2 = getpass.getpass('confirm> ')
if password != password2:
    print('Passwords do not match.')
    sys.exit(0)
sha = SHA3_256.new()
sha.update(password.encode())
key = sha.digest()
v=int.from_bytes(key,byteorder="little")

key = get_random_bytes(32) #
a=int.from_bytes(key,byteorder="little")
v^=a
key=v.to_bytes(32,byteorder="little")

def enc():
    random.seed(128976192873618971)
    cip = ChaCha20Poly1305(key)
    c= open("cipher.txt","wb")
    f=open("README.md", "rb")

    while True:
        rnd=random.randint(1,32)
        flag=f.read(rnd)
        if not flag:
            c.close()
            f.close()
            break
        
        cipher= AES.new(key, AES.MODE_GCM)
        ciphertext, tag= cipher.encrypt_and_digest(flag)
        enc= cipher.nonce + ciphertext + tag
        c.write(enc)
    
        rnd=random.randint(1,32)
        ff=f.read(rnd)
        if not ff:
            c.close()
            f.close()
            break

        ciphertext = cip.encrypt(nonce, ff)
        c.write(ciphertext)


        

def dec():
    random.seed(128976192873618971)
    c=open("cipher.txt","rb")
    f=open("plane.txt", "wb")
    cip = ChaCha20Poly1305(key)

    while True:
        rnd=random.randint(1,32)
        flag=c.read(rnd+32)
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
        rnd=random.randint(1,32)
        ciphertext=c.read(rnd+16)
        if not ciphertext:
            f.close()
            c.close()
            break
        plaintext = cip.decrypt(nonce, ciphertext)
        f.write(plaintext)
        print(plaintext)
        

enc()
dec()
