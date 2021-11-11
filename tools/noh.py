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
from hashlib import sha3_256,sha256,sha3_512,sha512


#print(seed)
#os.urandom(12)



def enc():
    password = getpass.getpass('password> ')
    password2 = getpass.getpass('confirm> ')
    if password != password2:
        print('Passwords do not match.')
        sys.exit(0)
    sha = sha3_256()
    sha.update(password.encode())
    seed = int(sha.hexdigest(),16)

    random.seed(seed)
    f=open("key.bin","wb")
    nonce=get_random_bytes(12)
    key=get_random_bytes(32)
    print(key)
    print(nonce)
    f.write(key)
    f.close()
    f=open("nonce","wb")
    f.write(nonce)
    f.close()
    #exit()
    cip = ChaCha20Poly1305(key)
    c= open("cipher.txt","wb")
    f=open("README.md", "rb")

    while True:
        rnd=random.randint(1,32)
        
        if rnd%2==0:
            flag=f.read(rnd)
            if not flag:
                c.close()
                f.close()
                break

            cipher= AES.new(key, AES.MODE_GCM)
            ciphertext, tag= cipher.encrypt_and_digest(flag)
            enc= cipher.nonce + ciphertext + tag
            c.write(enc)
        else:
            rnd=random.randint(1,32)
            ff=f.read(rnd)
            if not ff:
                c.close()
                f.close()
                break
            ciphertext = cip.encrypt(nonce, ff)
            c.write(ciphertext)


def dec():
    password = getpass.getpass('password> ')
    password2 = getpass.getpass('confirm> ')
    if password != password2:
        print('Passwords do not match.')
        sys.exit(0)
    sha = sha3_256()
    sha.update(password.encode())
    seed = int(sha.hexdigest(),16)
    random.seed(seed)
    
    fp=open("nonce","rb")
    fq=open("key.bin","rb")
    c=open("cipher.txt","rb")
    f=open("plane.txt", "wb")
    key=fq.read(32)
    print(key)
    nonce=fp.read(12)
    print(nonce)
    fp.close()
    fq.close()
    #exit()
    cip = ChaCha20Poly1305(key)
    while True:
        rnd=random.randint(1,32)
        if rnd%2==0:
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
        else:
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
