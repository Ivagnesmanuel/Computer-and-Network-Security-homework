import time
import sys
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

print("####### Cryptography test #######");
f = open(sys.argv[1], "rb")
in_read = f.read()

input = base64.encodebytes(in_read)                       # convert to ASCII string (for binary files)
in_size = len(input)
plen = ((in_size//16) + 1) * 16
input = input.ljust(plen, bytes('0', 'utf-8'))            # fix padding
#print(input); print()

key = os.urandom(32)
iv = os.urandom(16)
aes = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())


print(" ENCRYPTION TIME = ", end = '');
start = time.time()
encryptor = aes.encryptor()
ciphertext = encryptor.update(input) + encryptor.finalize()
end = time.time()
enc_time = end-start
print(str(enc_time));
#print(ciphertext); print()

print(" DECRYPTION TIME = ", end = '');
start = time.time()
decryptor = aes.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()
end = time.time()
dec_time = end-start
print(str(dec_time));
#print(plaintext); print()

print("SPEED RATIO => " + str(enc_time/dec_time));


print("####### Cryptography test (Fernet) #######");
input = base64.encodebytes(in_read) 
key = Fernet.generate_key()
f = Fernet(key)

print(" ENCRYPTION TIME = ", end = '');
start = time.time()
ciphertext = f.encrypt(input)
end = time.time()
enc_time = end-start
print(str(enc_time));
#print(ciphertext); print()

print(" DECRYPTION TIME = ", end = '');
start = time.time()
plaintext = f.decrypt(ciphertext)
end = time.time()
dec_time = end-start
print(str(dec_time));
#print(plaintext); print()

print("SPEED RATIO => " + str(enc_time/dec_time));
