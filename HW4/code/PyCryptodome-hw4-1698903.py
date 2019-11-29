import time
import sys
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


print("####### PyCryptodome test #######");
f = open(sys.argv[1], "rb")
in_read = f.read()

input = base64.encodebytes(in_read)                       # convert to ASCII string (for binary files)
in_size = len(input)
plen = ((in_size//16) + 1) * 16
input = input.ljust(plen, bytes('0', 'utf-8'))            # fix padding
#print(input); print()

key = get_random_bytes(32)
iv = get_random_bytes(AES.block_size)


print(" ENCRYPTION TIME = ", end = '');
aes = AES.new(key, AES.MODE_CBC, iv)
start = time.time()
ciphertext = aes.encrypt(input)
end = time.time()
enc_time = end-start
print(str(enc_time));
#print(ciphertext); print()

print(" DECRYPTION TIME = ", end = '');
aes = AES.new(key, AES.MODE_CBC, iv)
start = time.time()
plaintext = aes.decrypt(ciphertext)
end = time.time()
dec_time = end-start
print(str(dec_time));
#print(plaintext); print()

print("SPEED RATIO => " + str(enc_time/dec_time));
