import sys
from .aes_cipher import AESCypher

aes = AESCypher()

ct = aes.encrypt(sys.argv[1])

output = aes.decrypt(ct)
print(output)
