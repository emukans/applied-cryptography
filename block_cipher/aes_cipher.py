import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AESCypher:
    block_size = 16

    def __init__(self):
        backend = default_backend()
        key = os.urandom(32)
        iv = os.urandom(16)
        self.cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

    def encrypt(self, message: str) -> bytes:
        encryptor = self.cipher.encryptor()
        padded_message = message
        if len(message) % self.block_size:
            pad_length = len(message) % self.block_size
            padded_message = ' ' * (self.block_size - pad_length) + message

        buf = bytearray(len(padded_message) + self.block_size - 1)
        len_encrypted = encryptor.update_into(padded_message.encode(), buf)

        ct = bytes(buf[:len_encrypted]) + encryptor.finalize()

        return ct

    def decrypt(self, ct: bytes) -> str:
        buf = bytearray(len(ct) + self.block_size - 1)
        decryptor = self.cipher.decryptor()
        len_decrypted = decryptor.update_into(ct, buf)

        message = bytes(buf[:len_decrypted]) + decryptor.finalize()
        result = message.decode('utf-8').lstrip()

        return result
