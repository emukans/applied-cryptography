from typing import Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac


class AESCypher:
    block_size = 16

    def __init__(self, mode, key, iv):
        backend = default_backend()

        if mode == 'CBC':
            self.cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        elif mode == 'CFB':
            self.cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)

    def encrypt_cbc(self, message: str) -> bytes:
        encryptor = self.cipher.encryptor()
        padded_message = message
        if len(message) % self.block_size:
            pad_length = len(message) % self.block_size
            padded_message = ' ' * (self.block_size - pad_length) + message

        buf = bytearray(len(padded_message) + self.block_size - 1)
        len_encrypted = encryptor.update_into(padded_message.encode(), buf)

        ct = bytes(buf[:len_encrypted]) + encryptor.finalize()

        return ct

    def encrypt_cfb(self, message: str, key: bytes) -> Tuple[bytes, bytes]:
        encryptor = self.cipher.encryptor()
        buf = bytearray(len(message) + self.block_size - 1)
        len_encrypted = encryptor.update_into(message.encode(), buf)

        ct = bytes(buf[:len_encrypted]) + encryptor.finalize()

        mac = cmac.CMAC(algorithms.AES(key), backend=default_backend())
        mac.update(ct)

        return ct, mac.finalize()

    def decrypt_cbc(self, ct: bytes) -> str:
        buf = bytearray(len(ct) + self.block_size - 1)
        decryptor = self.cipher.decryptor()
        len_decrypted = decryptor.update_into(ct, buf)

        message = bytes(buf[:len_decrypted]) + decryptor.finalize()
        result = message.decode('utf-8').lstrip()

        return result

    def decrypt_cfb(self, ct: bytes, mac: bytes, key: bytes) -> str:
        cmac_instance = cmac.CMAC(algorithms.AES(key), backend=default_backend())
        cmac_instance.update(ct)
        cmac_instance.verify(mac)
        print(f'MAC has been verified')

        buf = bytearray(len(ct) + self.block_size - 1)
        decryptor = self.cipher.decryptor()
        len_decrypted = decryptor.update_into(ct, buf)

        message = bytes(buf[:len_decrypted]) + decryptor.finalize()
        result = message.decode('utf-8').lstrip()

        return result
