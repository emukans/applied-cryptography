import click
import os
from .aes_cipher import AESCypher


@click.command()
@click.option('--operation', prompt='Operation type:', type=click.Choice(['encrypt', 'decrypt'], case_sensitive=False))
@click.option('--mode', prompt='Chaining mode:', type=click.Choice(['CFB', 'CBC'], case_sensitive=False))
def main(operation, mode):
    dirname = os.path.dirname(os.path.abspath(__file__))
    message_path = os.path.join(dirname, 'message.txt')
    encrypted_message_path = os.path.join(dirname, 'message_encrypted')
    key_path = os.path.join(dirname, 'key')
    mac_path = os.path.join(dirname, 'mac')
    decrypted_path = os.path.join(dirname, 'decrypted')
    secret_path = os.path.join(dirname, 'secret')
    iv_path = os.path.join(dirname, 'iv')

    if operation == 'encrypt':
        with open(message_path, 'r') as file:
            message = file.readline()
            print(f'Message to encrypt: {message}')
    else:
        with open(encrypted_message_path, 'rb') as file:
            message = file.read()
            print(f'Message to decrypt: {message}')

    with open(key_path, 'rb') as file:
        key = file.read()

    if operation == 'encrypt':
        iv = os.urandom(16)
        with open(iv_path, 'wb') as file:
            file.write(iv)
    else:
        with open(iv_path, 'rb') as file:
            iv = file.read()

    aes = AESCypher(mode, key, iv)

    result = None
    mac = None
    secret = None

    if mode.upper() == 'CFB':
        if not os.path.exists(secret_path):
            secret = os.urandom(16)
            with open(secret_path, 'wb') as file:
                file.write(secret)
        else:
            with open(secret_path, 'rb') as file:
                secret = file.read()

    if operation == 'encrypt':
        if mode.upper() == 'CBC':
            result = aes.encrypt_cbc(message)
        elif mode.upper() == 'CFB':
            result, mac = aes.encrypt_cfb(message, secret)
    else:
        if mode.upper() == 'CBC':
            result = aes.decrypt_cbc(message)
        elif mode.upper() == 'CFB':
            with open(mac_path, 'rb') as file:
                mac = file.read()
            result = aes.decrypt_cfb(message, mac, secret)

    if mac:
        with open(mac_path, 'wb') as file:
            file.write(mac)

    if result:
        if operation == 'encrypt':
            print(f'Encrypted message: {result}')
            with open(encrypted_message_path, 'wb') as file:
                file.write(result)
        else:
            print(f'Decrypted message: {result}')
            with open(decrypted_path, 'wb') as file:
                file.write(result.encode())


main()
