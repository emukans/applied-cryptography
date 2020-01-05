import os
import sys
from dotenv import load_dotenv

from x509.utils import build_certificate, verify, encrypt, decrypt

command = sys.argv[1]
issuer = os.getenv('ISSUER', 'Eduards Mukans')
load_dotenv('./env')

dirname = os.path.dirname(os.path.abspath(__file__))
cert_path = os.path.join(dirname, 'cert.pem')
private_path = os.path.join(dirname, 'private.pem')
message_path = os.path.join(dirname, 'message.txt')
encrypted_message_path = os.path.join(dirname, 'encrypted_message')
decrypted_message_path = os.path.join(dirname, 'decrypted_message')

if command == 'generate':
    private, cert = build_certificate(issuer)

    if cert and private:
        with open(cert_path, 'wb') as file:
            file.write(cert)
        with open(private_path, 'wb') as file:
            file.write(private)

        print(f'Certificate has been successfully generated. The issuer is: {issuer}')
elif command == 'verify':
    with open(cert_path, 'rb') as file:
        cert = file.read()

    with open(private_path, 'rb') as file:
        key = file.read()

    try:
        verify(cert, key, issuer)
        print('Certificate signature, issuer and subject is correct')
    except ValueError as error:
        print(error)
elif command == 'encrypt':
    with open(private_path, 'rb') as file:
        key = file.read()

    with open(message_path, 'rb') as file:
        message = file.read()

    encrypted_message = encrypt(key, message)
    if encrypted_message:
        with open(encrypted_message_path, 'wb') as file:
            file.write(encrypted_message)
        print('Message has been encrypted and stored in `encrypted_message` file')

elif command == 'decrypt':
    with open(private_path, 'rb') as file:
        key = file.read()

    with open(encrypted_message_path, 'rb') as file:
        encrypted_message = file.read()

    decrypted_message = decrypt(key, encrypted_message)
    if decrypted_message:
        with open(decrypted_message_path, 'wb') as file:
            file.write(decrypted_message)
        print('Message has been encrypted and stored in `decrypted_message` file')
        print(f'The initial message is: "{decrypted_message.decode("utf-8").strip()}"')
