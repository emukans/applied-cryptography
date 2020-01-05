import os
import sys
from dotenv import load_dotenv

from x509.utils import build_certificate, verify

command = sys.argv[1]
issuer = os.getenv('ISSUER', 'Eduards Mukans')
load_dotenv('./env')

dirname = os.path.dirname(os.path.abspath(__file__))
public_path = os.path.join(dirname, 'public.pem')
cert_path = os.path.join(dirname, 'cert.pem')
private_path = os.path.join(dirname, 'private.pem')

if command == 'generate':
    public, private, cert = build_certificate(issuer)

    if cert and private and public:
        with open(public_path, 'wb') as file:
            file.write(public)
        with open(cert_path, 'wb') as file:
            file.write(cert)
        with open(private_path, 'wb') as file:
            file.write(private)

        print(f'Certificate has been successfully generated. The issuer is: {issuer}')
elif command == 'verify':
    with open(public_path, 'rb') as file:
        public = file.read()

    with open(cert_path, 'rb') as file:
        cert = file.read()

    try:
        verify(cert, public, issuer)
        print('Certificate signature, issuer and subject is correct')
    except ValueError as error:
        print(error)
