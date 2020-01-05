import os
from dotenv import load_dotenv

from x509.utils import build_certificate

issuer = os.getenv('ISSUER', 'Eduards Mukans')
load_dotenv('./env')
cert, key = build_certificate(issuer)

if cert and key:
    dirname = os.path.dirname(os.path.abspath(__file__))
    cert_path = os.path.join(dirname, 'cert.pem')
    key_path = os.path.join(dirname, 'key.pem')
    with open(cert_path, 'wb') as file:
        file.write(cert)
    with open(key_path, 'wb') as file:
        file.write(key)

    print(f'Certificate has been successfully generated. The issuer is: {issuer}')
