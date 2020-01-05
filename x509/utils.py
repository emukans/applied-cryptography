from datetime import datetime, timedelta
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding


def build_certificate(issuer):
    """Generates self signed certificate for a hostname, and optional IP addresses."""

    now = datetime.utcnow()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    public_key = private_key.public_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .serial_number(x509.random_serial_number())
        .public_key(public_key)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(issuer)]
            ),
            critical=False
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(
            private_key=private_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )
    )

    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return key_pem, cert_pem


def verify(cert_bytes, private_key_bytes, issuer):
    private_key = load_pem_private_key(private_key_bytes, None, default_backend())
    public_key = private_key.public_key()
    cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
    try:
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except InvalidSignature:
        raise ValueError('Certificate signature is invalid')

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])
    if name != cert.issuer or name != cert.subject:
        raise ValueError('Issuer or subject is invalid')
