"""Gestion des certificats TLS pour le proxy MITM.

Génère une CA racine + des certificats serveur signés à la volée
pour chaque hostname intercepté.
"""

import datetime
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from decepticon.navmax.core.config import config
from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)

CA_KEY_FILE = "navmax_ca_key.pem"
CA_CERT_FILE = "navmax_ca_cert.pem"

# Cache des certificats générés (hostname → (cert_pem, key_pem))
_cert_cache: dict[str, tuple[str, str]] = {}


def _ca_dir() -> Path:
    d = config.proxy_ca_dir
    d.mkdir(parents=True, exist_ok=True)
    return d


def generate_ca() -> tuple[str, str]:
    """Génère une nouvelle CA racine NavMAX.
    Retourne (cert_pem, key_pem).
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NavMAX Proxy CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "NavMAX Interception CA"),
        ],
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256(), backend=default_backend())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    # Sauvegarder
    ca_path = _ca_dir()
    (ca_path / CA_CERT_FILE).write_text(cert_pem)
    (ca_path / CA_KEY_FILE).write_text(key_pem)
    os.chmod(ca_path / CA_KEY_FILE, 0o600)

    logger.info("ca_générée", path=str(ca_path))
    return cert_pem, key_pem


def load_or_generate_ca() -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Charge la CA existante ou en génère une nouvelle.
    Retourne les objets cryptography (cert, key).
    """
    ca_path = _ca_dir()
    cert_file = ca_path / CA_CERT_FILE
    key_file = ca_path / CA_KEY_FILE

    if cert_file.exists() and key_file.exists():
        cert_pem = cert_file.read_bytes()
        key_pem = key_file.read_bytes()
    else:
        cert_pem_str, key_pem_str = generate_ca()
        cert_pem = cert_pem_str.encode()
        key_pem = key_pem_str.encode()

    ca_cert = x509.load_pem_x509_certificate(cert_pem, backend=default_backend())
    ca_key = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())

    return ca_cert, ca_key  # type: ignore[return-value]


def generate_host_cert(hostname: str) -> tuple[str, str]:
    """Génère (ou récupère du cache) un certificat signé pour un hostname.
    Retourne (cert_pem, key_pem).
    """
    if hostname in _cert_cache:
        return _cert_cache[hostname]

    ca_cert, ca_key = load_or_generate_ca()

    host_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NavMAX Intercepted"),
        ],
    )

    # SAN : hostname + wildcard
    san = x509.SubjectAlternativeName(
        [
            x509.DNSName(hostname),
            x509.DNSName(f"*.{hostname}"),
        ],
    )

    host_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(host_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256(), backend=default_backend())
    )

    cert_pem = host_cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = host_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    _cert_cache[hostname] = (cert_pem, key_pem)
    return cert_pem, key_pem
