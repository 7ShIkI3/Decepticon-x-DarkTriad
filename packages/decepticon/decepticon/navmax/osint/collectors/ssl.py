"""Collecteur SSL/TLS — certificats X.509.
Récupère le certificat d'un serveur et extrait les informations.
"""

import datetime
import socket
import ssl
from dataclasses import dataclass, field

from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SslCertInfo:
    host: str
    port: int = 443
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    san: list[str] = field(default_factory=list)
    fingerprint_sha256: str = ""
    issuer_country: str = ""
    is_valid: bool = False
    days_remaining: int = 0
    version: int = 0
    ocsp_url: list[str] = field(default_factory=list)


class SslCollector:
    """Collecteur de certificats SSL/TLS."""

    @staticmethod
    async def get_cert(host: str, port: int = 443, timeout: float = 10.0) -> SslCertInfo | None:
        """Récupère et analyse le certificat SSL d'un serveur."""
        info = SslCertInfo(host=host, port=port)

        try:
            # Socket standard (pas asyncio) pour compatibilité wrap_socket
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            raw_sock = socket.create_connection((host, port), timeout=timeout)
            with ctx.wrap_socket(raw_sock, server_hostname=host) as ssl_sock:
                cert = ssl_sock.getpeercert(binary_form=False)
                cert_bin = ssl_sock.getpeercert(binary_form=True)

                if not cert:
                    return info

                # Subject
                subject_parts: list[str] = []
                for field in cert.get("subject", []):
                    for key, val in field:
                        if key == "commonName":
                            subject_parts.append(f"CN={val}")
                info.subject = ", ".join(subject_parts)

                # Issuer
                issuer_parts: list[str] = []
                for field in cert.get("issuer", []):
                    for key, val in field:
                        if key == "commonName":
                            issuer_parts.append(f"CN={val}")
                        elif key == "countryName":
                            info.issuer_country = val
                info.issuer = ", ".join(issuer_parts)

                # Serial
                info.serial_number = cert.get("serialNumber", "")

                # Version
                info.version = cert.get("version", 0)

                # Dates
                info.not_before = cert.get("notBefore", "")
                info.not_after = cert.get("notAfter", "")

                # SAN (Subject Alternative Names)
                for ext in cert.get("subjectAltName", []):
                    _type, value = ext
                    if _type == "DNS":
                        info.san.append(value)

                # Fingerprint SHA256
                import hashlib

                if cert_bin:
                    info.fingerprint_sha256 = hashlib.sha256(cert_bin).hexdigest()

                # Validité
                try:
                    not_after = datetime.datetime.strptime(info.not_after, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.datetime.now(datetime.UTC)
                    info.days_remaining = (not_after.replace(tzinfo=datetime.UTC) - now).days
                    info.is_valid = info.days_remaining > 0
                except (ValueError, AttributeError):
                    pass

                # OCSP
                for ext in cert.get("authorityInfoAccess", []):
                    if ext[0] == "OCSP":
                        info.ocsp_url.append(ext[1])

                logger.info(
                    "ssl_cert_ok", host=host, subject=info.subject[:60], days=info.days_remaining,
                )

        except ssl.SSLError as e:
            logger.debug("ssl_erreur", host=host, erreur=str(e))
        except (TimeoutError, ConnectionRefusedError, OSError) as e:
            logger.debug("ssl_connexion_échouée", host=host, erreur=str(e))

        return info
