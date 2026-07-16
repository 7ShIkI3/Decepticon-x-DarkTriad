"""Scanner TCP Connect — ouvre une connexion TCP complète (sans privilèges admin).
Détection de services par banner grabbing.
"""

import asyncio
import contextlib
import time
from typing import NamedTuple

from decepticon.navmax.core.config import config
from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)


class PortResult(NamedTuple):
    port: int
    protocol: str  # tcp | udp
    state: str  # open | closed | filtered | timeout
    service: str | None = None
    banner: str | None = None
    version: str | None = None
    latency_ms: float | None = None


async def _scan_single_port(
    ip: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> PortResult:
    """Scanne un seul port TCP avec connexion complète."""
    async with semaphore:
        t0 = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
        except TimeoutError:
            return PortResult(port=port, protocol="tcp", state="filtered", latency_ms=None)
        except (ConnectionRefusedError, OSError):
            # ECONNREFUSED → port fermé (rare car le firewall bloque souvent)
            return PortResult(port=port, protocol="tcp", state="closed", latency_ms=None)

        latency = (time.monotonic() - t0) * 1000

        # Banner grabbing — le writer est fermé dans le finally
        banner = None
        service_name = None
        version = None

        try:
            try:
                # Certains services envoient une bannière immédiatement
                banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=min(timeout, 1.0))
                if banner_bytes:
                    banner = banner_bytes.decode("utf-8", errors="replace").strip()
                    service_name, version = _parse_banner(banner)
            except (TimeoutError, ConnectionError, OSError):
                pass  # Pas de bannière, normal
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

        return PortResult(
            port=port,
            protocol="tcp",
            state="open",
            service=service_name,
            banner=banner,
            version=version,
            latency_ms=round(latency, 1),
        )


async def tcp_connect_scan(
    ip: str,
    ports: list[int],
    timeout: float | None = None,
    max_concurrency: int | None = None,
) -> list[PortResult]:
    """Scan TCP Connect complet sur une IP et une liste de ports.

    Args:
        ip: Adresse IP de la cible
        ports: Liste des ports à scanner
        timeout: Timeout par port en secondes
        max_concurrency: Nombre max de connexions simultanées

    Returns:
        Liste des résultats triés par port

    """
    timeout = timeout or config.scanner_default_timeout
    max_concurrency = max_concurrency or config.scanner_max_concurrency
    semaphore = asyncio.Semaphore(max_concurrency)

    logger.info("tcp_scan_début", ip=ip, ports_count=len(ports), concurrency=max_concurrency)

    tasks = [_scan_single_port(ip, p, timeout, semaphore) for p in ports]
    results = await asyncio.gather(*tasks)

    # Tri par port
    results.sort(key=lambda r: r.port)
    open_ports = [r for r in results if r.state == "open"]

    logger.info("tcp_scan_fini", ip=ip, open=len(open_ports), total=len(ports))
    return results


# ---------------------------------------------------------------------------
# Parsing de bannières — heuristiques simples
# ---------------------------------------------------------------------------
SERVICE_SIGNATURES: dict[str, list[str]] = {
    "ssh": ["SSH-", "OpenSSH"],
    "http": ["HTTP/", "Apache", "nginx", "IIS", "Microsoft-IIS"],
    "https": ["HTTP/1.1 400", "HTTP/1.1 502"],
    "ftp": ["FTP", "vsftpd", "ProFTPD", "220 "],
    "smtp": ["ESMTP", "Postfix", "Sendmail", "Exim", "220 "],
    "mysql": ["mysql_native_password", "MySQL"],
    "postgresql": ["PostgreSQL"],
    "redis": ["-ERR", "+PONG", "redis"],
    "mongodb": ["MongoDB"],
    "dns": ["DNS"],
    "pop3": ["+OK", "POP3"],
    "imap": ["* OK", "IMAP"],
    "rdp": ["RDP"],
    "smb": ["SMB"],
    "telnet": ["login:", "Password:", "Username:"],
    "elasticsearch": ["elasticsearch"],
    "docker": ["Docker"],
    "http-proxy": ["Proxy-"],
}


def _parse_banner(banner: str) -> tuple[str | None, str | None]:
    """Analyse une bannière pour identifier le service et sa version.
    Retourne (service_name, version).
    """
    upper = banner.upper()
    for service, sigs in SERVICE_SIGNATURES.items():
        for sig in sigs:
            if sig.upper() in upper:
                version = _extract_version(banner)
                return service, version
    return None, None


def _extract_version(banner: str) -> str | None:
    """Tente d'extraire un numéro de version d'une bannière."""
    import re

    # Patterns communs : OpenSSH_8.9p1, Apache/2.4.57, nginx/1.24.0
    patterns = [
        r"(\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?)",  # X.Y ou X.Y.Z
        r"(?:version|v\.?)\s*(\d+\.\d+(?:\.\d+)?)",
    ]
    for pat in patterns:
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            return m.group(1)
    return None
