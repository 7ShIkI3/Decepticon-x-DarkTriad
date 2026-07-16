"""Fingerprinting : détection d'OS et identification avancée de services."""

import asyncio
import contextlib
import platform
import re
import socket

from decepticon.navmax.core.logging import get_logger
from decepticon.navmax.core.utils import safe_close_writer

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Détection d'OS par heuristiques TTL
# ---------------------------------------------------------------------------
TTL_SIGNATURES: dict[str, list[int]] = {
    "Linux": [64],
    "Windows": [128],
    "FreeBSD": [64],
    "OpenBSD": [64],
    "macOS": [64],
    "Solaris": [255],
    "Cisco IOS": [255],
    "AIX": [255],
    "HP-UX": [255],
}

# Mapping final
TTL_TO_OS: dict[int, str] = {}
for os_name, ttls in TTL_SIGNATURES.items():
    for ttl in ttls:
        TTL_TO_OS[ttl] = os_name


async def _ping_ttl(ip: str, timeout: float = 2.0) -> int | None:
    """Envoie un ping ICMP basique et récupère le TTL.
    Nécessite admin sur Windows. Utilise `ping` système comme fallback.
    """
    try:
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
        output = stdout.decode("utf-8", errors="replace")

        # Cherche "ttl=64" ou "TTL=128"
        m = re.search(r"[tT][tT][lL]\s*[=:]\s*(\d+)", output)
        if m:
            return int(m.group(1))
    except (TimeoutError, OSError) as e:
        logger.debug("ping_échec", ip=ip, erreur=str(e))

    return None


async def detect_os(ip: str, timeout: float = 2.0) -> dict:
    """Tente de détecter l'OS d'une cible.

    Méthodes :
    1. TTL du ping ICMP
    2. Fallback : TCP TTL sur connexion au port 80

    Returns:
        {"os": "Linux" | "Windows" | ... | "unknown", "confidence": "high" | "medium" | "low", "ttl": int | None}

    """
    result = {"os": "unknown", "confidence": "low", "ttl": None, "methods": []}

    # Méthode 1 : ping ICMP
    ttl = await _ping_ttl(ip, timeout)
    if ttl is not None:
        result["ttl"] = ttl
        result["methods"].append("icmp_ttl")
        os_guess = TTL_TO_OS.get(ttl)
        if os_guess:
            result["os"] = os_guess
            result["confidence"] = "medium"
            logger.info("os_détecté_icmp", ip=ip, os=os_guess, ttl=ttl)
            return result

    # Méthode 2 : TCP TTL (connexion au port 80)
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 80),
            timeout=timeout,
        )
        sock: socket.socket = writer.get_extra_info("socket")
        if sock:
            ttl_tcp = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            result["ttl"] = ttl_tcp
            result["methods"].append("tcp_ttl")
            os_guess = TTL_TO_OS.get(ttl_tcp)
            if os_guess:
                result["os"] = os_guess
                result["confidence"] = "medium"
        await safe_close_writer(writer)
    except (TimeoutError, ConnectionRefusedError, OSError) as e:
        logger.debug("tcp_ttl_échec", ip=ip, erreur=str(e))

    if result["os"] == "unknown":
        logger.info("os_indétectable", ip=ip)

    return result


# ---------------------------------------------------------------------------
# Détection avancée de service HTTP
# ---------------------------------------------------------------------------
async def detect_http_service(ip: str, port: int, timeout: float = 2.0) -> dict:
    """Récupère les en-têtes HTTP et identifie le serveur.

    Returns:
        {"server": "nginx/1.24.0", "headers": {"Server": "...", ...}, "title": "..."}

    """
    result: dict = {"server": None, "headers": {}, "title": None}

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        request = (
            f"GET / HTTP/1.0\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: NavMAX/0.1 Scanner\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        raw = b""
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > 16384:  # 16 Ko max
                    break
            except TimeoutError:
                break

        await safe_close_writer(writer)

        text = raw.decode("utf-8", errors="replace")

        # Parse les headers HTTP
        headers_raw, _, body = text.partition("\r\n\r\n")
        for line in headers_raw.split("\r\n")[1:]:  # Skip status line
            if ": " in line:
                key, val = line.split(": ", 1)
                result["headers"][key] = val
                if key.lower() == "server":
                    result["server"] = val

        # Titre HTML
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if m:
            result["title"] = m.group(1).strip()

    except (TimeoutError, ConnectionRefusedError, OSError) as e:
        logger.debug("http_detect_échec", ip=ip, port=port, erreur=str(e))

    return result


# ---------------------------------------------------------------------------
# Détection de service (point d'entrée unifié)
# ---------------------------------------------------------------------------
async def detect_service(ip: str, port: int, protocol: str = "tcp", timeout: float = 2.0) -> dict:
    """Détecte le service tournant sur un port ouvert.

    Returns:
        {"service": "http", "version": "2.4.57", "banner": "...", "details": {...}}

    """
    result: dict = {"service": "unknown", "version": None, "banner": None, "details": {}}

    if protocol != "tcp":
        return result

    # Si c'est un port HTTP(S), on fait une détection enrichie
    if port in (80, 8080, 8000, 443, 8443):
        http_info = await detect_http_service(ip, port, timeout)
        result["details"]["http"] = http_info
        if http_info["server"]:
            result["service"] = "http" if port != 443 else "https"
            result["version"] = http_info["server"]
            return result

    # Sinon, banner grabbing simple
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        banner_bytes = await asyncio.wait_for(reader.read(2048), timeout=min(timeout, 1.5))
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()

        if banner_bytes:
            banner = banner_bytes.decode("utf-8", errors="replace").strip()
            result["banner"] = banner

            from .tcp import _parse_banner

            service, version = _parse_banner(banner)
            if service:
                result["service"] = service
                result["version"] = version

    except (TimeoutError, ConnectionRefusedError, OSError):
        pass

    return result
