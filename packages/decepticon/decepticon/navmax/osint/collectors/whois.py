"""Collecteur WHOIS — informations de propriété de domaine.
Utilise le protocole WHOIS (port 43) directement.
"""

import asyncio
import contextlib
import re
from dataclasses import dataclass, field

from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)


# Serveurs WHOIS par TLD (liste partielle)
WHOIS_SERVERS: dict[str, str] = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "fr": "whois.nic.fr",
    "de": "whois.denic.de",
    "uk": "whois.nic.uk",
    "be": "whois.dns.be",
    "ch": "whois.nic.ch",
    "eu": "whois.eu",
    "it": "whois.nic.it",
    "nl": "whois.domain-registry.nl",
    "ru": "whois.tcinet.ru",
    "info": "whois.afilias.net",
    "biz": "whois.neulevel.biz",
    "tv": "whois.nic.tv",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "xyz": "whois.nic.xyz",
    "dev": "whois.nic.dev",
    "app": "whois.nic.app",
    "ai": "whois.nic.ai",
    "ca": "whois.cira.ca",
}


@dataclass
class WhoisInfo:
    domain: str
    registrar: str | None = None
    creation_date: str | None = None
    expiration_date: str | None = None
    updated_date: str | None = None
    name_servers: list[str] = field(default_factory=list)
    registrant_name: str | None = None
    registrant_org: str | None = None
    registrant_email: str | None = None
    registrant_country: str | None = None
    admin_email: str | None = None
    tech_email: str | None = None
    raw_text: str = ""


class WhoisCollector:
    """Collecteur WHOIS via connexion socket brute."""

    WHOIS_PORT = 43

    @staticmethod
    async def lookup(domain: str) -> WhoisInfo | None:
        """Effectue une requête WHOIS pour un domaine."""
        domain = domain.lower().strip()

        # Déterminer le serveur WHOIS à partir du TLD
        tld = domain.rsplit(".", 1)[-1] if "." in domain else domain
        server = WHOIS_SERVERS.get(tld, "whois.iana.org")

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server, WhoisCollector.WHOIS_PORT),
                timeout=10.0,
            )
            writer.write((domain + "\r\n").encode())
            await writer.drain()

            raw = b""
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(8192), timeout=5.0)
                    if not chunk:
                        break
                    raw += chunk
                    if len(raw) > 65536:  # 64 KB max
                        break
                except TimeoutError:
                    break

            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

            text = raw.decode("utf-8", errors="replace")
            return WhoisCollector._parse(text, domain)

        except (TimeoutError, ConnectionRefusedError, OSError, UnicodeDecodeError) as e:
            logger.debug("whois_échec", domain=domain, erreur=str(e))
            return None

    @staticmethod
    def _parse(text: str, domain: str) -> WhoisInfo:
        """Parse la sortie WHOIS brute."""
        info = WhoisInfo(domain=domain, raw_text=text[:5000])
        text.lower()

        # Registrar
        for pat in [
            r"registrar:\s*(.+)",
            r"registrar\s+name:\s*(.+)",
            r"Sponsoring Registrar:\s*(.+)",
        ]:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                info.registrar = m.group(1).strip()
                break

        # Dates
        for date_type, attr in [
            ("creation", "creation_date"),
            ("created", "creation_date"),
            ("expir", "expiration_date"),
            ("expiry", "expiration_date"),
            ("updated", "updated_date"),
            ("last modified", "updated_date"),
        ]:
            for pat in [
                rf"{date_type}\s*date:\s*(.+)",
                rf"{date_type}:\s*(.+)",
                rf"Registry {date_type.title()} Date:\s*(.+)",
            ]:
                m = re.search(pat, text, re.IGNORECASE)
                if m and getattr(info, attr) is None:
                    setattr(info, attr, m.group(1).strip()[:50])
                    break

        # Name servers
        ns_patterns = [
            r"name\s*server:\s*(.+)",
            r"nserver:\s*(.+)",
        ]
        for pat in ns_patterns:
            for match in re.finditer(pat, text, re.IGNORECASE):
                ns = match.group(1).strip().lower().rstrip(".")
                if ns and ns not in info.name_servers:
                    info.name_servers.append(ns)

        # Registrant
        for field, attr in [
            (r"registrant\s*name:\s*(.+)", "registrant_name"),
            (r"registrant\s*organization:\s*(.+)", "registrant_org"),
            (r"registrant\s*email:\s*(.+)", "registrant_email"),
            (r"registrant\s*country:\s*(.+)", "registrant_country"),
            (r"person:\s*(.+)", "registrant_name"),
            (r"org:\s*(.+)", "registrant_org"),
            (r"admin\s*email:\s*(.+)", "admin_email"),
            (r"tech\s*email:\s*(.+)", "tech_email"),
        ]:
            m = re.search(field, text, re.IGNORECASE)
            if m and getattr(info, attr) is None:
                val = m.group(1).strip()[:100]
                # Filtrer les valeurs génériques
                if val.lower() not in ("redacted for privacy", "not disclosed", "redacted"):
                    setattr(info, attr, val)

        return info
