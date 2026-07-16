"""Collecteurs OSINT — reconnaissance passive.

Sources :
- DNS (A, AAAA, MX, NS, TXT, SOA, CNAME, PTR)
- WHOIS (propriétaire, registrar, dates)
- SSL/TLS certificats (Subject, SAN, issuer, validité)
- Shodan (API — bannières, ports, vulns)
- Web scraping (technologies, emails, liens)
"""

import asyncio
import contextlib
import socket
from dataclasses import dataclass, field

from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Types de données collectées
# ---------------------------------------------------------------------------
@dataclass
class DnsRecord:
    type: str  # A, AAAA, MX, NS, TXT, CNAME, SOA, PTR
    name: str
    value: str
    ttl: int = 0
    priority: int | None = None  # Pour MX, SRV


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
    raw_text: str = ""


@dataclass
class SslCertInfo:
    host: str
    port: int = 443
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    san: list[str] = field(default_factory=list)  # Subject Alternative Names
    fingerprint_sha256: str = ""
    issuer_country: str = ""
    is_valid: bool = False
    days_remaining: int = 0


@dataclass
class WebTechInfo:
    url: str
    server: str | None = None
    technologies: list[str] = field(default_factory=list)
    emails_found: list[str] = field(default_factory=list)
    links_external: list[str] = field(default_factory=list)
    title: str | None = None
    status_code: int = 0


@dataclass
class ShodanInfo:
    ip: str
    ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    org: str | None = None
    isp: str | None = None
    country: str | None = None
    city: str | None = None
    os: str | None = None
    vulnerabilities: list[str] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    last_update: str = ""


# ---------------------------------------------------------------------------
# DNS Collector
# ---------------------------------------------------------------------------
class DnsCollector:
    """Résout les enregistrements DNS via le résolveur système."""

    # Serveurs DNS publics de fallback
    FALLBACK_DNS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

    @staticmethod
    async def lookup(domain: str, record_types: list[str] | None = None) -> list[DnsRecord]:
        """Résout tous les types d'enregistrements DNS pour un domaine.

        Args:
            domain: Nom de domaine (ex: example.com)
            record_types: Types à résoudre. Par défaut : A, AAAA, MX, NS, TXT, CNAME, SOA

        """
        record_types = record_types or ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        records: list[DnsRecord] = []

        domain = domain.rstrip(".")

        for rtype in record_types:
            with contextlib.suppress(socket.gaierror):
                socket.getaddrinfo(domain, None) if rtype in ("A", "AAAA") else []

            # Résolution spécifique par type
            try:
                if rtype == "A":
                    for family, *_ in [(socket.AF_INET,)]:
                        try:
                            info = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
                            for _, _, _, _, sockaddr in info:
                                records.append(DnsRecord(type="A", name=domain, value=sockaddr[0]))
                            break
                        except socket.gaierror:
                            continue

                elif rtype == "AAAA":
                    try:
                        info = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
                        for _, _, _, _, sockaddr in info:
                            records.append(DnsRecord(type="AAAA", name=domain, value=sockaddr[0]))
                    except socket.gaierror:
                        pass

                elif rtype == "MX":
                    records.extend(await DnsCollector._resolve_mx(domain))

                elif rtype == "NS":
                    records.extend(await DnsCollector._resolve_ns(domain))

                elif rtype == "TXT":
                    records.extend(await DnsCollector._resolve_txt(domain))

                elif rtype == "CNAME":
                    records.extend(await DnsCollector._resolve_cname(domain))

                elif rtype == "SOA":
                    records.extend(await DnsCollector._resolve_soa(domain))

            except (OSError, socket.gaierror, socket.herror) as e:
                logger.debug("dns_erreur", domain=domain, type=rtype, erreur=str(e))

        return records

    @staticmethod
    async def reverse_lookup(ip: str) -> list[DnsRecord]:
        """Reverse DNS (PTR)."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return [DnsRecord(type="PTR", name=ip, value=hostname)]
        except (socket.herror, socket.gaierror):
            return []

    # Méthodes internes — utilisent `nslookup` ou `dig` comme fallback
    @staticmethod
    async def _resolve_mx(domain: str) -> list[DnsRecord]:
        records: list[DnsRecord] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "nslookup",
                "-type=MX",
                domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            text = stdout.decode("utf-8", errors="replace")
            for line in text.split("\n"):
                if "mail exchanger" in line.lower():
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            priority = int(parts[-2])
                            value = parts[-1].rstrip(".")
                            records.append(
                                DnsRecord(type="MX", name=domain, value=value, priority=priority),
                            )
                        except ValueError:
                            pass
        except (TimeoutError, OSError, FileNotFoundError):
            pass
        return records

    @staticmethod
    async def _resolve_ns(domain: str) -> list[DnsRecord]:
        records: list[DnsRecord] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "nslookup",
                "-type=NS",
                domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            text = stdout.decode("utf-8", errors="replace")
            for line in text.split("\n"):
                if "nameserver" in line.lower():
                    parts = line.split("=")
                    if len(parts) >= 2:
                        value = parts[-1].strip().rstrip(".")
                        records.append(DnsRecord(type="NS", name=domain, value=value))
        except (TimeoutError, OSError, FileNotFoundError):
            pass
        return records

    @staticmethod
    async def _resolve_txt(domain: str) -> list[DnsRecord]:
        records: list[DnsRecord] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "nslookup",
                "-type=TXT",
                domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            text = stdout.decode("utf-8", errors="replace")
            for line in text.split("\n"):
                if "text =" in line.lower():
                    parts = line.split("=", 1)
                    if len(parts) >= 2:
                        value = parts[1].strip().strip('"')
                        records.append(DnsRecord(type="TXT", name=domain, value=value))
        except (TimeoutError, OSError, FileNotFoundError):
            pass
        return records

    @staticmethod
    async def _resolve_cname(domain: str) -> list[DnsRecord]:
        records: list[DnsRecord] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "nslookup",
                "-type=CNAME",
                domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            text = stdout.decode("utf-8", errors="replace")
            for line in text.split("\n"):
                if "canonical name" in line.lower():
                    parts = line.split("=")
                    if len(parts) >= 2:
                        value = parts[-1].strip().rstrip(".")
                        records.append(DnsRecord(type="CNAME", name=domain, value=value))
        except (TimeoutError, OSError, FileNotFoundError):
            pass
        return records

    @staticmethod
    async def _resolve_soa(domain: str) -> list[DnsRecord]:
        records: list[DnsRecord] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "nslookup",
                "-type=SOA",
                domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            text = stdout.decode("utf-8", errors="replace")
            lines = text.split("\n")
            soa_data: list[str] = []
            for line in lines:
                stripped = line.strip()
                if (
                    stripped
                    and not stripped.startswith("Server:")
                    and not stripped.startswith("Address:")
                ) and (
                    "primary name server" in line.lower()
                    or "responsible mail addr" in line.lower()
                    or "serial" in line.lower()
                    or "refresh" in line.lower()
                    or "retry" in line.lower()
                    or "expire" in line.lower()
                ):
                    soa_data.append(stripped)
            if soa_data:
                records.append(DnsRecord(type="SOA", name=domain, value=" | ".join(soa_data)))
        except (TimeoutError, OSError, FileNotFoundError):
            pass
        return records
