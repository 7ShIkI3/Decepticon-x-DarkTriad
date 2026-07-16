"""Collecteur Shodan — interroge l'API Shodan pour des infos sur une IP/domaine.

Usage:
    collector = ShodanCollector(api_key="...")
    result = await collector.lookup_ip("1.2.3.4")
"""

from dataclasses import dataclass, field

import httpx

from decepticon.navmax.core.config import config
from decepticon.navmax.core.logging import get_logger

# Rétrocompatibilité : CensysCollector et CensysResult peuvent être importés
# depuis shodan.py (ils étaient historiquement définis ici).
# Ils sont maintenant dans le module dédié censys.py.
from .censys import CensysCollector, CensysResult  # noqa: F401

logger = get_logger(__name__)


@dataclass
class ShodanResult:
    """Résultat d'une requête Shodan."""

    ip: str
    ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    org: str = ""
    isp: str = ""
    country: str = ""
    city: str = ""
    os: str = ""
    vulns: list[str] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    last_update: str = ""
    error: str | None = None


class ShodanCollector:
    """Collecteur d'information via l'API Shodan."""

    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or getattr(config, "shodan_api_key", "")

    async def lookup_ip(self, ip: str) -> ShodanResult:
        """Récupère les infos Shodan pour une IP."""
        if not self.api_key:
            logger.warning("shodan_api_key_manquante", message="Résultats OSINT Shodan ignorés")
            return ShodanResult(
                ip=ip, error="Clé API Shodan non configurée (NAVMAX_SHODAN_API_KEY)",
            )

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
                resp = await client.get(
                    f"{self.BASE_URL}/shodan/host/{ip}",
                    params={"key": self.api_key},
                )
                if resp.status_code != 200:
                    return ShodanResult(ip=ip, error=f"Shodan API: {resp.status_code}")

                data = resp.json()

                services = []
                for svc in data.get("data", []):
                    services.append(
                        {
                            "port": svc.get("port"),
                            "transport": svc.get("transport", "tcp"),
                            "product": svc.get("product", ""),
                            "version": svc.get("version", ""),
                            "banner": (svc.get("data", "") or "")[:200],
                        },
                    )

                return ShodanResult(
                    ip=ip,
                    ports=data.get("ports", []),
                    hostnames=data.get("hostnames", []),
                    org=data.get("org", ""),
                    isp=data.get("isp", ""),
                    country=data.get("country_name", ""),
                    city=data.get("city", ""),
                    os=data.get("os", ""),
                    vulns=data.get("vulns", []),
                    services=services,
                    last_update=data.get("last_update", ""),
                )
        except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
            return ShodanResult(ip=ip, error=str(e))


@dataclass
class CrtShResult:
    """Résultat certificate transparency (crt.sh)."""

    domain: str
    subdomains: list[str] = field(default_factory=list)
    certificates: list[dict] = field(default_factory=list)
    error: str | None = None


class CrtShCollector:
    """Collecteur via crt.sh (Certificate Transparency)."""

    BASE_URL = "https://crt.sh"

    async def search(self, domain: str) -> CrtShResult:
        """Recherche les certificats pour un domaine."""
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(
                    f"{self.BASE_URL}/?q=%.{domain}&output=json",
                )
                if resp.status_code != 200:
                    return CrtShResult(domain=domain, error=f"crt.sh: {resp.status_code}")

                data = resp.json()
                subdomains_set: set[str] = set()
                certs = []

                for entry in data[:100]:
                    name = entry.get("name_value", "")
                    for sub in name.split("\\n"):
                        sub = sub.strip().lower()
                        if sub and sub != domain and not sub.startswith("*."):
                            subdomains_set.add(sub)

                    certs.append(
                        {
                            "id": entry.get("id"),
                            "issuer": entry.get("issuer_name", ""),
                            "not_before": entry.get("not_before", ""),
                            "not_after": entry.get("not_after", ""),
                            "name": name[:100],
                        },
                    )

                return CrtShResult(
                    domain=domain,
                    subdomains=sorted(subdomains_set),
                    certificates=certs,
                )
        except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
            return CrtShResult(domain=domain, error=str(e))
