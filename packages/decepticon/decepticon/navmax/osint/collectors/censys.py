"""Collecteur Censys — interroge l'API Censys Search v2 pour des infos IP.

Usage:
    collector = CensysCollector(api_id="...", api_secret="...")
    result = await collector.lookup_ip("1.2.3.4")
"""

from dataclasses import dataclass, field

import httpx

from decepticon.navmax.core.config import config
from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class CensysResult:
    """Résultat d'une requête Censys Search v2."""

    ip: str
    services: list[dict] = field(default_factory=list)
    location: str = ""
    autonomous_system: str = ""
    error: str | None = None


class CensysCollector:
    """Collecteur via l'API Censys Search v2.

    Authentification par API ID + Secret (Basic Auth).
    """

    BASE_URL = "https://search.censys.io/api/v2"

    def __init__(self, api_id: str | None = None, api_secret: str | None = None) -> None:
        self.api_id = api_id or getattr(config, "censys_api_id", "")
        self.api_secret = api_secret or getattr(config, "censys_api_secret", "")

    async def lookup_ip(self, ip: str) -> CensysResult:
        """Recherche Censys pour une IP.

        Args:
            ip: Adresse IPv4 à rechercher.

        Returns:
            CensysResult avec les services, localisation, AS.

        """
        if not self.api_id:
            logger.warning("censys_api_key_manquante", message="Résultats OSINT Censys ignorés")
            return CensysResult(
                ip=ip,
                error="API Censys non configurée (NAVMAX_CENSYS_API_ID / NAVMAX_CENSYS_API_SECRET)",
            )

        try:
            import base64

            auth = base64.b64encode(f"{self.api_id}:{self.api_secret}".encode()).decode()

            async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
                resp = await client.get(
                    f"{self.BASE_URL}/hosts/{ip}",
                    headers={"Authorization": f"Basic {auth}"},
                )
                if resp.status_code != 200:
                    return CensysResult(ip=ip, error=f"Censys API: {resp.status_code}")

                data = resp.json().get("result", {})
                services = []
                for svc in data.get("services", []):
                    services.append(
                        {
                            "port": svc.get("port"),
                            "service_name": svc.get("service_name", ""),
                            "transport": svc.get("transport_protocol", "tcp"),
                            "banner": (svc.get("banner", "") or "")[:200],
                        },
                    )

                return CensysResult(
                    ip=ip,
                    services=services,
                    location=f"{data.get('location', {}).get('country', '')} {data.get('location', {}).get('city', '')}".strip(),
                    autonomous_system=data.get("autonomous_system", {}).get("description", ""),
                )
        except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
            return CensysResult(ip=ip, error=str(e))
