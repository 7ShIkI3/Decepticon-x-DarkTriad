"""FortiGate Connector — API REST native pour firewalls Fortinet.

Fonctionnalités :
- Authentification par API key ou username/password
- Extraction des politiques, interfaces, adresses, utilisateurs
- Détection de vulnérabilités connues (CVE-2026-35616, CVE-2022-40684...)
- Détection de configuration à risque

API FortiOS REST:
    https://<host>/api/v2/cmdb/firewall/policy/
    https://<host>/api/v2/monitor/system/status/

Usage:
    fgt = FortiGateConnector(host="10.0.0.1", api_key="xxx")
    await fgt.connect()
    config = await fgt.get_full_config()
    print(config.summary())
"""

import httpx
import structlog

from .base import (
    CVECheck,
    FirewallAddress,
    FirewallConnector,
    FirewallInterface,
    FirewallRule,
    FirewallUser,
    FirewallVendor,
    Protocol,
    RuleAction,
)

logger = structlog.get_logger(__name__)


# ── CVEs connues FortiGate ─────────────────────────────────────

FORTIGATE_CVES: list[dict] = [
    {
        "cve": "CVE-2026-35616",
        "title": "Authentification Bypass via Alternate Path",
        "severity": "critical",
        "cvss": 9.8,
        "affected": "< 7.0.16, < 7.2.10, < 7.4.6, < 7.6.2",
        "description": (
            "Contournement d'authentification permettant un accès "
            "administratif non authentifié via un chemin alternatif "
            "dans l'interface de management HTTPS."
        ),
        "remediation": "Mettre à jour vers 7.0.16+, 7.2.10+, 7.4.6+, ou 7.6.2+",
    },
    {
        "cve": "CVE-2022-40684",
        "title": "Authentication Bypass — Admin Interface",
        "severity": "critical",
        "cvss": 9.6,
        "affected": "7.2.0-7.2.1, 7.0.0-7.0.6",
        "description": (
            "Contournement d'authentification via le header HTTP "
            "X-Forwarded-For sur l'interface HTTPS d'administration."
        ),
        "remediation": "Mettre à jour vers 7.2.2+ ou 7.0.7+",
    },
    {
        "cve": "CVE-2024-21762",
        "title": "Out-of-Bounds Write in SSL-VPN",
        "severity": "critical",
        "cvss": 9.6,
        "affected": "7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13",
        "description": (
            "Écriture hors limites dans le composant SSL-VPN permettant "
            "l'exécution de code à distance non authentifiée."
        ),
        "remediation": (
            "Mettre à jour vers 7.4.3+, 7.2.7+, 7.0.14+ OU désactiver SSL-VPN si non utilisé"
        ),
    },
    {
        "cve": "CVE-2023-27997",
        "title": "Heap-Based Buffer Overflow in SSL-VPN",
        "severity": "critical",
        "cvss": 9.8,
        "affected": "7.2.0-7.2.4, 7.0.0-7.0.11, 6.4.0-6.4.12, 6.2.0-6.2.14, 6.0.0-6.0.16",
        "description": (
            "Dépassement de tampon dans le pré-authentification SSL-VPN "
            "permettant l'exécution de code à distance."
        ),
        "remediation": ("Mettre à jour vers 7.2.5+, 7.0.12+, 6.4.13+, 6.2.15+, 6.0.17+"),
    },
    {
        "cve": "CVE-2023-33308",
        "title": "Stack-Based Overflow in Proxy Policy",
        "severity": "critical",
        "cvss": 9.8,
        "affected": "7.2.0-7.2.4, 7.0.0-7.0.12",
        "description": (
            "Dépassement de pile dans le moteur de proxy permettant "
            "l'exécution de code via un paquet spécialement conçu."
        ),
        "remediation": "Mettre à jour vers 7.2.5+ ou 7.0.13+",
    },
    {
        "cve": "CVE-2024-31492",
        "title": "External Control of File Name in fgfmd",
        "severity": "high",
        "cvss": 8.1,
        "affected": "7.4.0-7.4.3, 7.2.0-7.2.7, 7.0.0-7.0.14",
        "description": (
            "Contrôle externe de nom de fichier dans le démon fgfmd "
            "permettant l'injection de commandes."
        ),
        "remediation": "Mettre à jour vers 7.4.4+, 7.2.8+, 7.0.15+",
    },
    {
        "cve": "CVE-2024-23662",
        "title": "SSL-VPN Web Portal XSS",
        "severity": "medium",
        "cvss": 6.1,
        "affected": "7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13",
        "description": (
            "Cross-Site Scripting dans le portail SSL-VPN permettant le vol de session."
        ),
        "remediation": "Mettre à jour vers 7.4.3+, 7.2.7+, 7.0.14+",
    },
]

# Ports à haut risque (RDP, SSH, etc. exposés)
HIGH_RISK_PORTS = {
    "22",
    "23",
    "3389",
    "5900",
    "5901",
    "21",
    "135",
    "139",
    "445",
    "1433",
    "1521",
    "3306",
    "5432",
    "6379",
    "27017",
    "11211",
}


# ── Connecteur FortiGate ───────────────────────────────────────


class FortiGateConnector(FirewallConnector):
    """Connecteur API REST FortiGate (FortiOS).

    Supporte FortiOS 6.x, 7.x.

    Usage:
        fgt = FortiGateConnector(
            host="192.168.1.99",
            api_key="xxx",
            verify_ssl=False,
        )
        await fgt.connect()
        rules = await fgt.get_rules()
    """

    @property
    def vendor(self) -> FirewallVendor:
        return FirewallVendor.FORTINET

    # ── Connexion ──────────────────────────────────────────────

    async def connect(self) -> bool:
        """Établit la connexion et vérifie l'authentification.

        Returns:
            True si connecté avec succès

        """
        try:
            self._client = httpx.AsyncClient(
                base_url=f"https://{self.host}",
                verify=self.verify_ssl,
                timeout=self.timeout,
                headers=self._build_headers(),
            )

            # Test de connexion
            resp = await self._client.get("/api/v2/cmdb/system/status")
            if resp.status_code == 401:
                logger.error("fortigate_auth_failed", host=self.host)
                return False
            if resp.status_code != 200:
                logger.warning("fortigate_status", host=self.host, status=resp.status_code)
                # Certaines versions répondent 403 sur /status...
                # On essaie une autre route
                resp2 = await self._client.get("/api/v2/monitor/system/status")
                if resp2.status_code != 200:
                    return False

            self._connected = True
            logger.info(
                "fortigate_connected",
                host=self.host,
                using="api_key" if self.api_key else "password",
            )
            return True

        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as e:
            logger.exception("fortigate_connect_failed", host=self.host, error=str(e))
            return False

    async def close(self) -> None:
        """Ferme la connexion HTTP."""
        if hasattr(self, "_client"):
            await self._client.aclose()
        self._connected = False
        logger.info("fortigate_disconnected", host=self.host)

    def _build_headers(self) -> dict:
        """Construit les headers HTTP d'authentification."""
        if self.api_key:
            return {"Authorization": f"Bearer {self.api_key}"}
        if self.username and self.password:
            import base64

            credentials = base64.b64encode(
                f"{self.username}:{self.password}".encode(),
            ).decode()
            return {"Authorization": f"Basic {credentials}"}
        return {}

    # ── API Calls ──────────────────────────────────────────────

    async def _api_get(self, path: str, params: dict | None = None) -> dict:
        """GET sur l'API REST FortiOS."""
        if not hasattr(self, "_client"):
            msg = "Not connected. Call connect() first."
            raise RuntimeError(msg)

        resp = await self._client.get(path, params=params)
        resp.raise_for_status()
        return resp.json()

    async def get_system_info(self) -> dict:
        """Récupère les infos système (hostname, version, modèle)."""
        try:
            data = await self._api_get("/api/v2/monitor/system/status")
            # FortiOS versions récentes
            status = data.get("results", data)
            return {
                "hostname": status.get("hostname", self.host),
                "model": status.get("model", ""),
                "version": status.get("version", ""),
                "serial": status.get("serial", ""),
            }
        except (httpx.HTTPStatusError, httpx.RequestError, RuntimeError, KeyError):
            # Fallback: cmdb
            try:
                data = await self._api_get(
                    "/api/v2/cmdb/system/global",
                    params={"vdom": "root"},
                )
                results = data.get("results", [data])
                global_config = results[0] if isinstance(results, list) else results
                return {
                    "hostname": global_config.get("hostname", self.host),
                    "model": "",
                    "version": "",
                    "serial": "",
                }
            except (httpx.HTTPStatusError, httpx.RequestError, RuntimeError, KeyError):
                return {"hostname": self.host, "model": "", "version": "", "serial": ""}

    async def get_rules(self) -> list[FirewallRule]:
        """Extrait toutes les politiques firewall (IPv4)."""
        rules: list[FirewallRule] = []
        try:
            data = await self._api_get("/api/v2/cmdb/firewall/policy")
            results = data.get("results", [])

            for i, pol in enumerate(results):
                rules.append(
                    FirewallRule(
                        id=str(pol.get("policyid", i)),
                        name=pol.get("name", f"policy-{pol.get('policyid', i)}"),
                        action=RuleAction.ALLOW
                        if pol.get("action") == "accept"
                        else RuleAction.DENY,
                        source_zones=[
                            z.get("name", "") if isinstance(z, dict) else str(z)
                            for z in pol.get("srcintf", [])
                        ],
                        source_addresses=[
                            a.get("name", "") if isinstance(a, dict) else str(a)
                            for a in pol.get("srcaddr", [])
                        ],
                        source_ports=[],
                        destination_zones=[
                            z.get("name", "") if isinstance(z, dict) else str(z)
                            for z in pol.get("dstintf", [])
                        ],
                        destination_addresses=[
                            a.get("name", "") if isinstance(a, dict) else str(a)
                            for a in pol.get("dstaddr", [])
                        ],
                        destination_ports=[
                            s.get("port", "") if isinstance(s, dict) else str(s)
                            for s in pol.get("service", [])
                        ],
                        protocol=Protocol.ANY,
                        application=str(
                            pol.get("application", [])[0] if pol.get("application") else "",
                        ),
                        enabled=pol.get("status") == "enable",
                        position=i,
                        description=pol.get("comments", ""),
                        raw=pol,
                    ),
                )
        except (httpx.HTTPStatusError, httpx.RequestError, RuntimeError, KeyError) as e:
            logger.exception("fortigate_get_rules", error=str(e))

        return rules

    async def get_interfaces(self) -> list[FirewallInterface]:
        """Extrait les interfaces réseau."""
        interfaces: list[FirewallInterface] = []
        try:
            data = await self._api_get("/api/v2/cmdb/system/interface")
            results = data.get("results", [])

            for iface in results:
                interfaces.append(
                    FirewallInterface(
                        name=iface.get("name", ""),
                        ip_address=str(
                            iface.get("ip", "").split("/")[0] if iface.get("ip") else "",
                        ),
                        netmask="",
                        zone=str(iface.get("interface", "")),
                        enabled=iface.get("status") != "down",
                        type=iface.get("type", "physical"),
                        vlan_id=int(iface.get("vlanid", 0)),
                    ),
                )
        except (httpx.HTTPStatusError, httpx.RequestError, RuntimeError, KeyError) as e:
            logger.exception("fortigate_get_interfaces", error=str(e))

        return interfaces

    async def get_addresses(self) -> list[FirewallAddress]:
        """Extrait les objets adresse."""
        addresses: list[FirewallAddress] = []
        try:
            data = await self._api_get("/api/v2/cmdb/firewall/address")
            results = data.get("results", [])

            for addr in results:
                value = ""
                addr_type = "ip"
                if addr.get("type") == "fqdn":
                    value = addr.get("fqdn", "")
                    addr_type = "fqdn"
                elif addr.get("type") == "iprange":
                    value = f"{addr.get('start-ip', '')}-{addr.get('end-ip', '')}"
                    addr_type = "range"
                else:
                    value = addr.get("subnet", "")

                addresses.append(
                    FirewallAddress(
                        name=addr.get("name", ""),
                        value=value,
                        type=addr_type,
                    ),
                )
        except (httpx.HTTPStatusError, httpx.RequestError, RuntimeError, KeyError) as e:
            logger.exception("fortigate_get_addresses", error=str(e))

        return addresses

    async def get_users(self) -> list[FirewallUser]:
        """Extrait les administrateurs."""
        users: list[FirewallUser] = []
        try:
            data = await self._api_get("/api/v2/cmdb/system/admin")
            results = data.get("results", [])

            for admin in results:
                users.append(
                    FirewallUser(
                        name=admin.get("name", ""),
                        type=admin.get("accprofile", "local"),
                        profile=admin.get("accprofile", ""),
                        trusted_hosts=[
                            f"{h.get('ip', '')}/{h.get('mask', '')}"
                            for h in admin.get("trusthost", [])
                        ],
                    ),
                )
        except (httpx.HTTPStatusError, httpx.RequestError, RuntimeError, KeyError) as e:
            logger.exception("fortigate_get_users", error=str(e))

        return users

    # ── CVE Checks ─────────────────────────────────────────────

    async def check_cves(self, version: str) -> list[CVECheck]:
        """Vérifie les CVEs connues pour cette version de FortiOS.

        Args:
            version: Version FortiOS (ex: "v7.2.8")

        Returns:
            Liste de CVECheck

        """
        checks: list[CVECheck] = []
        version_clean = version.lower().replace("v", "").replace(" ", "")

        for cve_data in FORTIGATE_CVES:
            vulnerable = self._version_affected(
                version_clean,
                cve_data["affected"],
            )

            checks.append(
                CVECheck(
                    cve_id=cve_data["cve"],
                    title=cve_data["title"],
                    severity=cve_data["severity"],
                    vulnerable=vulnerable,
                    version_affected=cve_data["affected"],
                    current_version=version,
                    description=cve_data["description"],
                    remediation=cve_data["remediation"],
                    cvss_score=cve_data["cvss"],
                ),
            )

        vuln_count = sum(1 for c in checks if c.vulnerable)
        logger.info("fortigate_cve_check", version=version, vulnerable=vuln_count)

        return checks

    def _version_affected(self, current: str, affected_range: str) -> bool:
        """Vérifie si une version est dans une plage affectée.

        Args:
            current: Version actuelle (ex: "7.2.4")
            affected_range: Plage affectée (ex: "7.2.0-7.2.6")

        Returns:
            True si la version est vulnérable

        """
        if not current:
            return True  # Version inconnue → considérée vulnérable

        try:
            current_parts = [int(x) for x in current.split(".")]

            for part in affected_range.split(","):
                part = part.strip()
                if "<" in part:
                    # " < 7.0.16"
                    threshold = part.replace("<", "").strip()
                    threshold_parts = [int(x) for x in threshold.split(".")]
                    return self._version_lt(current_parts, threshold_parts)
                if "-" in part:
                    # "7.2.0-7.2.6"
                    low, high = part.split("-", 1)
                    low_parts = [int(x) for x in low.strip().split(".")]
                    high_parts = [int(x) for x in high.strip().split(".")]
                    if self._version_gte(current_parts, low_parts) and self._version_lte(
                        current_parts, high_parts,
                    ):
                        return True
        except (ValueError, IndexError):
            return False

        return False

    @staticmethod
    def _version_lt(a: list[int], b: list[int]) -> bool:
        """A < b."""
        for i in range(max(len(a), len(b))):
            va = a[i] if i < len(a) else 0
            vb = b[i] if i < len(b) else 0
            if va != vb:
                return va < vb
        return False

    @staticmethod
    def _version_lte(a: list[int], b: list[int]) -> bool:
        """A <= b."""
        for i in range(max(len(a), len(b))):
            va = a[i] if i < len(a) else 0
            vb = b[i] if i < len(b) else 0
            if va != vb:
                return va < vb
        return True

    @staticmethod
    def _version_gte(a: list[int], b: list[int]) -> bool:
        """A >= b."""
        for i in range(max(len(a), len(b))):
            va = a[i] if i < len(a) else 0
            vb = b[i] if i < len(b) else 0
            if va != vb:
                return va > vb
        return True
