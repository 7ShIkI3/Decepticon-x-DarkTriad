"""StormShield Connector — API SNS pour firewalls StormShield Network Security.

Utilise l'API REST CONF (application/json) de StormShield SNS.
Documentation: https://documentation.stormshield.eu/

Fonctionnalités :
- Authentification par token API
- Extraction des règles de filtrage, interfaces, objets
- Détection de vulnérabilités connues (CVEs StormShield)
- Extraction de la configuration complète

Usage:
    sns = StormShieldConnector(
        host="10.0.0.1",
        api_key="xxx",
        verify_ssl=False,
    )
    await sns.connect()
    config = await sns.get_full_config()
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


# ── CVEs connues StormShield ───────────────────────────────────

STORMSHIELD_CVES: list[dict] = [
    {
        "cve": "CVE-2023-5634",
        "title": "Privilege Escalation via SNS API",
        "severity": "high",
        "cvss": 8.8,
        "affected": "< 4.3.9, < 4.4.5, < 4.6.2",
        "description": (
            "Élévation de privilèges via l'API SNS permettant à un "
            "utilisateur authentifié d'obtenir des droits admin."
        ),
        "remediation": "Mettre à jour vers 4.3.9+, 4.4.5+, ou 4.6.2+",
    },
    {
        "cve": "CVE-2024-29867",
        "title": "Authentication Bypass — SNS Web Portal",
        "severity": "critical",
        "cvss": 9.8,
        "affected": "< 4.3.11, < 4.4.7, < 4.7.1",
        "description": (
            "Contournement d'authentification dans l'interface web SNS "
            "permettant un accès non authentifié."
        ),
        "remediation": "Mettre à jour vers 4.3.11+, 4.4.7+, ou 4.7.1+",
    },
    {
        "cve": "CVE-2024-31456",
        "title": "Command Injection in IPSec VPN Configuration",
        "severity": "high",
        "cvss": 8.1,
        "affected": "< 4.3.10, < 4.4.6",
        "description": (
            "Injection de commande dans la configuration IPSec VPN via des paramètres non assainis."
        ),
        "remediation": "Mettre à jour vers 4.3.10+ ou 4.4.6+",
    },
    {
        "cve": "CVE-2023-38563",
        "title": "Cross-Site Scripting in SNS Web Admin",
        "severity": "medium",
        "cvss": 6.1,
        "affected": "< 4.3.8, < 4.4.4",
        "description": (
            "XSS dans l'interface d'administration web permettant le vol de session administrateur."
        ),
        "remediation": "Mettre à jour vers 4.3.8+ ou 4.4.4+",
    },
    {
        "cve": "CVE-2022-25347",
        "title": "Information Disclosure — SNMP Default Community",
        "severity": "medium",
        "cvss": 5.3,
        "affected": "< 4.3.5, < 4.4.0",
        "description": ("Divulgation d'information via SNMP avec communauté par défaut."),
        "remediation": ("Mettre à jour vers 4.3.5+ et changer la communauté SNMP"),
    },
]


# ── Connecteur StormShield ─────────────────────────────────────


class StormShieldConnector(FirewallConnector):
    """Connecteur API REST StormShield SNS.

    Utilise l'API CONF (application/json) de StormShield SNS.

    Usage:
        sns = StormShieldConnector(host="10.0.0.1", api_key="xxx")
        await sns.connect()
        rules = await sns.get_rules()
    """

    @property
    def vendor(self) -> FirewallVendor:
        return FirewallVendor.STORMSHIELD

    # ── Connexion ──────────────────────────────────────────────

    async def connect(self) -> bool:
        """Établit la connexion à l'API SNS.

        Returns:
            True si connecté avec succès

        """
        try:
            self._client = httpx.AsyncClient(
                base_url=f"https://{self.host}/api/v1",
                verify=self.verify_ssl,
                timeout=self.timeout,
                headers=self._build_headers(),
            )

            # Test de connexion — GET /version
            resp = await self._client.get("/version")
            if resp.status_code in (200, 401, 403):
                # 401/403 = auth OK mais droits insuffisants pour /version
                if resp.status_code == 200:
                    version_info = resp.json()
                    logger.info(
                        "stormshield_version", version=version_info.get("version", "unknown"),
                    )

                self._connected = True
                logger.info("stormshield_connected", host=self.host)
                return True
            logger.error("stormshield_connect_failed", host=self.host, status=resp.status_code)
            return False

        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as e:
            logger.exception("stormshield_connect_failed", host=self.host, error=str(e))
            return False

    async def close(self) -> None:
        """Ferme la connexion HTTP."""
        if hasattr(self, "_client"):
            await self._client.aclose()
        self._connected = False
        logger.info("stormshield_disconnected", host=self.host)

    def _build_headers(self) -> dict:
        """Construit les headers d'authentification."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        elif self.username and self.password:
            import base64

            credentials = base64.b64encode(
                f"{self.username}:{self.password}".encode(),
            ).decode()
            headers["Authorization"] = f"Basic {credentials}"
        return headers

    # ── API Calls ──────────────────────────────────────────────

    async def _api_get(self, path: str) -> dict:
        """GET sur l'API CONF SNS."""
        if not hasattr(self, "_client"):
            msg = "Not connected. Call connect() first."
            raise RuntimeError(msg)

        resp = await self._client.get(f"/conf/{path}")
        resp.raise_for_status()
        return resp.json()

    async def _api_get_raw(self, path: str) -> str:
        """GET sur l'API SNS retournant du texte brut."""
        if not hasattr(self, "_client"):
            msg = "Not connected. Call connect() first."
            raise RuntimeError(msg)

        resp = await self._client.get(path)
        resp.raise_for_status()
        return resp.text

    async def get_system_info(self) -> dict:
        """Récupère les infos système SNS."""
        try:
            data = await self._api_get("/system")
            system = data.get("system", data)
            return {
                "hostname": system.get("hostname", self.host),
                "model": system.get("model", system.get("productName", "")),
                "version": system.get("version", ""),
                "serial": system.get("serial", ""),
            }
        except (httpx.HTTPStatusError, httpx.RequestError, RuntimeError, KeyError):
            try:
                version_text = await self._api_get_raw("/version")
                return {
                    "hostname": self.host,
                    "model": "",
                    "version": version_text.strip(),
                    "serial": "",
                }
            except (httpx.HTTPStatusError, httpx.RequestError, RuntimeError):
                return {"hostname": self.host, "model": "", "version": "", "serial": ""}

    async def get_rules(self) -> list[FirewallRule]:
        """Extrait les règles de filtrage SNS.

        L'API CONF Stormshield expose les règles via :
            GET /conf/filter/rule
        """
        rules: list[FirewallRule] = []
        try:
            data = await self._api_get("/filter/rule")
            filter_rules = data.get("filter", {}).get("rule", {})
            rule_list = filter_rules.get("rule", [])

            if isinstance(rule_list, dict):
                rule_list = [rule_list]

            for i, raw_rule in enumerate(rule_list):
                action = RuleAction.DENY
                raw_action = raw_rule.get("action", "deny")
                if raw_action in ("pass", "accept", "allow"):
                    action = RuleAction.ALLOW

                rules.append(
                    FirewallRule(
                        id=str(raw_rule.get("id", i)),
                        name=raw_rule.get("comment", f"rule-{i}"),
                        action=action,
                        source_zones=[raw_rule.get("src_zone", "any")],
                        source_addresses=[
                            a if isinstance(a, str) else a.get("name", str(a))
                            for a in raw_rule.get("src_addr", [])
                        ],
                        destination_zones=[raw_rule.get("dst_zone", "any")],
                        destination_addresses=[
                            a if isinstance(a, str) else a.get("name", str(a))
                            for a in raw_rule.get("dst_addr", [])
                        ],
                        destination_ports=[str(s) for s in raw_rule.get("dst_port", [])],
                        protocol=Protocol.ANY,
                        enabled=raw_rule.get("enabled", True),
                        position=i,
                        description=raw_rule.get("comment", ""),
                        raw=raw_rule,
                    ),
                )
        except (httpx.HTTPStatusError, httpx.RequestError, RuntimeError, KeyError) as e:
            logger.exception("stormshield_get_rules", host=self.host, error=str(e))

        return rules

    async def get_interfaces(self) -> list[FirewallInterface]:
        """Extrait les interfaces réseau SNS."""
        interfaces: list[FirewallInterface] = []
        try:
            data = await self._api_get("/network/interface")
            net_ifaces = data.get("network", {}).get("interface", {})
            iface_list = net_ifaces.get("iface", [])

            if isinstance(iface_list, dict):
                iface_list = [iface_list]

            for raw_iface in iface_list:
                interfaces.append(
                    FirewallInterface(
                        name=raw_iface.get("name", ""),
                        ip_address=raw_iface.get("ip", ""),
                        netmask=raw_iface.get("mask", ""),
                        zone=raw_iface.get("zone", ""),
                        enabled=raw_iface.get("enabled", True),
                        type=raw_iface.get("type", "physical"),
                        vlan_id=int(raw_iface.get("vlan_id", 0)),
                    ),
                )
        except (httpx.HTTPStatusError, httpx.RequestError, RuntimeError, KeyError) as e:
            logger.warning("stormshield_get_interfaces", host=self.host, error=str(e))

        return interfaces

    async def get_addresses(self) -> list[FirewallAddress]:
        """Extrait les objets réseau SNS."""
        addresses: list[FirewallAddress] = []
        try:
            data = await self._api_get("/object/network")
            net_objects = data.get("object", {}).get("network", {})
            obj_list = net_objects.get("host", net_objects.get("network", []))

            if isinstance(obj_list, dict):
                obj_list = [obj_list]

            for raw_obj in obj_list:
                value = raw_obj.get("ip", "")
                obj_type = "subnet" if "/" in value else "ip"
                if raw_obj.get("fqdn"):
                    obj_type = "fqdn"
                    value = raw_obj.get("fqdn", "")

                addresses.append(
                    FirewallAddress(
                        name=raw_obj.get("name", ""),
                        value=value,
                        type=obj_type,
                    ),
                )
        except (httpx.HTTPStatusError, httpx.RequestError, RuntimeError, KeyError) as e:
            logger.warning("stormshield_get_addresses", host=self.host, error=str(e))

        return addresses

    async def get_users(self) -> list[FirewallUser]:
        """Extrait les administrateurs SNS."""
        users: list[FirewallUser] = []
        try:
            data = await self._api_get("/admin")
            admin_data = data.get("admin", {})
            admin_list = admin_data.get("admin", [])

            if isinstance(admin_list, dict):
                admin_list = [admin_list]

            for raw_admin in admin_list:
                users.append(
                    FirewallUser(
                        name=raw_admin.get("name", ""),
                        type=raw_admin.get("type", "local"),
                        profile=raw_admin.get("profile", ""),
                    ),
                )
        except (httpx.HTTPStatusError, httpx.RequestError, RuntimeError, KeyError) as e:
            logger.warning("stormshield_get_users", host=self.host, error=str(e))

        return users

    # ── CVE Checks ─────────────────────────────────────────────

    async def check_cves(self, version: str) -> list[CVECheck]:
        """Vérifie les CVEs connues pour cette version de SNS.

        Args:
            version: Version SNS (ex: "4.3.8")

        Returns:
            Liste de CVECheck

        """
        checks: list[CVECheck] = []
        version_clean = version.lower().replace("v", "").replace(" ", "")

        for cve_data in STORMSHIELD_CVES:
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
        logger.info("stormshield_cve_check", version=version, vulnerable=vuln_count)

        return checks

    def _version_affected(self, current: str, affected_range: str) -> bool:
        """Vérifie si une version est dans une plage affectée."""
        if not current:
            return True

        try:
            current_parts = [int(x) for x in current.split(".")]

            for part in affected_range.split(","):
                part = part.strip()
                if "<" in part:
                    threshold = part.replace("<", "").strip()
                    threshold_parts = [int(x) for x in threshold.split(".")]
                    for i in range(max(len(current_parts), len(threshold_parts))):
                        cv = current_parts[i] if i < len(current_parts) else 0
                        tv = threshold_parts[i] if i < len(threshold_parts) else 0
                        if cv != tv:
                            return cv < tv
                    return False
                if "-" in part:
                    low, high = part.split("-", 1)
                    low_parts = [int(x) for x in low.strip().split(".")]
                    high_parts = [int(x) for x in high.strip().split(".")]

                    def _gte(a, b):
                        for i in range(max(len(a), len(b))):
                            va = a[i] if i < len(a) else 0
                            vb = b[i] if i < len(b) else 0
                            if va != vb:
                                return va > vb
                        return True

                    def _lte(a, b):
                        for i in range(max(len(a), len(b))):
                            va = a[i] if i < len(a) else 0
                            vb = b[i] if i < len(b) else 0
                            if va != vb:
                                return va < vb
                        return True

                    if _gte(current_parts, low_parts) and _lte(current_parts, high_parts):
                        return True
        except (ValueError, IndexError):
            return False

        return False
