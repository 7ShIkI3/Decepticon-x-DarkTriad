"""Firewall Connector Base — protocole abstrait pour connecteurs firewall.

Définit l'interface commune que tous les connecteurs (FortiGate, StormShield,
Palo Alto, etc.) doivent implémenter.

Usage:
    class MyFirewall(FirewallConnector):
        async def get_rules(self) -> list[FirewallRule]: ...
        async def get_interfaces(self) -> list[FirewallInterface]: ...
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ── Types communs ──────────────────────────────────────────────


class RuleAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


class FirewallVendor(StrEnum):
    FORTINET = "fortinet"
    STORMSHIELD = "stormshield"
    PALO_ALTO = "palo_alto"
    CHECKPOINT = "checkpoint"
    CISCO = "cisco"
    GENERIC = "generic"


class RuleSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class FirewallRule:
    """Règle de pare-feu normalisée (indépendante du vendor)."""

    id: str = ""
    name: str = ""
    action: RuleAction = RuleAction.DENY
    source_zones: list[str] = field(default_factory=list)
    source_addresses: list[str] = field(default_factory=list)
    source_ports: list[str] = field(default_factory=list)
    destination_zones: list[str] = field(default_factory=list)
    destination_addresses: list[str] = field(default_factory=list)
    destination_ports: list[str] = field(default_factory=list)
    protocol: Protocol = Protocol.ANY
    application: str = ""
    enabled: bool = True
    position: int = 0
    hit_count: int = 0
    description: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class FirewallInterface:
    """Interface réseau du firewall."""

    name: str = ""
    ip_address: str = ""
    netmask: str = ""
    zone: str = ""
    enabled: bool = True
    type: str = "physical"  # physical, vlan, loopback, tunnel
    vlan_id: int = 0


@dataclass
class FirewallAddress:
    """Objet adresse (host, subnet, FQDN, range)."""

    name: str = ""
    value: str = ""  # IP, subnet, FQDN
    type: str = "ip"  # ip, subnet, fqdn, range
    zone: str = ""


@dataclass
class FirewallUser:
    """Utilisateur/administrateur du firewall."""

    name: str = ""
    type: str = "local"  # local, ldap, radius
    profile: str = ""  # super_admin, readonly...
    trusted_hosts: list[str] = field(default_factory=list)


@dataclass
class CVECheck:
    """Résultat de vérification CVE sur un firewall."""

    cve_id: str
    title: str
    severity: str  # critical, high, medium
    vulnerable: bool = False
    version_affected: str = ""
    current_version: str = ""
    description: str = ""
    remediation: str = ""
    cvss_score: float = 0.0


@dataclass
class FirewallConfig:
    """Configuration complète extraite d'un firewall."""

    vendor: FirewallVendor
    hostname: str = ""
    model: str = ""
    version: str = ""
    serial: str = ""
    rules: list[FirewallRule] = field(default_factory=list)
    interfaces: list[FirewallInterface] = field(default_factory=list)
    addresses: list[FirewallAddress] = field(default_factory=list)
    users: list[FirewallUser] = field(default_factory=list)
    cve_checks: list[CVECheck] = field(default_factory=list)
    raw_config: dict[str, Any] = field(default_factory=dict)

    @property
    def enabled_rules(self) -> list[FirewallRule]:
        return [r for r in self.rules if r.enabled]

    @property
    def allow_rules(self) -> list[FirewallRule]:
        return [r for r in self.rules if r.action == RuleAction.ALLOW and r.enabled]

    @property
    def risky_rules(self) -> list[FirewallRule]:
        """Règles potentiellement dangereuses."""
        risky = []
        for r in self.allow_rules:
            # Any/Any rules
            if (
                (
                    (not r.source_addresses or "any" in [a.lower() for a in r.source_addresses])
                    and (
                        not r.destination_addresses
                        or "any" in [a.lower() for a in r.destination_addresses]
                    )
                )
                or "22" in r.destination_ports
                or "3389" in r.destination_ports
            ):
                risky.append(r)
        return risky

    def summary(self) -> str:
        lines = [
            f"=== {self.vendor.value.upper()} Firewall: {self.hostname} ===",
            f"Model: {self.model}",
            f"Version: {self.version}",
            f"Rules: {len(self.rules)} ({len(self.enabled_rules)} enabled, "
            f"{len(self.allow_rules)} allow)",
            f"Interfaces: {len(self.interfaces)}",
            f"Addresses: {len(self.addresses)}",
            f"Users: {len(self.users)}",
            f"CVEs: {sum(1 for c in self.cve_checks if c.vulnerable)} vulnerable",
        ]
        if self.risky_rules:
            lines.append(f"\n⚠️  Risky rules ({len(self.risky_rules)}):")
            for r in self.risky_rules[:5]:
                src = ", ".join(r.source_addresses) or "any"
                dst = ", ".join(r.destination_addresses) or "any"
                svc = ", ".join(r.destination_ports) or "any"
                lines.append(f"  [{r.position}] {r.name}: {src} → {dst} ({svc})")
        return "\n".join(lines)


# ── Protocol ───────────────────────────────────────────────────


class FirewallConnector(ABC):
    """Interface abstraite pour tout connecteur firewall.

    Chaque implémentation (FortiGate, StormShield...) doit fournir :
    - Connexion / déconnexion
    - Extraction des règles, interfaces, adresses, utilisateurs
    - Vérification des CVEs connues
    """

    def __init__(
        self,
        host: str,
        api_key: str = "",
        username: str = "",
        password: str = "",
        verify_ssl: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.host = host
        self.api_key = api_key
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._connected = False

    @property
    @abstractmethod
    def vendor(self) -> FirewallVendor:
        """Le fabricant du firewall."""
        ...

    @abstractmethod
    async def connect(self) -> bool:
        """Établit la connexion au firewall."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Ferme la connexion."""
        ...

    @abstractmethod
    async def get_system_info(self) -> dict:
        """Récupère les infos système (hostname, version, modèle...)."""
        ...

    @abstractmethod
    async def get_rules(self) -> list[FirewallRule]:
        """Extrait toutes les règles du firewall."""
        ...

    @abstractmethod
    async def get_interfaces(self) -> list[FirewallInterface]:
        """Extrait les interfaces réseau."""
        ...

    @abstractmethod
    async def get_addresses(self) -> list[FirewallAddress]:
        """Extrait les objets adresse."""
        ...

    @abstractmethod
    async def get_users(self) -> list[FirewallUser]:
        """Extrait les utilisateurs/administrateurs."""
        ...

    async def get_full_config(self) -> FirewallConfig:
        """Extrait la configuration complète (toutes les sections).

        Returns:
            FirewallConfig normalisé

        """
        info = await self.get_system_info()
        rules = await self.get_rules()
        interfaces = await self.get_interfaces()
        addresses = await self.get_addresses()
        users = await self.get_users()
        cves = await self.check_cves(info.get("version", ""))

        return FirewallConfig(
            vendor=self.vendor,
            hostname=info.get("hostname", self.host),
            model=info.get("model", ""),
            version=info.get("version", ""),
            serial=info.get("serial", ""),
            rules=rules,
            interfaces=interfaces,
            addresses=addresses,
            users=users,
            cve_checks=cves,
        )

    async def check_cves(self, version: str) -> list[CVECheck]:
        """Vérifie les CVEs connues pour la version du firmware.

        Args:
            version: Version du firmware

        Returns:
            Liste de CVECheck

        """
        # Implémentation par défaut — à surcharger par vendor
        return []

    @property
    def is_connected(self) -> bool:
        return self._connected

    def __repr__(self) -> str:
        return f"{self.vendor.value}Connector(host={self.host})"
