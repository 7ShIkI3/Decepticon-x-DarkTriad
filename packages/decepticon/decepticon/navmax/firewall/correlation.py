"""Firewall-AD Correlation — vision unifiée infrastructure × identité.

Corrèle les données Active Directory avec les règles de firewall pour :
- Identifier les utilisateurs AD ayant un accès réseau à des ressources sensibles
- Détecter les comptes admin AD exposés via des règles firewall permissives
- Prioriser les risques en combinant criticité AD + exposition réseau
- Produire des rapports d'impact métier

Usage:
    correlator = ADCorrelator()
    report = correlator.correlate(domain_map, firewall_config)
    print(report.summary())
"""

from dataclasses import dataclass, field
from enum import StrEnum

import structlog

from .base import FirewallConfig

logger = structlog.get_logger(__name__)


# ── Types ──────────────────────────────────────────────────────


class CorrelationSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class CorrelationFinding:
    """Un risque identifié par corrélation AD × Firewall."""

    title: str
    description: str
    severity: CorrelationSeverity
    ad_user: str = ""
    ad_group: str = ""
    firewall_rule: str = ""
    sensitive_resource: str = ""
    business_impact: str = ""
    remediation: str = ""


@dataclass
class CorrelationReport:
    """Rapport de corrélation AD × Firewall."""

    domain: str = ""
    firewall: str = ""
    findings: list[CorrelationFinding] = field(default_factory=list)
    total_ad_users: int = 0
    total_fw_rules: int = 0
    correlated_rules: int = 0  # Règles corrélées avec AD
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "  AD × Firewall Correlation Report",
            f"  Domain: {self.domain}  |  Firewall: {self.firewall}",
            "=" * 60,
            f"  Total AD users: {self.total_ad_users}",
            f"  Total FW rules: {self.total_fw_rules}",
            f"  Correlated rules: {self.correlated_rules}",
            f"  Findings: {len(self.findings)}",
            "",
        ]

        if self.findings:
            lines.append("-" * 60)
            lines.append("  CORRELATED RISKS")
            lines.append("-" * 60)
            for i, f in enumerate(self.findings, 1):
                marker = {
                    "critical": "🔴 CRITICAL",
                    "high": "🟠 HIGH",
                    "medium": "🟡 MEDIUM",
                    "low": "🟢 LOW",
                }.get(f.severity, "❓")
                lines.append(f"  [{i}] {marker}: {f.title}")
                lines.append(f"      {f.description}")
                if f.ad_user:
                    lines.append(f"      AD User: {f.ad_user}")
                if f.ad_group:
                    lines.append(f"      AD Group: {f.ad_group}")
                if f.firewall_rule:
                    lines.append(f"      FW Rule: {f.firewall_rule}")
                if f.sensitive_resource:
                    lines.append(f"      Resource: {f.sensitive_resource}")
                lines.append(f"      Business Impact: {f.business_impact}")
                lines.append(f"      Remediation: {f.remediation}")
                lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)


# ── Corrélateur ────────────────────────────────────────────────


class ADCorrelator:
    """Corrélateur Active Directory × Firewall.

    Combine les données d'énumération AD avec la configuration firewall
    pour identifier les risques combinés.

    Usage:
        correlator = ADCorrelator()
        report = correlator.correlate(domain_map, fw_config)
        print(report.summary())
    """

    # Ressources sensibles par mot-clé dans le nom
    SENSITIVE_RESOURCES = {
        "database": ("Base de données", "Accès non autorisé aux données"),
        "db": ("Base de données", "Accès non autorisé aux données"),
        "sql": ("Base de données", "Accès non autorisé aux données"),
        "finance": ("Système financier", "Fraude financière"),
        "compta": ("Système comptable", "Fraude comptable"),
        "hr": ("Ressources Humaines", "Vol de données personnelles"),
        "rh": ("Ressources Humaines", "Vol de données personnelles"),
        "payroll": ("Paie", "Vol de données salariales"),
        "backup": ("Sauvegarde", "Destruction/vol de sauvegardes"),
        "admin": ("Serveur d'administration", "Prise de contrôle infrastructure"),
        "dc": ("Contrôleur de domaine", "Compromission du domaine"),
        "pki": ("Infrastructure PKI", "Émission de certificats frauduleux"),
        "ca": ("Autorité de certification", "Émission de certificats frauduleux"),
        "vpn": ("Accès VPN", "Accès réseau non autorisé"),
        "dmz": ("Zone démilitarisée", "Pivot vers le réseau interne"),
        "exchange": ("Serveur mail", "Accès aux emails de l'entreprise"),
        "sharepoint": ("SharePoint", "Vol de documents"),
        "sap": ("Système ERP", "Fraude et vol de données"),
        "crm": ("CRM", "Vol de données clients"),
        "pci": ("Zone PCI-DSS", "Vol de données de paiement"),
        "swift": ("Système bancaire", "Fraude financière"),
    }

    # Ports sensibles
    SENSITIVE_PORTS = {
        "1433": "SQL Server",
        "1521": "Oracle",
        "3306": "MySQL",
        "5432": "PostgreSQL",
        "3389": "RDP",
        "22": "SSH",
        "445": "SMB",
        "636": "LDAPS",
        "389": "LDAP",
        "5985": "WinRM",
        "5986": "WinRM HTTPS",
    }

    def __init__(self) -> None:
        pass

    def correlate(
        self,
        domain_map,
        fw_config: FirewallConfig,
    ) -> CorrelationReport:
        """Corrèle les données AD avec la configuration firewall.

        Args:
            domain_map: DomainMap AD
            fw_config: FirewallConfig extraite

        Returns:
            CorrelationReport structuré

        """
        report = CorrelationReport(
            domain=domain_map.domain.name if hasattr(domain_map, "domain") else "",
            firewall=fw_config.hostname,
            total_ad_users=len(domain_map.users) if hasattr(domain_map, "users") else 0,
            total_fw_rules=len(fw_config.rules),
        )

        # Récupérer les données AD
        users = domain_map.users if hasattr(domain_map, "users") else []
        privileged = domain_map.privileged_users if hasattr(domain_map, "privileged_users") else []
        kerb_users = [u for u in users if hasattr(u, "is_kerberoastable") and u.is_kerberoastable]

        # ── Corrélation 1: Admins exposés ──────────────────────
        self._correlate_admin_exposure(report, privileged, fw_config)

        # ── Corrélation 2: Ressources sensibles exposées ───────
        self._correlate_sensitive_exposure(report, fw_config)

        # ── Corrélation 3: Comptes de service Kerberoastable ──
        self._correlate_kerberoastable_exposure(report, kerb_users, fw_config)

        # ── Corrélation 4: Accès VPN privilégiés ──────────────
        self._correlate_vpn_privileged(report, privileged, fw_config)

        report.correlated_rules = sum(1 for f in report.findings if f.firewall_rule)

        return report

    # ── Corrélations ───────────────────────────────────────────

    def _correlate_admin_exposure(
        self,
        report: CorrelationReport,
        privileged_users: list,
        fw_config: FirewallConfig,
    ) -> None:
        """Détecte les admins AD exposés via des règles firewall."""
        admin_count = len(privileged_users)
        risky_rules = fw_config.risky_rules

        if admin_count > 0 and len(risky_rules) > 3:
            report.findings.append(
                CorrelationFinding(
                    title=f"Domaine avec {admin_count} admins + règles firewall permissives",
                    description=(
                        f"Le domaine compte {admin_count} comptes privilégiés ET "
                        f"le firewall a {len(risky_rules)} règles permissives. "
                        f"Un attaquant qui compromet un compte admin peut pivoter "
                        f"sans restriction réseau."
                    ),
                    severity=CorrelationSeverity.HIGH
                    if admin_count > 5
                    else CorrelationSeverity.MEDIUM,
                    ad_group="Domain Admins (et assimilés)",
                    firewall_rule=f"{len(risky_rules)} règles Any/Any ou à risque",
                    business_impact=(
                        "Compromission d'un admin → accès réseau complet aux ressources critiques"
                    ),
                    remediation=(
                        "1. Réduire le nombre de comptes admin\n"
                        "2. Restreindre les règles firewall à des IPs de gestion\n"
                        "3. Mettre en place un bastion/jump host"
                    ),
                ),
            )

    def _correlate_sensitive_exposure(
        self,
        report: CorrelationReport,
        fw_config: FirewallConfig,
    ) -> None:
        """Détecte les ressources sensibles exposées."""
        for rule in fw_config.allow_rules:
            for addr in rule.destination_addresses:
                addr_lower = addr.lower()
                for keyword, (label, impact) in self.SENSITIVE_RESOURCES.items():
                    if keyword in addr_lower:
                        report.findings.append(
                            CorrelationFinding(
                                title=f"Ressource sensible exposée: {label}",
                                description=(
                                    f"L'adresse '{addr}' correspond à '{label}' "
                                    f"et est accessible via la règle '{rule.name}'."
                                ),
                                severity=CorrelationSeverity.HIGH,
                                firewall_rule=rule.name,
                                sensitive_resource=addr,
                                business_impact=impact,
                                remediation=(
                                    f"Restreindre l'accès à {addr} aux seules "
                                    f"sources autorisées (bastion, IPs admin)."
                                ),
                            ),
                        )
                        break  # Un seul match par adresse

            # Ports sensibles
            for port in rule.destination_ports:
                port_clean = port.strip().split(":")[0]
                if port_clean in self.SENSITIVE_PORTS:
                    svc_name = self.SENSITIVE_PORTS[port_clean]
                    report.findings.append(
                        CorrelationFinding(
                            title=f"Service sensible exposé: {svc_name} (port {port_clean})",
                            description=(
                                f"Le port {port_clean} ({svc_name}) est exposé "
                                f"via la règle '{rule.name}'."
                            ),
                            severity=CorrelationSeverity.MEDIUM,
                            firewall_rule=rule.name,
                            sensitive_resource=f"port {port_clean}/{svc_name}",
                            business_impact=(f"Bruteforce ou exploitation de {svc_name} possible"),
                            remediation=(
                                f"1. Restreindre les sources pour le port {port_clean}\n"
                                f"2. Utiliser un VPN pour l'accès à {svc_name}"
                            ),
                        ),
                    )

    def _correlate_kerberoastable_exposure(
        self,
        report: CorrelationReport,
        kerb_users: list,
        fw_config: FirewallConfig,
    ) -> None:
        """Corrèle les comptes Kerberoastable avec l'exposition réseau."""
        if not kerb_users:
            return

        kerb_admin = [u for u in kerb_users if hasattr(u, "is_admin") and u.is_admin]

        if kerb_admin and len(fw_config.allow_rules) > 0:
            report.findings.append(
                CorrelationFinding(
                    title="Comptes admin Kerberoastable + exposition réseau",
                    description=(
                        f"{len(kerb_admin)} compte(s) admin Kerberoastable(s) "
                        f"détecté(s) avec {len(fw_config.allow_rules)} règles "
                        f"firewall permissives. Un attaquant externe peut casser "
                        f"le hash Kerberos et obtenir des accès admin réseau."
                    ),
                    severity=CorrelationSeverity.CRITICAL,
                    ad_user=", ".join(
                        getattr(u, "sam_account_name", str(u)) for u in kerb_admin[:5]
                    ),
                    business_impact=(
                        "Compromission complète du domaine possible via "
                        "Kerberoasting + accès réseau admin"
                    ),
                    remediation=(
                        "1. Supprimer les SPNs des comptes admin\n"
                        "2. Migrer vers des gMSA\n"
                        "3. Restreindre l'accès réseau aux DCs"
                    ),
                ),
            )
        elif kerb_users:
            report.findings.append(
                CorrelationFinding(
                    title=f"{len(kerb_users)} comptes Kerberoastable avec exposition réseau",
                    description=(
                        f"{len(kerb_users)} comptes avec SPN détectés. En combinaison "
                        f"avec les {len(fw_config.allow_rules)} règles allow du firewall, "
                        f"un attaquant peut kerberoaster puis pivoter."
                    ),
                    severity=CorrelationSeverity.MEDIUM,
                    ad_user=", ".join(
                        getattr(u, "sam_account_name", str(u)) for u in kerb_users[:5]
                    ),
                    business_impact=("Escalade de privilèges possible via Kerberoasting"),
                    remediation=(
                        "1. Utiliser des mots de passe 30+ caractères\n"
                        "2. Migrer vers gMSA\n"
                        "3. Restreindre l'accès réseau sortant vers les DCs"
                    ),
                ),
            )

    def _correlate_vpn_privileged(
        self,
        report: CorrelationReport,
        privileged_users: list,
        fw_config: FirewallConfig,
    ) -> None:
        """Détecte les admins avec accès VPN."""
        vpn_rules = [
            r
            for r in fw_config.allow_rules
            if any("vpn" in a.lower() or "ssl" in a.lower() for a in r.destination_addresses)
        ]

        if vpn_rules and len(privileged_users) > 3:
            report.findings.append(
                CorrelationFinding(
                    title="Accès VPN pour utilisateurs privilégiés",
                    description=(
                        f"{len(privileged_users)} utilisateurs privilégiés "
                        f"avec {len(vpn_rules)} règles VPN actives. "
                        f"L'accès admin depuis le VPN étend la surface d'attaque."
                    ),
                    severity=CorrelationSeverity.MEDIUM,
                    ad_group=f"{len(privileged_users)} comptes privilégiés",
                    firewall_rule=vpn_rules[0].name if vpn_rules else "",
                    business_impact=(
                        "Un attaquant qui vole des credentials VPN admin "
                        "obtient un accès complet au réseau interne."
                    ),
                    remediation=(
                        "1. Activer le MFA pour tous les accès VPN admin\n"
                        "2. Séparer les accès VPN admin du VPN utilisateur\n"
                        "3. Appliquer le principe du moindre privilège réseau"
                    ),
                ),
            )
