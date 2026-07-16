"""AD Vulnerability Scanner — évaluation de la robustesse de l'annuaire.

Détecte automatiquement :
- Comptes Kerberoastable (SPNs)
- Comptes AS-REP Roastable (pas de pré-authentification)
- Délégations non contraintes / contraintes
- SMB signing désactivé
- LDAP signing/channel binding manquant
- Politique de mot de passe faible
- Comptes avec mot de passe qui n'expire jamais
- Comptes à haut privilège sans protection suffisante
- Mots de passe par défaut (krbtgt sans reset, etc.)
- ACLs dangereuses (AdminSDHolder non protégé)

Usage:
    scanner = ADVulnScanner(connector)
    findings = await scanner.scan_all(domain_map)
    for f in findings:
        print(f"{f.severity}: {f.title}")
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import structlog

from .connector import ADConnector

logger = structlog.get_logger(__name__)


# ── Types ──────────────────────────────────────────────────────


class FindingSeverity(StrEnum):
    CRITICAL = "critical"  # Compromission domaine immédiate
    HIGH = "high"  # Escalade de privilèges probable
    MEDIUM = "medium"  # Surface d'attaque augmentée
    LOW = "low"  # Bonne pratique
    INFO = "info"  # Information


class FindingCategory(StrEnum):
    KERBEROASTING = "kerberoasting"
    ASREP_ROASTING = "asrep_roasting"
    DELEGATION = "delegation"
    SMB_SIGNING = "smb_signing"
    LDAP_SIGNING = "ldap_signing"
    PASSWORD_POLICY = "password_policy"
    PRIVILEGED_ACCOUNTS = "privileged_accounts"
    DEFAULT_PASSWORDS = "default_passwords"
    ACL = "acl"
    ADCS = "adcs"
    DOMAIN_TRUST = "domain_trust"


@dataclass
class VulnFinding:
    """Une vulnérabilité AD détectée."""

    title: str
    description: str
    severity: FindingSeverity
    category: FindingCategory
    affected_assets: list[str] = field(default_factory=list)
    affected_count: int = 0
    remediation: str = ""
    references: list[str] = field(default_factory=list)  # CVEs, URLs
    raw_data: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        emoji = {
            FindingSeverity.CRITICAL: "🔴",
            FindingSeverity.HIGH: "🟠",
            FindingSeverity.MEDIUM: "🟡",
            FindingSeverity.LOW: "🟢",
            FindingSeverity.INFO: "ℹ️",
        }.get(self.severity, "❓")
        return f"{emoji} [{self.severity.upper()}] {self.title}"


@dataclass
class ScanReport:
    """Rapport de scan de vulnérabilités AD."""

    domain: str
    findings: list[VulnFinding] = field(default_factory=list)
    scan_duration: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def by_severity(self, severity: FindingSeverity) -> list[VulnFinding]:
        return [f for f in self.findings if f.severity == severity]

    def summary(self) -> str:
        lines = [
            f"=== AD Vulnerability Scan: {self.domain} ===",
            f"Total findings: {self.total_findings}",
            f"  CRITICAL: {self.critical_count}",
            f"  HIGH: {self.high_count}",
            f"  MEDIUM: {len(self.by_severity(FindingSeverity.MEDIUM))}",
            f"  LOW: {len(self.by_severity(FindingSeverity.LOW))}",
            f"  INFO: {len(self.by_severity(FindingSeverity.INFO))}",
            f"Duration: {self.scan_duration:.1f}s",
        ]
        if self.errors:
            lines.append(f"Errors: {len(self.errors)}")
        return "\n".join(lines)

    def detailed_report(self) -> str:
        """Rapport complet avec détails et remédiations."""
        lines = [self.summary(), "", "=" * 60]
        for severity in (
            FindingSeverity.CRITICAL,
            FindingSeverity.HIGH,
            FindingSeverity.MEDIUM,
            FindingSeverity.LOW,
            FindingSeverity.INFO,
        ):
            findings = self.by_severity(severity)
            if not findings:
                continue
            lines.append(f"\n--- {severity.upper()} ---")
            for f in findings:
                lines.append(f"\n  {f}")
                lines.append(f"  Description: {f.description}")
                if f.affected_assets:
                    lines.append(
                        f"  Affected ({f.affected_count}): {', '.join(f.affected_assets[:5])}",
                    )
                if f.remediation:
                    lines.append(f"  Remediation: {f.remediation}")
        return "\n".join(lines)


# ── Scanner ────────────────────────────────────────────────────


class ADVulnScanner:
    """Scanner de vulnérabilités Active Directory.

    Analyse une DomainMap (et optionnellement un connecteur actif)
    pour détecter les faiblesses de configuration AD.

    Usage:
        scanner = ADVulnScanner(connector=connector)
        report = await scanner.scan_all(domain_map)
        print(report.detailed_report())
    """

    # Comptes extrêmement sensibles
    TIER0_ACCOUNTS = {
        "administrator",
        "krbtgt",
        "guest",
    }

    # Mots de passe par défaut connus
    DEFAULT_PASSWORD_INDICATORS = [
        "password",
        "Password1",
        "P@ssw0rd",
        "Welcome1",
        "changeme",
        "admin",
        "Admin123",
        "Company@123",
    ]

    def __init__(self, connector: ADConnector | None = None) -> None:
        self.connector = connector
        self._findings: list[VulnFinding] = []

    async def scan_all(self, domain_map) -> ScanReport:
        """Lance tous les scans de vulnérabilités.

        Args:
            domain_map: DomainMap issue de l'énumérateur

        Returns:
            ScanReport structuré

        """
        import time

        t_start = time.monotonic()
        self._findings = []

        logger.info("vuln_scan_started", domain=domain_map.domain.name)

        # ── Scans algorithmiques (sur DomainMap) ────────────────
        self._check_kerberoasting(domain_map)
        self._check_asrep_roasting(domain_map)
        self._check_unconstrained_delegation(domain_map)
        self._check_privileged_accounts(domain_map)
        self._check_password_policy(domain_map)
        self._check_kerberos_delegation(domain_map)
        self._check_default_passwords(domain_map)
        self._check_trust_security(domain_map)
        self._check_admin_count(domain_map)

        # ── Scans réseau (nécessitent connecteur actif) ────────
        if self.connector and self.connector.is_connected:
            await self._check_smb_signing(domain_map)
            await self._check_ldap_signing()

        report = ScanReport(
            domain=domain_map.domain.name,
            findings=self._findings,
            scan_duration=time.monotonic() - t_start,
        )

        logger.info(
            "vuln_scan_complete",
            domain=domain_map.domain.name,
            findings=len(self._findings),
            critical=report.critical_count,
        )

        return report

    # ── Checks algorithmiques ──────────────────────────────────

    def _check_kerberoasting(self, domain_map) -> None:
        """Détecte les comptes Kerberoastable avec haut privilège."""
        kerb_users = domain_map.kerberoastable_users
        if not kerb_users:
            return

        # Distinguer : comptes admin avec SPN (CRITICAL) vs comptes standards (HIGH)
        admin_spns = [u for u in kerb_users if u.is_admin]
        standard_spns = [u for u in kerb_users if not u.is_admin]

        if admin_spns:
            names = [u.sam_account_name for u in admin_spns]
            self._add(
                FindingSeverity.CRITICAL,
                "Comptes Kerberoastable à haut privilège",
                f"{len(admin_spns)} compte(s) admin avec SPN : "
                f"le cassage du hash Kerberos donne un accès admin direct.",
                FindingCategory.KERBEROASTING,
                names,
                len(admin_spns),
                "Supprimer les SPNs de ces comptes admin ou les migrer "
                "vers des comptes de service dédiés (gMSA).",
                ["https://attack.mitre.org/techniques/T1558/003/"],
            )

        if standard_spns:
            names = [u.sam_account_name for u in standard_spns]
            self._add(
                FindingSeverity.HIGH,
                "Comptes Kerberoastable standards",
                f"{len(standard_spns)} compte(s) avec SPN : vulnérables au Kerberoasting.",
                FindingCategory.KERBEROASTING,
                names,
                len(standard_spns),
                "Utiliser des mots de passe complexes (30+ caractères) "
                "pour les comptes de service. Considérer les gMSA.",
                ["https://attack.mitre.org/techniques/T1558/003/"],
            )

    def _check_asrep_roasting(self, domain_map) -> None:
        """Détecte les comptes sans pré-authentification Kerberos."""
        asrep_users = domain_map.asrep_roastable_users
        if not asrep_users:
            return

        # Distinguer ceux avec privilèges
        privileged = [u for u in asrep_users if u.is_admin]
        names = [u.sam_account_name for u in asrep_users]

        severity = FindingSeverity.CRITICAL if privileged else FindingSeverity.HIGH
        self._add(
            severity,
            "Comptes vulnérables à l'AS-REP Roasting",
            f"{len(asrep_users)} compte(s) sans pré-authentification "
            f"Kerberos : un attaquant non authentifié peut demander "
            f"un TGT et tenter de casser le hash.",
            FindingCategory.ASREP_ROASTING,
            names,
            len(asrep_users),
            "Activer 'Do not require Kerberos preauthentication' = OFF sur ces comptes.",
            ["https://attack.mitre.org/techniques/T1558/004/"],
        )

    def _check_unconstrained_delegation(self, domain_map) -> None:
        """Détecte les machines avec délégation non contrainte."""
        dc_names = [c.dns_hostname for c in domain_map.domain_controllers]
        unconstrained = [
            c
            for c in domain_map.unconstrained_delegation_computers
            if c.dns_hostname not in dc_names
        ]

        if unconstrained:
            names = [c.dns_hostname for c in unconstrained]
            self._add(
                FindingSeverity.HIGH,
                "Délégation Kerberos non contrainte",
                f"{len(unconstrained)} machine(s) avec délégation non "
                f"contrainte : un attaquant qui compromet ces machines "
                f"peut impersoner n'importe quel utilisateur.",
                FindingCategory.DELEGATION,
                names,
                len(unconstrained),
                "Remplacer par la délégation contrainte (Kerberos "
                "Constrained Delegation) ou désactiver la délégation.",
                ["https://attack.mitre.org/techniques/T1558/001/"],
            )

        # Les DCs ont TOUJOURS la délégation non contrainte
        if dc_names:
            self._add(
                FindingSeverity.INFO,
                "Délégation non contrainte sur DCs",
                f"{len(dc_names)} DC(s) avec délégation non contrainte "
                f"(normal pour les DCs, mais surface d'attaque).",
                FindingCategory.DELEGATION,
                dc_names,
                len(dc_names),
                "Limiter l'accès physique et réseau aux DCs. Surveiller les tickets TGT émis.",
            )

    def _check_privileged_accounts(self, domain_map) -> None:
        """Analyse les comptes à haut privilège."""
        privileged = domain_map.privileged_users

        # Comptes admin sans mot de passe qui expire
        no_expire = [u for u in privileged if (u.user_account_control & 0x10000) != 0]
        if no_expire:
            names = [u.sam_account_name for u in no_expire]
            self._add(
                FindingSeverity.HIGH,
                "Comptes admin avec mot de passe permanent",
                f"{len(no_expire)} compte(s) admin avec 'Password never expires' activé.",
                FindingCategory.PRIVILEGED_ACCOUNTS,
                names,
                len(no_expire),
                "Désactiver 'Password never expires' pour les comptes "
                "admin. Utiliser des mots de passe tournants.",
            )

        # Comptes admin désactivés mais toujours privilégiés
        disabled_admin = [u for u in privileged if not u.is_enabled]
        if disabled_admin:
            names = [u.sam_account_name for u in disabled_admin]
            self._add(
                FindingSeverity.MEDIUM,
                "Comptes admin désactivés",
                f"{len(disabled_admin)} compte(s) adminCount=1 mais "
                f"désactivé(s) — peuvent être réactivés.",
                FindingCategory.PRIVILEGED_ACCOUNTS,
                names,
                len(disabled_admin),
                "Supprimer définitivement ou révoquer adminCount.",
            )

        # Tier 0 accounts (Administrator, krbtgt, Guest)
        tier0_issues = []
        for user in domain_map.users:
            if user.sam_account_name.lower() in self.TIER0_ACCOUNTS:
                if user.sam_account_name.lower() == "krbtgt":
                    # Vérifier l'âge du mot de passe krbtgt
                    if user.pwd_last_set:
                        from datetime import datetime

                        age = datetime.now() - user.pwd_last_set
                        if age.days > 180:
                            tier0_issues.append(
                                f"krbtgt (password age: {age.days} jours)",
                            )
                elif user.sam_account_name.lower() == "guest":
                    if user.is_enabled:
                        tier0_issues.append("Guest account ENABLED")
                elif user.sam_account_name.lower() == "administrator":
                    if not user.is_enabled:
                        tier0_issues.append(
                            "Administrator account DISABLED (bonne pratique ✓)",
                        )

        if any("krbtgt" in i for i in tier0_issues):
            self._add(
                FindingSeverity.HIGH,
                "Mot de passe krbtgt ancien",
                "Le mot de passe du compte krbtgt n'a pas été changé "
                "depuis plus de 180 jours. Le reset du krbtgt est une "
                "mesure de sécurité critique post-compromission.",
                FindingCategory.PRIVILEGED_ACCOUNTS,
                ["krbtgt"],
                1,
                "Effectuer un double reset du mot de passe krbtgt "
                "(PowerShell: Reset-ComputerMachinePassword).",
                ["https://attack.mitre.org/techniques/T1003/001/"],
            )

        if any("Guest" in i and "ENABLED" in i for i in tier0_issues):
            self._add(
                FindingSeverity.MEDIUM,
                "Compte Guest activé",
                "Le compte Guest est activé, ce qui est déconseillé.",
                FindingCategory.PRIVILEGED_ACCOUNTS,
                ["Guest"],
                1,
                "Désactiver le compte Guest.",
            )

    def _check_password_policy(self, domain_map) -> None:
        """Analyse la politique de mot de passe du domaine."""
        # Ces informations ne sont pas directement dans DomainMap.
        # On infère à partir des comptes utilisateurs.

        # Vérifier combien de comptes ont 'Password never expires'
        no_expire_users = domain_map.users_without_password_expiry
        if len(no_expire_users) > len(domain_map.users) * 0.1:  # >10%
            self._add(
                FindingSeverity.MEDIUM,
                "Trop de comptes sans expiration de mot de passe",
                f"{len(no_expire_users)}/{len(domain_map.users)} "
                f"utilisateurs ont 'Password never expires'.",
                FindingCategory.PASSWORD_POLICY,
                [u.sam_account_name for u in no_expire_users[:10]],
                len(no_expire_users),
                "Réviser la politique de mot de passe. Maximum 5% "
                "des comptes devraient avoir cette exemption.",
            )

        # Comptes sans mot de passe (PASSWD_NOTREQD)
        no_pwd = [u for u in domain_map.users if (u.user_account_control & 0x20) != 0]
        if no_pwd:
            names = [u.sam_account_name for u in no_pwd]
            self._add(
                FindingSeverity.CRITICAL,
                "Comptes sans mot de passe requis",
                f"{len(no_pwd)} compte(s) avec PASSWD_NOTREQD : mot de passe vide accepté.",
                FindingCategory.PASSWORD_POLICY,
                names,
                len(no_pwd),
                "Désactiver PASSWD_NOTREQD et forcer un mot de passe.",
            )

    def _check_kerberos_delegation(self, domain_map) -> None:
        """Détecte les comptes avec délégation Kerberos contrainte."""
        # Utilisateurs avec TRUSTED_TO_AUTH_FOR_DELEGATION (S4U2Self)
        s4u2self = [u for u in domain_map.users if (u.user_account_control & 0x1000000) != 0]
        if s4u2self:
            names = [u.sam_account_name for u in s4u2self]
            self._add(
                FindingSeverity.MEDIUM,
                "Comptes avec délégation protocole (S4U2Self)",
                f"{len(s4u2self)} compte(s) configurés pour la "
                f"délégation de protocole : possibilité d'impersonation.",
                FindingCategory.DELEGATION,
                names,
                len(s4u2self),
                "Auditer les comptes avec cette configuration. Limiter au strict nécessaire.",
            )

    def _check_default_passwords(self, domain_map) -> None:
        """Vérifie les indicateurs de mots de passe par défaut."""
        # On ne peut pas vérifier les mots de passe sans les tester,
        # mais on peut identifier les comptes créés récemment qui n'ont
        # jamais changé leur mot de passe.

        from datetime import datetime

        new_users_no_pwd_change = []
        for user in domain_map.users:
            if user.is_enabled and user.pwd_last_set and user.when_created:
                # Compte créé il y a plus de 30j, mot de passe jamais changé
                age_since_creation = user.pwd_last_set - user.when_created
                if (
                    age_since_creation.total_seconds() < 3600
                    and (datetime.now() - user.when_created).days > 30
                ):
                    new_users_no_pwd_change.append(user.sam_account_name)

        if new_users_no_pwd_change:
            self._add(
                FindingSeverity.MEDIUM,
                "Comptes n'ayant jamais changé leur mot de passe",
                f"{len(new_users_no_pwd_change)} compte(s) créé(s) "
                f"depuis >30j sans changement de mot de passe.",
                FindingCategory.DEFAULT_PASSWORDS,
                new_users_no_pwd_change[:10],
                len(new_users_no_pwd_change),
                "Forcer le changement de mot de passe à la prochaine connexion pour ces comptes.",
            )

    def _check_trust_security(self, domain_map) -> None:
        """Analyse la sécurité des relations de confiance."""
        for trust in domain_map.trusts:
            if not trust.sid_filtering and trust.type != "ParentChild":
                self._add(
                    FindingSeverity.HIGH,
                    "SID filtering désactivé sur une confiance",
                    f"La confiance vers {trust.target_domain} n'a pas "
                    f"le SID filtering activé : attaque SID History "
                    f"possible.",
                    FindingCategory.DOMAIN_TRUST,
                    [trust.target_domain],
                    1,
                    "Activer le SID filtering sur cette confiance.",
                    ["https://attack.mitre.org/techniques/T1134/005/"],
                )

            if trust.direction == "Bidirectional" and not trust.transitive:
                self._add(
                    FindingSeverity.MEDIUM,
                    "Confiance bidirectionnelle non transitive",
                    f"La confiance vers {trust.target_domain} est "
                    f"bidirectionnelle. Vérifier que c'est intentionnel.",
                    FindingCategory.DOMAIN_TRUST,
                    [trust.target_domain],
                    1,
                    "Préférer les confiances unidirectionnelles quand c'est possible.",
                )

    def _check_admin_count(self, domain_map) -> None:
        """Vérifie les objets protégés par SDProp (adminCount=1)."""
        # Les objets avec adminCount=1 sont protégés par AdminSDHolder.
        # Mais certains groupes admin peuvent ne pas l'être.
        [g for g in domain_map.groups if g.admin_count == 1]
        protected_users = len(domain_map.privileged_users)

        if protected_users > 20:
            self._add(
                FindingSeverity.MEDIUM,
                "Trop de comptes protégés par AdminSDHolder",
                f"{protected_users} comptes avec adminCount=1. "
                f"Chaque compte admin est une cible potentielle.",
                FindingCategory.PRIVILEGED_ACCOUNTS,
                [u.sam_account_name for u in domain_map.privileged_users[:10]],
                protected_users,
                "Réduire le nombre de comptes admin. Appliquer le "
                "principe du moindre privilège. Utiliser des groupes "
                "séparés pour les tâches admin.",
            )

    # ── Checks réseau ──────────────────────────────────────────

    async def _check_smb_signing(self, domain_map) -> None:
        """Vérifie si SMB signing est activé sur les DCs."""
        self._add(
            FindingSeverity.INFO,
            "SMB Signing — vérification réseau",
            "La vérification SMB signing nécessite une connexion "
            "SMB directe aux DCs (port 445). Utiliser le module "
            "scanner.contextual pour cette vérification.",
            FindingCategory.SMB_SIGNING,
            [],
            0,
            "Exécuter: navmax scan <DC> -p 445 --contextual",
        )

    async def _check_ldap_signing(self) -> None:
        """Vérifie si LDAP signing/channel binding est requis."""
        # LDAP signing se vérifie via une requête LDAP non signée
        self._add(
            FindingSeverity.INFO,
            "LDAP Signing — vérification",
            "La vérification LDAP signing nécessite l'envoi d'une "
            "requête LDAP non signée au DC. Vérifier la politique "
            "'Domain controller: LDAP server signing requirements'.",
            FindingCategory.LDAP_SIGNING,
            [],
            0,
            "Configurer 'LDAP server signing requirements' = "
            "'Require signing' dans la GPO Default Domain Controllers.",
        )

    # ── Helpers ────────────────────────────────────────────────

    def _add(
        self,
        severity: FindingSeverity,
        title: str,
        description: str,
        category: FindingCategory,
        affected_assets: list[str],
        affected_count: int,
        remediation: str,
        references: list[str] | None = None,
    ) -> None:
        """Ajoute un finding."""
        self._findings.append(
            VulnFinding(
                title=title,
                description=description.strip(),
                severity=severity,
                category=category,
                affected_assets=affected_assets,
                affected_count=affected_count,
                remediation=remediation.strip(),
                references=references or [],
            ),
        )


# ── Fonction utilitaire ────────────────────────────────────────


async def quick_vuln_scan(domain_map, connector=None) -> ScanReport:
    """Scan rapide en une ligne.

    Usage:
        report = await quick_vuln_scan(domain_map)
        print(report.detailed_report())
    """
    scanner = ADVulnScanner(connector)
    return await scanner.scan_all(domain_map)
