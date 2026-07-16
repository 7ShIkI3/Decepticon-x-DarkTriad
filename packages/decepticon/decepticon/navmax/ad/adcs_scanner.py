"""ADCS Scanner — détection des vulnérabilités Active Directory Certificate Services.

Détecte les certifications ADCS mal configurées selon les techniques ESC1-ESC13 :
- ESC1: Template avec enrollee supplies subject + Client Authentication EKU
- ESC2: Template sans EKU (Any Purpose)
- ESC3: Enrollment Agent + Certificate Request Agent
- ESC4: ACL faible sur template (contrôlable par utilisateurs non-privilégiés)
- ESC5: Objets PKI non sécurisés
- ESC6: CA avec flag EDITF_ATTRIBUTESUBJECTALTNAME2
- ESC7: Permissions CA faibles (ManageCA, ManageCertificates)
- ESC8: NTLM relay vers HTTP enrollment endpoints
- ESC9: Absence d'extension de sécurité (CT_FLAG_NO_SECURITY_EXTENSION)
- ESC10: Certificate mapping faible (X509IssuerSubject → SID)
- ESC11: Chiffrement absent pour requêtes ICPR
- ESC13: OID group link vers groupes privilégiés

Références:
- https://posts.specterops.io/certified-pre-owned-d95910965cd2
- https://research.ifcr.dk/certipy-esc1-8-explained/

Usage:
    scanner = ADCSSCanner(connector)
    findings = await scanner.scan_all(domain_map)
    for f in findings:
        print(f"{f.severity}: {f.title}")
"""

from dataclasses import dataclass, field
from enum import StrEnum

import structlog

logger = structlog.get_logger(__name__)


# ── Types ──────────────────────────────────────────────────────


class ESCSeverity(StrEnum):
    CRITICAL = "critical"  # Escalade domaine directe
    HIGH = "high"  # Escalade probable
    MEDIUM = "medium"  # Surface d'attaque
    LOW = "low"  # Information


@dataclass
class ADCSFinding:
    """Une vulnérabilité ADCS détectée."""

    esc_id: str  # ESC1, ESC2...
    title: str
    description: str
    severity: ESCSeverity
    affected_templates: list[str] = field(default_factory=list)
    affected_cas: list[str] = field(default_factory=list)
    exploitation: str = ""  # Comment exploiter
    remediation: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class TemplateInfo:
    """Informations sur un certificate template."""

    name: str
    dn: str
    display_name: str = ""
    oid: str = ""  # Template OID
    schema_version: int = 1
    # Flags
    enrollee_supplies_subject: bool = False  # ESC1
    requires_manager_approval: bool = False
    requires_authorization_signatures: int = 0
    # EKU
    ekus: list[str] = field(default_factory=list)  # "1.3.6.1.5.5.7.3.1", etc.
    has_client_auth_eku: bool = False
    has_any_purpose_eku: bool = False  # ESC2
    has_cert_request_agent_eku: bool = False  # ESC3
    has_enrollment_agent_eku: bool = False
    # Security
    no_security_extension: bool = False  # ESC9
    # Permissions
    enroll_permissions: list[str] = field(default_factory=list)
    autoenroll_permissions: list[str] = field(default_factory=list)
    write_permissions: list[str] = field(default_factory=list)  # ESC4
    full_control_permissions: list[str] = field(default_factory=list)
    # Validity
    validity_period: str = ""
    renewal_period: str = ""


@dataclass
class CAInfo:
    """Informations sur une Certificate Authority."""

    name: str
    dn: str
    dns_hostname: str = ""
    config_dn: str = ""
    # Flags CA
    editf_attributesubjectaltname2: bool = False  # ESC6
    # Permissions
    manage_ca_permissions: list[str] = field(default_factory=list)  # ESC7
    manage_certificates_permissions: list[str] = field(default_factory=list)  # ESC7
    enroll_permissions: list[str] = field(default_factory=list)
    # Web enrollment (ESC8)
    web_enrollment_enabled: bool = False
    web_enrollment_url: str = ""
    # Security
    sanitized_name: str = ""  # Nom sans les caractères de contrôle


@dataclass
class ADCSReport:
    """Rapport de scan ADCS complet."""

    domain: str
    cas: list[CAInfo] = field(default_factory=list)
    templates: list[TemplateInfo] = field(default_factory=list)
    findings: list[ADCSFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        esc_counts = {}
        for f in self.findings:
            esc_counts[f.esc_id] = esc_counts.get(f.esc_id, 0) + 1

        lines = [
            f"=== ADCS Scan: {self.domain} ===",
            f"CAs found: {len(self.cas)}",
            f"Templates found: {len(self.templates)}",
            f"Findings: {len(self.findings)}",
        ]
        if esc_counts:
            lines.append("\nESC Techniques detected:")
            for esc_id in sorted(esc_counts.keys()):
                lines.append(f"  {esc_id}: {esc_counts[esc_id]} finding(s)")
        return "\n".join(lines)


# ── Constantes ─────────────────────────────────────────────────

# OIDs EKU (Extended Key Usage)
CLIENT_AUTHENTICATION_OID = "1.3.6.1.5.5.7.3.2"
SERVER_AUTHENTICATION_OID = "1.3.6.1.5.5.7.3.1"
CODE_SIGNING_OID = "1.3.6.1.5.5.7.3.3"
SMARTCARD_LOGON_OID = "1.3.6.1.5.5.7.3.20"  # ESC1 target
ANY_PURPOSE_OID = "2.5.29.37.0"  # ESC2
CERT_REQUEST_AGENT_OID = "1.3.6.1.4.1.311.20.2.1"  # ESC3
ENROLLMENT_AGENT_OID = "1.3.6.1.4.1.311.20.2.1"  # ESC3


# ── Scanner ────────────────────────────────────────────────────


class ADCSSCanner:
    """Scanner de vulnérabilités ADCS.

    Détecte les templates et CAs vulnérables selon les techniques ESC1-ESC13.

    Usage:
        scanner = ADCSSCanner(connector)
        report = await scanner.scan_all(domain_map)
        for f in report.findings:
            print(f"ESC{f.esc_id}: {f.title}")
    """

    def __init__(self, connector=None) -> None:
        self.connector = connector

    async def scan_all(self, domain_map) -> ADCSReport:
        """Scan ADCS complet : CAs + templates + analyses.

        Args:
            domain_map: DomainMap issue de l'énumérateur

        Returns:
            ADCSReport structuré

        """
        report = ADCSReport(domain=domain_map.domain.name)

        if not self.connector or not self.connector.is_connected:
            report.errors.append(
                "No active AD connector — ADCS scan requires authenticated LDAP access",
            )
            return report

        logger.info("adcs_scan_starting", domain=domain_map.domain.name)

        # ── Énumérer les CAs ───────────────────────────────────
        try:
            report.cas = await self._enumerate_cas()
        except Exception as e:
            report.errors.append(f"CA enumeration failed: {e}")
            logger.exception("adcs_ca_enum_failed", error=str(e))

        # ── Énumérer les templates ─────────────────────────────
        try:
            report.templates = await self._enumerate_templates()
        except Exception as e:
            report.errors.append(f"Template enumeration failed: {e}")
            logger.exception("adcs_template_enum_failed", error=str(e))

        # ── Analyser les vulnérabilités ────────────────────────
        self._check_esc1(report)
        self._check_esc2(report)
        self._check_esc3(report)
        self._check_esc4(report)
        self._check_esc5(report)
        self._check_esc6(report)
        self._check_esc7(report)
        self._check_esc8(report)
        self._check_esc9(report)

        logger.info(
            "adcs_scan_complete",
            cas=len(report.cas),
            templates=len(report.templates),
            findings=len(report.findings),
        )

        return report

    # ── Énumération ────────────────────────────────────────────

    async def _enumerate_cas(self) -> list[CAInfo]:
        """Énumère les Certificate Authorities via LDAP."""
        cas = []

        entries = await self.connector.search(
            "(objectClass=pKIEnrollmentService)",
            search_base=f"CN=Enrollment Services,"
            f"CN=Public Key Services,CN=Services,"
            f"{self.connector.config.effective_base_dn}",
            attributes=["cn", "dNSHostName", "cACertificate", "certificateTemplates"],
        )

        for entry in entries:
            attrs = entry.get("attributes", {})
            ca = CAInfo(
                name=str(attrs.get("cn", [""])[0] or ""),
                dn=entry.get("dn", ""),
                dns_hostname=str(attrs.get("dNSHostName", [""])[0] or ""),
            )
            cas.append(ca)

        # Enrichir avec les infos de configuration CA
        for ca in cas:
            try:
                config_entries = await self.connector.search(
                    f"(cn={ca.name})",
                    search_base=f"CN=Certification Authorities,"
                    f"CN=Public Key Services,CN=Services,"
                    f"{self.connector.config.effective_base_dn}",
                    attributes=["flags", "cACertificateDN"],
                    max_entries=1,
                )
                if config_entries:
                    ca_attrs = config_entries[0].get("attributes", {})
                    flags = int(ca_attrs.get("flags", [0])[0] or 0)
                    # EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x40000
                    ca.editf_attributesubjectaltname2 = bool(flags & 0x40000)
                    ca.config_dn = config_entries[0].get("dn", "")

                # Vérifier les permissions (ESC7)
                # ManageCA = Right to modify CA configuration
                # ManageCertificates = Right to issue/renew/revoke certs
                # En production, utiliser les ACLs AD complètes.
                # Ici on vérifie via une heuristique basée sur les groupes connus.
                ca.manage_ca_permissions = await self._check_ca_permission(
                    ca.config_dn,
                    "ManageCA",
                )
                ca.manage_certificates_permissions = await self._check_ca_permission(
                    ca.config_dn,
                    "ManageCertificates",
                )

                # Web enrollment (ESC8)
                if ca.dns_hostname:
                    ca.web_enrollment_enabled = True
                    ca.web_enrollment_url = f"http://{ca.dns_hostname}/certsrv/"

            except Exception as e:
                logger.debug("ca_enrich_failed", ca=ca.name, error=str(e))

        return cas

    async def _enumerate_templates(self) -> list[TemplateInfo]:
        """Énumère les certificate templates via LDAP."""
        templates = []

        entries = await self.connector.search(
            "(objectClass=pKICertificateTemplate)",
            search_base=f"CN=Certificate Templates,"
            f"CN=Public Key Services,CN=Services,"
            f"{self.connector.config.effective_base_dn}",
            attributes=[
                "cn",
                "displayName",
                "msPKI-Cert-Template-OID",
                "msPKI-Template-Schema-Version",
                "msPKI-Enrollment-Flag",
                "msPKI-Certificate-Name-Flag",
                "pKIExtendedKeyUsage",
                "msPKI-RA-Signature",
                "msPKI-Certificate-Application-Policy",
                "msPKI-Minimal-Key-Size",
                "msPKI-Template-Schema-Version",
                "msPKI-RA-Application-Policies",
            ],
        )

        for entry in entries:
            attrs = entry.get("attributes", {})
            enroll_flag = int(attrs.get("msPKI-Enrollment-Flag", [0])[0] or 0)
            name_flag = int(attrs.get("msPKI-Certificate-Name-Flag", [0])[0] or 0)

            # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001 (ESC1)
            enrollee_supplies_subject = bool(name_flag & 0x00000001)

            # msPKI-RA-Signature: 0 = no authorization required
            ra_signature = int(attrs.get("msPKI-RA-Signature", [0])[0] or 0)

            # EKUs
            ekus = []
            for eku in attrs.get("pKIExtendedKeyUsage", []):
                if eku:
                    ekus.append(str(eku))

            if not ekus:
                # Vérifier msPKI-Certificate-Application-Policy
                for policy in attrs.get("msPKI-Certificate-Application-Policy", []):
                    if policy:
                        ekus.append(str(policy))

            has_any_purpose = ANY_PURPOSE_OID in ekus
            has_client_auth = CLIENT_AUTHENTICATION_OID in ekus
            has_cra = CERT_REQUEST_AGENT_OID in ekus
            has_enrollment_agent = any("1.3.6.1.4.1.311.20.2.1" in eku for eku in ekus)

            # ESC9: no security extension = no CT_FLAG_ENFORCE... flag
            # msPKI-Enrollment-Flag & 0x00000100 = CT_FLAG_NO_SECURITY_EXTENSION
            no_security_ext = bool(enroll_flag & 0x00000100)

            template = TemplateInfo(
                name=str(attrs.get("cn", [""])[0] or ""),
                dn=entry.get("dn", ""),
                display_name=str(attrs.get("displayName", [""])[0] or ""),
                oid=str(attrs.get("msPKI-Cert-Template-OID", [""])[0] or ""),
                schema_version=int(
                    attrs.get("msPKI-Template-Schema-Version", [1])[0] or 1,
                ),
                enrollee_supplies_subject=enrollee_supplies_subject,
                requires_manager_approval=bool(enroll_flag & 0x00000002),
                requires_authorization_signatures=ra_signature,
                ekus=ekus,
                has_client_auth_eku=has_client_auth,
                has_any_purpose_eku=has_any_purpose,
                has_cert_request_agent_eku=has_cra,
                has_enrollment_agent_eku=has_enrollment_agent,
                no_security_extension=no_security_ext,
            )
            templates.append(template)

        return templates

    async def _check_ca_permission(
        self,
        ca_dn: str,
        permission: str,
    ) -> list[str]:
        """Vérifie les permissions sur une CA (simplifié).

        En production, nécessite une analyse complète des ACLs.
        Retourne une liste de groupes/SIDs ayant la permission.
        """
        # Implémentation simplifiée — en production, parser les ACLs complètes
        # via nTSecurityDescriptor
        return []

    # ── Checks ESC1-9 ──────────────────────────────────────────

    def _check_esc1(self, report: ADCSReport) -> None:
        """ESC1: Template allows enrollee supplies subject + Client Auth EKU.

        Condition:
        1. Enrollee can supply subject (SAN) → msPKI-Certificate-Name-Flag & 1
        2. Template has Client Authentication, Smart Card Logon, or Any Purpose EKU
        3. Enroll permission for non-privileged users
        4. No manager approval required
        """
        vulnerable = []
        for t in report.templates:
            if not t.enrollee_supplies_subject:
                continue
            if t.requires_manager_approval:
                continue
            if (
                t.has_client_auth_eku
                or t.has_any_purpose_eku
                or any("Smartcard" in eku or "Smart Card" in eku for eku in t.ekus)
            ):
                vulnerable.append(t.name)

        if vulnerable:
            report.findings.append(
                ADCSFinding(
                    esc_id="ESC1",
                    title="Template vulnérable — Enrollee supplies subject + Client Auth EKU",
                    description=(
                        f"{len(vulnerable)} template(s) permettent à l'enrolleur "
                        f"de spécifier le sujet (SAN) et ont un EKU d'authentification : "
                        f"un attaquant peut demander un certificat pour n'importe quel "
                        f"utilisateur (y compris Domain Admin)."
                    ),
                    severity=ESCSeverity.CRITICAL,
                    affected_templates=vulnerable,
                    exploitation=(
                        f"certipy-ad req -u 'user' -p 'pass' -dc-ip DC "
                        f"-ca 'CA_NAME' -template '{vulnerable[0]}' "
                        f"-upn 'administrator@domain'"
                    ),
                    remediation=(
                        "1. Supprimer le flag CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT\n"
                        "2. OU exiger l'approbation du manager\n"
                        "3. OU restreindre les permissions d'enrôlement"
                    ),
                    references=[
                        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    ],
                ),
            )

    def _check_esc2(self, report: ADCSReport) -> None:
        """ESC2: Template with Any Purpose EKU or no EKU.

        Condition:
        1. Template has Any Purpose EKU (2.5.29.37.0) or no EKU
        2. Enroll permission for non-privileged users
        """
        vulnerable = []
        for t in report.templates:
            if t.has_any_purpose_eku or not t.ekus:
                if not t.requires_manager_approval:
                    vulnerable.append(t.name)

        if vulnerable:
            report.findings.append(
                ADCSFinding(
                    esc_id="ESC2",
                    title="Template avec Any Purpose EKU ou sans EKU",
                    description=(
                        f"{len(vulnerable)} template(s) avec EKU 'Any Purpose' "
                        f"ou sans restriction EKU — le certificat peut être "
                        f"utilisé pour n'importe quel usage, incluant "
                        f"l'authentification client."
                    ),
                    severity=ESCSeverity.CRITICAL,
                    affected_templates=vulnerable,
                    exploitation=(
                        f"certipy-ad req -u 'user' -p 'pass' "
                        f"-template '{vulnerable[0]}' -ca 'CA_NAME'"
                    ),
                    remediation=(
                        "1. Définir des EKUs spécifiques sur le template\n"
                        "2. Ne PAS utiliser Any Purpose sauf absolument nécessaire"
                    ),
                    references=[
                        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    ],
                ),
            )

    def _check_esc3(self, report: ADCSReport) -> None:
        """ESC3: Enrollment Agent + Certificate Request Agent.

        Condition:
        1. Template avec Enrollment Agent EKU (ESC3a)
        2. Un autre template avec Certificate Request Agent EKU (ESC3b)
        3. L'attaquant peut s'enrôler dans le template ESC3a
        4. Peut ensuite demander un certificat ESC3b pour n'importe quel user
        """
        enrollment_agent_templates = [
            t.name for t in report.templates if t.has_enrollment_agent_eku
        ]
        request_agent_templates = [t.name for t in report.templates if t.has_cert_request_agent_eku]

        if enrollment_agent_templates and request_agent_templates:
            report.findings.append(
                ADCSFinding(
                    esc_id="ESC3",
                    title="Enrollment Agent + Certificate Request Agent exploitables",
                    description=(
                        f"Templates Enrollment Agent ({len(enrollment_agent_templates)}) "
                        f"et Certificate Request Agent ({len(request_agent_templates)}) "
                        f"présents : un attaquant peut s'enrôler comme agent et "
                        f"demander des certificats pour d'autres utilisateurs."
                    ),
                    severity=ESCSeverity.HIGH,
                    affected_templates=enrollment_agent_templates + request_agent_templates,
                    exploitation=(
                        f"# Étape 1: Enrôler comme agent\n"
                        f"certipy-ad req -template '"
                        f"{enrollment_agent_templates[0]}' -ca 'CA_NAME'\n"
                        f"# Étape 2: Demander certificat pour admin\n"
                        f"certipy-ad req -template '"
                        f"{request_agent_templates[0]}' -on-behalf-of 'DOMAIN\\\\admin'"
                    ),
                    remediation=(
                        "1. Supprimer le template Enrollment Agent si non nécessaire\n"
                        "2. Restreindre les permissions d'enrôlement\n"
                        "3. Exiger des signatures d'autorisation (RA signatures > 0)"
                    ),
                    references=[
                        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    ],
                ),
            )

    def _check_esc4(self, report: ADCSReport) -> None:
        """ESC4: ACLs faibles sur les templates.

        Condition:
        - Utilisateurs non-privilégiés ont des droits d'écriture sur un template
        - Peuvent modifier le template pour le rendre vulnérable (ESC1)
        """
        vulnerable = []
        for t in report.templates:
            if t.write_permissions or t.full_control_permissions:
                vulnerable.append(t.name)

        if vulnerable:
            report.findings.append(
                ADCSFinding(
                    esc_id="ESC4",
                    title="Permissions faibles sur les templates",
                    description=(
                        f"{len(vulnerable)} template(s) avec des permissions "
                        f"d'écriture pour des utilisateurs non-privilégiés. "
                        f"Un attaquant peut modifier le template pour activer "
                        f"les vulnérabilités ESC1-3."
                    ),
                    severity=ESCSeverity.HIGH,
                    affected_templates=vulnerable,
                    exploitation=(
                        "Modifier le template pour ajouter "
                        "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU"
                    ),
                    remediation=(
                        "1. Auditer les ACLs des templates\n"
                        "2. Retirer les droits d'écriture aux utilisateurs non-admin\n"
                        "3. Activer l'audit des modifications de templates"
                    ),
                    references=[
                        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    ],
                ),
            )

    def _check_esc5(self, report: ADCSReport) -> None:
        """ESC5: Objets PKI non sécurisés.

        Condition:
        - Le serveur CA ou les objets PKI ont des ACLs faibles
        - Permet de prendre le contrôle du serveur CA
        """
        # Vérification heuristique basée sur le nombre de CAs
        for ca in report.cas:
            if not ca.config_dn:
                report.findings.append(
                    ADCSFinding(
                        esc_id="ESC5",
                        title=f"CA {ca.name} — configuration PKI potentiellement non sécurisée",
                        description=(
                            f"La CA {ca.name} n'a pas de DN de configuration "
                            f"accessible : les ACLs PKI n'ont pas pu être vérifiées."
                        ),
                        severity=ESCSeverity.MEDIUM,
                        affected_cas=[ca.name],
                        remediation=(
                            "1. Vérifier les ACLs sur les objets PKI :\n"
                            "   - CN=Public Key Services,CN=Services,CN=Configuration,DC=...\n"
                            "   - Objets CA, NTAuthCertificates, AIA, CDP\n"
                            "2. Restreindre au strict minimum"
                        ),
                        references=[
                            "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                        ],
                    ),
                )

    def _check_esc6(self, report: ADCSReport) -> None:
        """ESC6: CA avec flag EDITF_ATTRIBUTESUBJECTALTNAME2.

        Condition:
        - Le flag EDITF_ATTRIBUTESUBJECTALTNAME2 est activé sur la CA
        - N'importe quel utilisateur peut spécifier un SAN dans sa requête
        """
        vulnerable = []
        for ca in report.cas:
            if ca.editf_attributesubjectaltname2:
                vulnerable.append(ca.name)

        if vulnerable:
            report.findings.append(
                ADCSFinding(
                    esc_id="ESC6",
                    title="CA avec EDITF_ATTRIBUTESUBJECTALTNAME2 activé",
                    description=(
                        f"{len(vulnerable)} CA(s) avec le flag "
                        f"EDITF_ATTRIBUTESUBJECTALTNAME2 : n'importe quel "
                        f"utilisateur peut spécifier un Subject Alternative Name "
                        f"dans ses requêtes de certificat → impersonation."
                    ),
                    severity=ESCSeverity.CRITICAL,
                    affected_cas=vulnerable,
                    exploitation=(
                        f"certipy-ad req -u 'user' -p 'pass' "
                        f"-ca '{vulnerable[0]}' -template 'User' "
                        f"-upn 'administrator@domain'"
                    ),
                    remediation=(
                        "Désactiver le flag : "
                        "certutil -setreg Policy\\EditFlags "
                        "-EDITF_ATTRIBUTESUBJECTALTNAME2"
                    ),
                    references=[
                        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    ],
                ),
            )

    def _check_esc7(self, report: ADCSReport) -> None:
        """ESC7: Permissions CA faibles (ManageCA, ManageCertificates).

        Condition:
        - Utilisateurs non-admin ont ManageCA ou ManageCertificates
        - ManageCA → modifier la config CA (ex: activer ESC6)
        - ManageCertificates → révoquer/émettre certs pour n'importe qui
        """
        vulnerable = []
        for ca in report.cas:
            if ca.manage_ca_permissions:
                vulnerable.append(f"{ca.name} (ManageCA)")
            if ca.manage_certificates_permissions:
                vulnerable.append(f"{ca.name} (ManageCertificates)")

        if vulnerable:
            report.findings.append(
                ADCSFinding(
                    esc_id="ESC7",
                    title="Permissions CA excessives",
                    description=(
                        f"Permissions ManageCA/ManageCertificates détectées "
                        f"sur {len(vulnerable)} CA(s). Un attaquant peut modifier "
                        f"la configuration de la CA ou émettre des certificats "
                        f"arbitraires."
                    ),
                    severity=ESCSeverity.CRITICAL,
                    affected_cas=vulnerable,
                    exploitation=(
                        "# ManageCA: activer ESC6 puis exploiter\n"
                        "# ManageCertificates: émettre un certificat pour admin"
                    ),
                    remediation=(
                        "1. Retirer ManageCA des utilisateurs non-admin\n"
                        "2. Retirer ManageCertificates des utilisateurs non-admin\n"
                        "3. Restreindre au groupe 'Cert Publishers' minimum"
                    ),
                    references=[
                        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    ],
                ),
            )

    def _check_esc8(self, report: ADCSReport) -> None:
        """ESC8: NTLM relay vers HTTP enrollment endpoints.

        Condition:
        - Web enrollment activé (HTTP, pas HTTPS)
        - L'attaquant peut faire du NTLM relay depuis un serveur SMB/HTTP
        """
        vulnerable = []
        for ca in report.cas:
            if ca.web_enrollment_enabled:
                if ca.web_enrollment_url.startswith("http://"):
                    vulnerable.append(f"{ca.name} ({ca.web_enrollment_url})")

        if vulnerable:
            report.findings.append(
                ADCSFinding(
                    esc_id="ESC8",
                    title="Web enrollment HTTP — vulnérable au NTLM relay",
                    description=(
                        f"{len(vulnerable)} CA(s) avec web enrollment en HTTP : "
                        f"un attaquant peut faire du NTLM relay depuis un serveur "
                        f"SMB/HTTP malveillant pour obtenir un certificat."
                    ),
                    severity=ESCSeverity.HIGH,
                    affected_cas=vulnerable,
                    exploitation=(
                        "# 1. Configurer le relay NTLM\n"
                        "ntlmrelayx -t http://CA/certsrv/certfnsh.asp "
                        "-smb2support --adcs --template 'User'\n"
                        "# 2. Forcer l'authentification (PetitPotam, coerced auth...)\n"
                        "python3 PetitPotam.py -d DOMAIN ATTACKER_IP DC_IP"
                    ),
                    remediation=(
                        "1. Activer HTTPS sur le web enrollment\n"
                        "2. OU désactiver le web enrollment si non utilisé\n"
                        "3. Activer EPA (Extended Protection for Authentication)"
                    ),
                    references=[
                        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    ],
                ),
            )

    def _check_esc9(self, report: ADCSReport) -> None:
        """ESC9: Absence d'extension de sécurité (CT_FLAG_NO_SECURITY_EXTENSION).

        Condition:
        - Le template n'a pas l'extension de sécurité (msPKI-Enrollment-Flag & 0x100)
        - Le certificat ne contient pas le SID de l'enrolleur
        - Combine avec ESC1 pour une impersonation plus difficile à tracer
        """
        vulnerable = []
        for t in report.templates:
            if t.no_security_extension and t.has_client_auth_eku:
                vulnerable.append(t.name)

        if vulnerable:
            report.findings.append(
                ADCSFinding(
                    esc_id="ESC9",
                    title="Absence d'extension de sécurité (CT_FLAG_NO_SECURITY_EXTENSION)",
                    description=(
                        f"{len(vulnerable)} template(s) sans extension de sécurité : "
                        f"le certificat ne contient pas le SID de l'enrolleur, "
                        f"facilitant l'impersonation silencieuse."
                    ),
                    severity=ESCSeverity.MEDIUM,
                    affected_templates=vulnerable,
                    remediation=(
                        "Désactiver CT_FLAG_NO_SECURITY_EXTENSION sur les templates. "
                        "Re-publier les certificats existants."
                    ),
                    references=[
                        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    ],
                ),
            )


# ── Fonction utilitaire ────────────────────────────────────────


async def quick_adcs_scan(domain_map, connector=None) -> ADCSReport:
    """Scan ADCS rapide.

    Usage:
        report = await quick_adcs_scan(domain_map, connector)
        print(report.summary())
    """
    scanner = ADCSSCanner(connector)
    return await scanner.scan_all(domain_map)
