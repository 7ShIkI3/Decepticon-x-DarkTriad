"""VulnDatabase — base de signatures CVE locale pour matcher service+version → vulnérabilités.

Format: JSON compact avec service, version_range, CVE, sévérité.
Fonctionne 100% offline — pas d'appel API externe.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path

from packaging.version import InvalidVersion, Version

from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class VulnEntry:
    """Une entrée de vulnérabilité."""

    cve: str
    service: str
    version_range: str  # ex: ">=2.4.49,<2.4.51" ou "*"
    severity: str  # info, low, medium, high, critical
    description: str
    exploit_module: str | None = None  # module NavMAX associé
    references: list[str] = None

    def __post_init__(self):
        if self.references is None:
            self.references = []


# ── Base de signatures intégrée ────────────────────────────────

DEFAULT_SIGNATURES: list[dict] = [
    # Apache HTTPd
    {
        "cve": "CVE-2021-41773",
        "service": "apache",
        "version_range": ">=2.4.49,<2.4.51",
        "severity": "high",
        "description": "Path traversal in Apache HTTP Server 2.4.49-2.4.50",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    },
    {
        "cve": "CVE-2021-42013",
        "service": "apache",
        "version_range": ">=2.4.49,<2.4.51",
        "severity": "critical",
        "description": "Path traversal + RCE in Apache 2.4.49-2.4.50",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"],
    },
    # OpenSSH
    {
        "cve": "CVE-2024-6387",
        "service": "openssh",
        "version_range": ">=8.5p1,<9.8p1",
        "severity": "high",
        "description": "regreSSHion — RCE in OpenSSH (signal handler race condition)",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
    },
    {
        "cve": "CVE-2023-38408",
        "service": "openssh",
        "version_range": "<9.3p2",
        "severity": "critical",
        "description": "RCE via ssh-agent PKCS#11",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
    },
    # Redis
    {
        "cve": "CVE-2022-0543",
        "service": "redis",
        "version_range": ">=5.0.0,<=7.0.8",
        "severity": "critical",
        "description": "Lua sandbox escape leading to RCE in Debian/Ubuntu Redis",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-0543"],
    },
    # MySQL / MariaDB
    {
        "cve": "CVE-2012-2122",
        "service": "mysql",
        "version_range": ">=5.1.0,<5.1.63",
        "severity": "medium",
        "description": "Authentication bypass in MySQL (CAST trick)",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2012-2122"],
    },
    # PostgreSQL
    {
        "cve": "CVE-2019-9193",
        "service": "postgresql",
        "version_range": ">=9.3,<11.3",
        "severity": "high",
        "description": "COPY FROM PROGRAM — RCE via PostgreSQL",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-9193"],
    },
    # Docker
    {
        "cve": "CVE-2019-5736",
        "service": "docker",
        "version_range": "<18.09.2",
        "severity": "high",
        "description": "Container escape via runc (overwrite host binary)",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-5736"],
    },
    # Kubernetes
    {
        "cve": "CVE-2018-1002105",
        "service": "kubernetes",
        "version_range": ">=1.0.0,<1.10.11",
        "severity": "critical",
        "description": "Privilege escalation via Kubernetes API proxy",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-1002105"],
    },
    # Elasticsearch
    {
        "cve": "CVE-2015-1427",
        "service": "elasticsearch",
        "version_range": ">=1.0.0,<1.4.0",
        "severity": "high",
        "description": "RCE via Groovy scripting engine",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2015-1427"],
    },
    # Jenkins
    {
        "cve": "CVE-2024-23897",
        "service": "jenkins",
        "version_range": ">=2.0,<2.442",
        "severity": "high",
        "description": "Arbitrary file read via Jenkins CLI",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-23897"],
    },
    # Tomcat
    {
        "cve": "CVE-2019-0232",
        "service": "tomcat",
        "version_range": ">=7.0.0,<9.0.20",
        "severity": "high",
        "description": "RCE via CGI Servlet in Windows Tomcat",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0232"],
    },
    # SMB (EternalBlue)
    {
        "cve": "CVE-2017-0144",
        "service": "smb",
        "version_range": "*",
        "severity": "critical",
        "description": "EternalBlue — RCE via SMBv1 (MS17-010)",
        "exploit_module": "eternalblue",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
    },
    # Log4Shell
    {
        "cve": "CVE-2021-44228",
        "service": "log4j",
        "version_range": ">=2.0-beta9,<2.15.0",
        "severity": "critical",
        "description": "Log4Shell — RCE via JNDI injection",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    },
    # Nginx
    {
        "cve": "CVE-2019-9513",
        "service": "nginx",
        "version_range": "<1.17.3",
        "severity": "medium",
        "description": "HTTP/2 DoS via resource loop",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-9513"],
    },
    # Exim (mail)
    {
        "cve": "CVE-2019-10149",
        "service": "exim",
        "version_range": ">=4.87,<4.91",
        "severity": "critical",
        "description": "Return of the WIZard — RCE in Exim",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-10149"],
    },
    # ProFTPd
    {
        "cve": "CVE-2015-3306",
        "service": "proftpd",
        "version_range": ">=1.3.0,<1.3.5",
        "severity": "critical",
        "description": "RCE via mod_copy in ProFTPd",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2015-3306"],
    },
    # vsftpd backdoor
    {
        "cve": "CVE-2011-2523",
        "service": "vsftpd",
        "version_range": "==2.3.4",
        "severity": "critical",
        "description": "Backdoor in vsftpd 2.3.4 (smiley face)",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
    },
    # Apache (new)
    {
        "cve": "CVE-2024-3094",
        "service": "apache",
        "version_range": ">=2.4.0,<2.4.60",
        "severity": "critical",
        "description": "XZ Utils backdoor (CVE-2024-3094) — RCE in Apache via xz/liblzma (supply chain)",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
    },
    {
        "cve": "CVE-2023-44487",
        "service": "apache",
        "version_range": ">=2.4.0,<2.4.58",
        "severity": "high",
        "description": "HTTP/2 Rapid Reset attack — DoS/RCE via stream cancellation",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
    },
    # Tomcat (Ghostcat)
    {
        "cve": "CVE-2020-1938",
        "service": "tomcat",
        "version_range": ">=7.0.0,<9.0.31",
        "severity": "critical",
        "description": "Ghostcat — arbitrary file read / RCE via AJP connector (AJP/1.3 on port 8009)",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-1938"],
    },
    # WebLogic
    {
        "cve": "CVE-2020-14882",
        "service": "weblogic",
        "version_range": ">=10.3.6.0,<12.2.1.4.0",
        "severity": "critical",
        "description": "RCE in Oracle WebLogic Server via Console",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-14882"],
    },
    {
        "cve": "CVE-2017-10271",
        "service": "weblogic",
        "version_range": ">=10.3.6.0,<12.2.1.1.0",
        "severity": "critical",
        "description": "RCE via XMLDecoder deserialization in WebLogic WLS-WSAT",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-10271"],
    },
    # JBoss
    {
        "cve": "CVE-2017-12149",
        "service": "jboss",
        "version_range": ">=5.0.0,<7.0.0",
        "severity": "critical",
        "description": "RCE via HTTP deserialization in JBoss AS",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-12149"],
    },
    # Drupal
    {
        "cve": "CVE-2018-7600",
        "service": "drupal",
        "version_range": ">=7.0,<7.58",
        "severity": "critical",
        "description": "Drupalgeddon2 — RCE via Drupal Core (SA-CORE-2018-002)",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-7600"],
    },
    # WordPress
    {
        "cve": "CVE-2024-44000",
        "service": "wordpress",
        "version_range": ">=6.0,<6.5.5",
        "severity": "medium",
        "description": "Stored XSS via HTML tag in uploaded file names",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-44000"],
    },
    {
        "cve": "CVE-2017-1001000",
        "service": "wordpress",
        "version_range": ">=4.7.0,<4.7.1",
        "severity": "high",
        "description": "REST API content injection (privilege escalation)",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-1001000"],
    },
    # Exchange ProxyLogon
    {
        "cve": "CVE-2021-26855",
        "service": "exchange",
        "version_range": ">=2013,<=2019",
        "severity": "critical",
        "description": "ProxyLogon — SSRF leading to RCE in Microsoft Exchange Server",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-26855"],
    },
    # Exchange ProxyShell
    {
        "cve": "CVE-2021-34473",
        "service": "exchange",
        "version_range": ">=2016,<=2019",
        "severity": "critical",
        "description": "ProxyShell — RCE via autodiscover (pre-auth) in Exchange",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-34473"],
    },
    # vCenter
    {
        "cve": "CVE-2021-21972",
        "service": "vcenter",
        "version_range": ">=6.5,<7.0.2",
        "severity": "critical",
        "description": "RCE via vSphere Client plugin upload in VMware vCenter",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-21972"],
    },
    {
        "cve": "CVE-2021-22005",
        "service": "vcenter",
        "version_range": "<7.0.3",
        "severity": "critical",
        "description": "File upload RCE in VMware vCenter Server analytics",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-22005"],
    },
    # Citrix ADC
    {
        "cve": "CVE-2019-19781",
        "service": "citrix_adc",
        "version_range": ">=10.5,<13.0",
        "severity": "critical",
        "description": "Directory traversal / RCE in Citrix ADC / NetScaler Gateway",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-19781"],
    },
    # F5 BIG-IP
    {
        "cve": "CVE-2020-5902",
        "service": "f5_bigip",
        "version_range": ">=11.6,<16.0",
        "severity": "critical",
        "description": "RCE via TMUI in F5 BIG-IP (Traffic Management User Interface)",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-5902"],
    },
    {
        "cve": "CVE-2022-1388",
        "service": "f5_bigip",
        "version_range": ">=11.6,<17.0",
        "severity": "critical",
        "description": "RCE via unauthenticated iControl REST API in F5 BIG-IP",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-1388"],
    },
    # Atlassian Confluence
    {
        "cve": "CVE-2023-22515",
        "service": "confluence",
        "version_range": ">=8.0.0,<8.6.0",
        "severity": "critical",
        "description": "Broken access control — privilege escalation in Confluence Data Center/Server",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-22515"],
    },
    {
        "cve": "CVE-2022-26134",
        "service": "confluence",
        "version_range": ">=1.3.0,<7.18.0",
        "severity": "critical",
        "description": "OGNL injection — RCE in Confluence Server/Data Center",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-26134"],
    },
    # Zoho ManageEngine
    {
        "cve": "CVE-2022-47966",
        "service": "manageengine",
        "version_range": ">=1.0,<17.0",
        "severity": "critical",
        "description": "RCE via SAML SSO in Zoho ManageEngine",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-47966"],
    },
    # Microsoft RDP (BlueKeep)
    {
        "cve": "CVE-2019-0708",
        "service": "rdp",
        "version_range": ">=6.0,<=10.0",
        "severity": "critical",
        "description": "BlueKeep — RCE via RDP (MS19-002), pre-auth in Windows RDS",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
    },
    # Cisco IOS
    {
        "cve": "CVE-2023-20198",
        "service": "cisco_ios",
        "version_range": ">=15.0,<17.9",
        "severity": "critical",
        "description": "Privilege escalation in Cisco IOS XE Web UI",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-20198"],
    },
    {
        "cve": "CVE-2020-3566",
        "service": "cisco_ios",
        "version_range": ">=15.0,<16.12",
        "severity": "high",
        "description": "DoS via IP fragment reassembly in Cisco IOS",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-3566"],
    },
    # Spring4Shell
    {
        "cve": "CVE-2022-22965",
        "service": "spring",
        "version_range": ">=5.3.0,<5.3.18",
        "severity": "critical",
        "description": "Spring4Shell — RCE via Spring Framework class property injection",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
    },
    # Struts2
    {
        "cve": "CVE-2017-5638",
        "service": "struts2",
        "version_range": ">=2.3.5,<2.3.31",
        "severity": "critical",
        "description": "RCE via Content-Type header in Apache Struts2 (Jakarta Multipart parser)",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-5638"],
    },
    # PHP
    {
        "cve": "CVE-2024-4577",
        "service": "php",
        "version_range": ">=8.0.0,<8.0.30",
        "severity": "critical",
        "description": "Argument injection RCE in PHP CGI on Windows",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-4577"],
    },
    {
        "cve": "CVE-2019-11043",
        "service": "php",
        "version_range": ">=7.1,<7.3.10",
        "severity": "critical",
        "description": "RCE via FPM fastcgi in PHP (path_info under nginx)",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11043"],
    },
    # IIS
    {
        "cve": "CVE-2021-31166",
        "service": "iis",
        "version_range": ">=10.0,<10.0.20348.288",
        "severity": "critical",
        "description": "HTTP Protocol Stack RCE in Windows HTTP.sys (MS21-031)",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-31166"],
    },
    # CUPS
    {
        "cve": "CVE-2024-47176",
        "service": "cups",
        "version_range": ">=2.0.0,<2.4.9",
        "severity": "critical",
        "description": "RCE via IPP/HTTP in CUPS printing system",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-47176"],
    },
    # PHPUnit
    {
        "cve": "CVE-2017-9841",
        "service": "phpunit",
        "version_range": ">=5.0.0,<6.5.0",
        "severity": "critical",
        "description": "RCE via PHPUnit eval-stdin.php gadget",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-9841"],
    },
]


# ── VulnDatabase ────────────────────────────────────────────────


class VulnDatabase:
    """Base de signatures CVE avec matching version.

    Usage:
        db = VulnDatabase()
        vulns = db.check("apache", "2.4.49")
        # → [{"cve": "CVE-2021-41773", ...}, {"cve": "CVE-2021-42013", ...}]
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or Path(__file__).parent / "data" / "cve_signatures.json"
        self._signatures: list[dict] = []
        self._loaded = False

    def load(self) -> int:
        """Charge les signatures depuis le fichier JSON. Retourne le nombre d'entrées."""
        if self.db_path.exists():
            try:
                with open(self.db_path) as f:
                    self._signatures = json.load(f)
                logger.info("vulndb_loaded", path=str(self.db_path), count=len(self._signatures))
            except (OSError, json.JSONDecodeError) as e:
                logger.warning("vulndb_parse_error", error=str(e))
                self._signatures = DEFAULT_SIGNATURES
        else:
            logger.info("vulndb_default", count=len(DEFAULT_SIGNATURES))
            self._signatures = DEFAULT_SIGNATURES

        self._loaded = True
        return len(self._signatures)

    def check(self, service: str, version: str) -> list[dict]:
        """Vérifie les vulnérabilités pour un service+version.

        Args:
            service: Nom du service (ex: "apache", "openssh", "redis")
            version: Version détectée (ex: "2.4.49", "8.9p1")

        Returns:
            Liste de signatures CVE correspondantes

        """
        if not self._loaded:
            self.load()

        matches = []
        service_low = service.lower()

        for sig in self._signatures:
            if sig["service"].lower() != service_low:
                continue
            if self._version_in_range(version, sig.get("version_range", "*")):
                matches.append(dict(sig))

        return matches

    def check_bulk(self, services: list[dict]) -> dict[str, list[dict]]:
        """Vérifie plusieurs services en une fois.

        Args:
            services: [{"service": "apache", "version": "2.4.49"}, ...]

        Returns:
            {service_key: [vulns]}

        """
        results = {}
        for svc in services:
            key = f"{svc['service']}:{svc.get('port', '?')}"
            vulns = self.check(svc["service"], svc.get("version", ""))
            if vulns:
                results[key] = vulns
        return results

    def _version_in_range(self, version: str, range_spec: str) -> bool:
        """Vérifie si une version est dans un range.

        Formats supportés:
            "*"                          → match tout
            "==2.3.4"                   → exact match
            ">=2.4.49,<2.4.51"          → range
            "<18.09.2"                  → inférieur
            ">=5.0.0,<=7.0.8"          → range inclusif
        """
        if range_spec == "*":
            return True

        if not version:
            return range_spec == "*"

        try:
            v = Version(self._normalize_version(version))
        except InvalidVersion:
            # Fallback: comparaison string
            return self._string_range_match(version, range_spec)

        conditions = [c.strip() for c in range_spec.split(",")]

        for cond in conditions:
            op = ""
            ver_str = cond
            for prefix in [">=", "<=", "==", "!=", ">", "<"]:
                if cond.startswith(prefix):
                    op = prefix
                    ver_str = cond[len(prefix) :].strip()
                    break

            try:
                target = Version(self._normalize_version(ver_str))
            except InvalidVersion:
                return False

            if (op == ">=" and not (v >= target)) or (op == "<=" and not (v <= target)):
                return False
            if (
                (op == ">" and not (v > target))
                or (op == "<" and not (v < target))
                or (op == "==" and v != target)
                or (op == "!=" and v == target)
            ):
                return False

        return True

    def _normalize_version(self, version: str) -> str:
        """Normalise une version pour packaging.version.Version.

        Exemples: "8.5p1" → "8.5.1", "9.3p2" → "9.3.2"
        """
        # OpenSSH style: 8.5p1 → 8.5.1
        v = re.sub(r"p(\d+)", r".\1", version)
        # Strip non-version suffixes
        v = re.sub(r"[^0-9.].*$", "", v)
        # Ensure at least x.y format
        if "." not in v:
            v = f"{v}.0"
        return v

    def _string_range_match(self, version: str, range_spec: str) -> bool:
        """Fallback: comparaison string simple."""
        if range_spec == "*":
            return True
        if range_spec.startswith("=="):
            return version == range_spec[2:].strip()
        return False

    @property
    def count(self) -> int:
        if not self._loaded:
            self.load()
        return len(self._signatures)
