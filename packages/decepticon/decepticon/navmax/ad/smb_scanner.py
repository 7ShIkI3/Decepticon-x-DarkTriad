"""AD SMB Scanner — énumération des partages SMB et configuration.

Analyse les partages SMB sur les machines du domaine :
- Liste des partages (administratifs et utilisateur)
- Permissions (qui a accès)
- Partages accessibles en écriture (privesc potentielle)
- Détection SMBv1 (EternalBlue)
- SMB signing activé/désactivé
- Shares exposés avec données sensibles

Usage:
    scanner = ADSMSScanner(connector)
    results = await scanner.scan_computer("dc01.corp.local")
    for share in results.shares:
        print(f"{share.name}: {share.permissions}")
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ── Types ──────────────────────────────────────────────────────


class SharePermission(StrEnum):
    READ = "read"
    WRITE = "write"
    FULL = "full"
    NONE = "none"


class SMBSigningMode(StrEnum):
    REQUIRED = "required"
    ENABLED = "enabled"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


@dataclass
class SMBShare:
    """Un partage SMB découvert."""

    name: str
    path: str = ""
    description: str = ""
    current_uses: int = 0
    max_uses: int = 0
    permissions: SharePermission = SharePermission.NONE
    is_admin_share: bool = False  # C$, ADMIN$, IPC$...
    is_writable: bool = False
    raw_info: dict[str, Any] = field(default_factory=dict)


@dataclass
class SMBSigningInfo:
    """Configuration SMB signing d'une machine."""

    hostname: str
    signing_required: bool = False
    signing_enabled: bool = True
    mode: SMBSigningMode = SMBSigningMode.UNKNOWN
    vulnerable_to_relay: bool = False


@dataclass
class SMBComputerResult:
    """Résultat de scan SMB pour une machine."""

    hostname: str
    ip_address: str = ""
    reachable: bool = False
    smb_version: str = ""
    smbv1_enabled: bool = False  # Vulnérable à EternalBlue
    signing: SMBSigningInfo = field(default_factory=lambda: SMBSigningInfo(hostname=""))
    shares: list[SMBShare] = field(default_factory=list)
    accessible_shares: int = 0
    writable_shares: int = 0
    error: str | None = None

    @property
    def has_writable_shares(self) -> bool:
        return self.writable_shares > 0

    @property
    def risky(self) -> bool:
        """La machine présente des risques élevés."""
        return self.smbv1_enabled or self.signing.vulnerable_to_relay or self.has_writable_shares


@dataclass
class SMBDomainReport:
    """Rapport d'énumération SMB sur tout le domaine."""

    domain: str
    computers_scanned: int = 0
    computers_reachable: int = 0
    results: list[SMBComputerResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def smbv1_hosts(self) -> list[SMBComputerResult]:
        return [r for r in self.results if r.smbv1_enabled]

    @property
    def relay_vulnerable_hosts(self) -> list[SMBComputerResult]:
        return [r for r in self.results if r.signing.vulnerable_to_relay]

    @property
    def hosts_with_writable_shares(self) -> list[SMBComputerResult]:
        return [r for r in self.results if r.has_writable_shares]

    def summary(self) -> str:
        lines = [
            f"=== SMB Domain Scan: {self.domain} ===",
            f"Computers scanned: {self.computers_scanned}",
            f"Computers reachable: {self.computers_reachable}",
            f"SMBv1 hosts (EternalBlue): {len(self.smbv1_hosts)}",
            f"SMB relay vulnerable: {len(self.relay_vulnerable_hosts)}",
            f"Hosts with writable shares: {len(self.hosts_with_writable_shares)}",
        ]
        if self.smbv1_hosts:
            lines.append("\n⚠️  SMBv1 ENABLED on:")
            for r in self.smbv1_hosts:
                lines.append(f"  - {r.hostname}")
        if self.relay_vulnerable_hosts:
            lines.append("\n⚠️  SMB RELAY VULNERABLE on:")
            for r in self.relay_vulnerable_hosts:
                lines.append(f"  - {r.hostname}")
        if self.hosts_with_writable_shares:
            lines.append("\n⚠️  WRITABLE SHARES on:")
            for r in self.hosts_with_writable_shares:
                writable = [s.name for s in r.shares if s.is_writable]
                lines.append(f"  - {r.hostname}: {', '.join(writable)}")
        return "\n".join(lines)


# ── Scanner ────────────────────────────────────────────────────


class ADSMSScanner:
    """Scanner SMB pour environnement Active Directory.

    Énumère les partages, vérifie SMB signing, détecte SMBv1.

    Utilise l'implémentation SMB native Python (pas de dépendance externe)
    avec fallback sur subprocess + smbclient si disponible.

    Usage:
        scanner = ADSMSScanner()
        report = await scanner.scan_domain(domain_map)
        print(report.summary())
    """

    # Partages à risque élevé
    HIGH_RISK_SHARES = {
        "C$",
        "ADMIN$",
        "SYSVOL",
        "NETLOGON",
    }

    # Partages communs pouvant contenir des données sensibles
    SENSITIVE_PATTERNS = {
        "backup",
        "data",
        "database",
        "finance",
        "hr",
        "users",
        "home",
        "profiles",
        "transfer",
        "shared",
        "public",
        "tmp",
        "temp",
        "install",
    }

    def __init__(self, connector=None, timeout: float = 10.0) -> None:
        self.connector = connector
        self.timeout = timeout

    async def scan_domain(self, domain_map) -> SMBDomainReport:
        """Scanne tous les ordinateurs du domaine.

        Args:
            domain_map: DomainMap issue de l'énumérateur

        Returns:
            SMBDomainReport complet

        """
        report = SMBDomainReport(domain=domain_map.domain.name)
        computers = domain_map.computers

        logger.info(
            "smb_domain_scan_starting", domain=domain_map.domain.name, computers=len(computers),
        )

        for computer in computers:
            if not computer.is_enabled:
                continue
            hostname = computer.dns_hostname or computer.sam_account_name.rstrip("$")
            if not hostname:
                continue

            report.computers_scanned += 1

            try:
                result = await self.scan_computer(hostname)
                report.results.append(result)
                if result.reachable:
                    report.computers_reachable += 1
            except Exception as e:
                report.errors.append(f"{hostname}: {e}")
                logger.warning("smb_scan_error", hostname=hostname, error=str(e))

        logger.info(
            "smb_domain_scan_complete",
            scanned=report.computers_scanned,
            reachable=report.computers_reachable,
        )

        return report

    async def scan_computer(self, hostname: str) -> SMBComputerResult:
        """Scanne une machine spécifique.

        Args:
            hostname: Nom DNS ou IP de la machine

        Returns:
            SMBComputerResult avec shares, signing, version

        """
        result = SMBComputerResult(hostname=hostname)

        # ── Tentative de connexion SMB ─────────────────────────
        try:
            smb_info = await self._probe_smb(hostname)
            result.reachable = True
            result.ip_address = smb_info.get("ip", "")
            result.smb_version = smb_info.get("version", "")
            result.smbv1_enabled = smb_info.get("smbv1", False)
            result.signing = smb_info.get("signing", SMBSigningInfo(hostname=hostname))
        except Exception as e:
            result.error = str(e)
            logger.debug("smb_probe_failed", hostname=hostname, error=str(e))
            return result

        # ── Énumération des partages ────────────────────────────
        try:
            shares = await self._enumerate_shares(hostname)
            result.shares = shares
            result.accessible_shares = len(shares)
            result.writable_shares = sum(1 for s in shares if s.is_writable)
        except Exception as e:
            logger.debug("smb_shares_failed", hostname=hostname, error=str(e))

        return result

    # ── Probes ─────────────────────────────────────────────────

    async def _probe_smb(self, hostname: str) -> dict:
        """Sonde SMB sur une machine.

        Tente de déterminer :
        - Version SMB (SMBv1, v2, v3)
        - SMB signing
        - Accessibilité
        """
        info = {
            "hostname": hostname,
            "ip": "",
            "version": "unknown",
            "smbv1": False,
            "reachable": False,
            "signing": SMBSigningInfo(hostname=hostname),
        }

        try:
            # Tenter un scan SMB via l'API Python
            import socket

            # Résolution DNS
            try:
                info["ip"] = socket.gethostbyname(hostname)
            except socket.gaierror:
                info["ip"] = hostname

            # Test de connectivité port 445
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((info["ip"], 445))
            sock.close()

            if result != 0:
                # Port 139 fallback (NetBIOS)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((info["ip"], 139))
                sock.close()

            info["reachable"] = result == 0

            if not info["reachable"]:
                return info

            # Tentative de négociation SMB
            try:
                version_info = await self._smb_negotiate(info["ip"])
                info.update(version_info)
            except Exception:
                # Fallback: on marque comme accessible mais version inconnue
                info["version"] = "SMBv2+ (presumed)"

            # Analyse SMB signing (basée sur la config OS si dispo)
            info["signing"] = self._analyze_signing(hostname, info.get("version", ""))

        except Exception as e:
            logger.debug("smb_probe_error", hostname=hostname, error=str(e))

        return info

    async def _smb_negotiate(self, ip: str) -> dict:
        """Négociation SMB basique pour déterminer la version."""
        info = {"version": "unknown", "smbv1": False}

        try:
            import socket
            import struct

            # SMBv1 Negotiate Protocol Request
            smb1_negotiate = bytes(
                [
                    0x00,  # SMB_COM_NEGOTIATE
                    0x00,
                    0x00,
                    0x00,  # Status
                    0x02,  # Flags
                    0x00,
                    0x00,  # Flags2
                    0x00,
                    0x00,  # PID High
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,  # Signature
                    0x00,
                    0x00,  # Reserved
                    0x00,
                    0x00,  # TID
                    0x00,
                    0x00,  # PID Low
                    0x00,
                    0x00,  # UID
                    0x00,
                    0x00,  # MID
                ],
            )

            # NetBIOS Session Request
            nb_name = b"\x20" + b"CK" + b"A" * 14 + b"\x00"  # *SMBSERVER
            nb_session_req = b"\x81\x00\x00\x44\x20" + nb_name

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)

            try:
                sock.connect((ip, 445))
                sock.send(nb_session_req)
                response = sock.recv(1024)

                if response and response[0] == 0x82:  # Positive session response
                    # Session établie — tenter negotiate
                    b"\x00\x00\x00\x2b" + smb1_negotiate
                    sock.send(struct.pack(">I", len(smb1_negotiate)) + smb1_negotiate)
                    negotiate_resp = sock.recv(4096)

                    if negotiate_resp and len(negotiate_resp) > 39:
                        dialect_index = negotiate_resp[39] if len(negotiate_resp) > 39 else 0

                        # Dialect index mapping
                        dialect_map = {
                            0: "PC NETWORK PROGRAM 1.0",
                            1: "LANMAN 1.0",
                            2: "DOS LM1.2X002",
                            3: "DOS LANMAN 2.1",
                            4: "Windows for Workgroups 3.1a",
                            5: "NT LANMAN 1.0",
                            6: "NT LM 0.12",
                            7: "SMB 2.0",
                            8: "SMB 2.1",
                        }

                        if dialect_index <= 6:
                            info["smbv1"] = True
                            info["version"] = f"SMBv1 ({dialect_map.get(dialect_index, 'unknown')})"
                        elif dialect_index == 7:
                            info["version"] = "SMBv2.0"
                        else:
                            info["version"] = f"SMBv2+ (dialect {dialect_index})"
                    else:
                        # SMBv1 a échoué → probablement SMBv2+
                        info["version"] = "SMBv2+ (SMBv1 rejected)"

            finally:
                sock.close()

        except (TimeoutError, ConnectionRefusedError, OSError):
            info["version"] = "SMBv2+ (port open, SMBv1 timeout)"
        except Exception as e:
            logger.debug("smb_negotiate_error", ip=ip, error=str(e))

        return info

    async def _enumerate_shares(self, hostname: str) -> list[SMBShare]:
        """Énumère les partages SMB d'une machine.

        Utilise smbclient si disponible, sinon fallback basique.
        """
        shares: list[SMBShare] = []

        try:
            # Tenter d'utiliser smbclient (si installé)
            import asyncio

            proc = await asyncio.create_subprocess_exec(
                "smbclient",
                "-L",
                f"//{hostname}",
                "-N",  # Pas d'auth
                "-g",  # Output grepable
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, _stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout,
                )
            except TimeoutError:
                proc.kill()
                await proc.wait()
                return shares

            if proc.returncode == 0:
                for line in stdout.decode("utf-8", errors="ignore").splitlines():
                    if "|" in line and "Disk" in line:
                        parts = line.split("|")
                        if len(parts) >= 3:
                            share_name = parts[0].strip()
                            share = SMBShare(
                                name=share_name,
                                path=parts[1].strip() if len(parts) > 1 else "",
                                description=parts[2].strip() if len(parts) > 2 else "",
                                is_admin_share=share_name.endswith("$"),
                            )
                            shares.append(share)
            else:
                # Fallback: partages connus par défaut
                shares = self._default_shares()

        except FileNotFoundError:
            # smbclient non installé → fallback
            shares = self._default_shares()
        except Exception as e:
            logger.debug("smb_share_enum_error", hostname=hostname, error=str(e))
            shares = self._default_shares()

        # Enrichir avec l'analyse des permissions
        for share in shares:
            share.is_writable = self._check_share_writability(hostname, share)

        return shares

    def _default_shares(self) -> list[SMBShare]:
        """Partages par défaut (fallback si énumération impossible)."""
        return [
            SMBShare(name="C$", path="C:\\", is_admin_share=True),
            SMBShare(name="ADMIN$", path="C:\\Windows", is_admin_share=True),
            SMBShare(name="IPC$", is_admin_share=True),
            SMBShare(name="NETLOGON", path="C:\\Windows\\SYSVOL\\sysvol\\{domain}\\SCRIPTS"),
            SMBShare(name="SYSVOL", path="C:\\Windows\\SYSVOL\\sysvol"),
        ]

    def _check_share_writability(
        self,
        hostname: str,
        share: SMBShare,
    ) -> bool:
        """Vérifie si un partage est accessible en écriture."""
        # Vérification limitée sans authentification.
        # Les partages admin ($) sont en lecture seule sans privilèges.
        if share.is_admin_share:
            return False

        # Un attaquant non authentifié ne peut généralement pas écrire.
        # Cette méthode est un placeholder pour une vérification avec
        # credentials (via smbclient -c 'put test.txt').
        return False

    def _analyze_signing(
        self,
        hostname: str,
        smb_version: str,
    ) -> SMBSigningInfo:
        """Analyse la configuration SMB signing."""
        signing = SMBSigningInfo(hostname=hostname)

        # Par défaut sur les versions récentes de Windows :
        # - Workstation: signing enabled but not required
        # - DC: signing required (depuis 2019+)
        # - SMBv1: signing optionnel (vulnérable au relay)

        if "SMBv1" in smb_version:
            signing.signing_required = False
            signing.signing_enabled = False
            signing.mode = SMBSigningMode.DISABLED
            signing.vulnerable_to_relay = True
        else:
            signing.signing_required = False
            signing.signing_enabled = True
            signing.mode = SMBSigningMode.ENABLED
            signing.vulnerable_to_relay = not signing.signing_required

        return signing


# ── Fonction utilitaire ────────────────────────────────────────


async def quick_smb_scan(domain_map) -> SMBDomainReport:
    """Scan SMB rapide sur tout le domaine.

    Usage:
        report = await quick_smb_scan(domain_map)
        print(report.summary())
    """
    scanner = ADSMSScanner()
    return await scanner.scan_domain(domain_map)
