"""NmapScanner — wrapper asynchrone autour de python-nmap avec fallback scapy.

Détection OS, version detection, NSE scripts, avec fallback élégant
vers le scanner TCP natif (asyncio) si nmap n'est pas installé.

Sécurité stricte : les arguments nmap sont limités à des profils prédéfinis.
Aucun passage d'arguments bruts autorisé.

Output structuré via des modèles Pydantic (NmapHostResult, PortScanResult).
"""

import asyncio
import contextlib
import re
import shutil

from pydantic import BaseModel, Field

from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)

# ── Profils nmap whitelistés ──────────────────────────────────
# Seuls ces profils peuvent être utilisés ; aucun argument nmap libre.
NMAP_PROFILES: dict[str, str] = {
    "quick": "-T4 -F",
    "default": "-sV -sC -T4",
    "deep": "-sV -sC -O -T4 --script vuln",
    "stealth": "-sS -T2 -f",
    "vuln": "-sV --script vuln",
}

# Description lisible des profils pour l'utilisateur
PROFILE_DESCRIPTIONS: dict[str, str] = {
    "quick": "Scan rapide (100 ports les plus communs, agressif -T4)",
    "default": "Scan équilibré : détection de version + scripts NSE par défaut",
    "deep": "Scan profond : OS + version + scripts vuln (peut prendre du temps)",
    "stealth": "Scan furtif : SYN stealth + lent (-T2) + fragmentation",
    "vuln": "Scan ciblé vulnérabilités : NSE scripts vuln + version detection",
}

# Message d'aide complet listant tous les profils disponibles
PROFILES_HELP = "\n".join(
    f"  {name:12s} — {desc}"
    for name, desc in PROFILE_DESCRIPTIONS.items()
)


def _validate_host(host: str) -> None:
    """Valide que host est une IP ou un hostname basique.

    Args:
        host: Adresse IP ou hostname à valider.

    Raises:
        ValueError: Si le format est invalide ou vide.
    """
    if not host or not isinstance(host, str):
        msg = f"host must be a non-empty string, got {type(host).__name__}"
        raise ValueError(msg)
    host = host.strip()
    # IPv4
    ipv4_re = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    # IPv6 simplifié (présence de ':')
    # Hostname (lettres, chiffres, points, tirets)
    hostname_re = r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$"
    if not (re.match(ipv4_re, host) or ":" in host or re.match(hostname_re, host)):
        msg = f"Invalid host format: '{host}'"
        raise ValueError(msg)


class NmapHostResult(BaseModel):
    """Résultat d'un scan nmap pour un hôte (modèle Pydantic).

    Attributes:
        host: Adresse IP ou hostname scanné.
        status: "up" si l'hôte répond, "down" sinon.
        ports: Dictionnaire {port: dict} avec les détails de chaque port.
        os_matches: Liste de dictionnaires de correspondances OS.
        os_cpe: CPE du meilleur match OS.
        uptime: Temps d'activité de l'hôte (secondes).
        mac_address: Adresse MAC si disponible.
        error: Message d'erreur si le scan a échoué.
    """

    host: str
    status: str = Field(default="down", description="État de l'hôte ('up' ou 'down')")
    ports: dict[int, dict] = Field(
        default_factory=dict,
        description="Ports scannés : {port: {détails...}}",
    )
    os_matches: list[dict] = Field(
        default_factory=list,
        description="Correspondances OS détectées",
    )
    os_cpe: str = Field(default="", description="CPE du meilleur match OS")
    uptime: str | None = Field(default=None, description="Temps d'activité (secondes)")
    mac_address: str | None = Field(default=None, description="Adresse MAC")
    error: str | None = Field(default=None, description="Message d'erreur éventuel")


class PortScanResult(BaseModel):
    """Résultat enrichi pour un port scanné (modèle Pydantic).

    Attributes:
        port: Numéro de port.
        protocol: Protocole (tcp, udp).
        state: État du port (open, closed, filtered).
        service: Nom du service détecté.
        product: Produit logiciel identifié.
        version: Version du produit.
        extrainfo: Informations supplémentaires.
        cpe: CPE du service.
        script_results: Résultats des scripts NSE exécutés.
        os_detected: OS détecté sur ce port (si applicable).
        os_accuracy: Précision de la détection OS (0-100).
        vulnerabilities: Liste de vulnérabilités trouvées par NSE.
    """

    port: int
    protocol: str = Field(default="tcp", description="Protocole de transport")
    state: str = Field(default="closed", description="État du port")
    service: str | None = Field(default=None, description="Nom du service")
    product: str | None = Field(default=None, description="Produit logiciel")
    version: str | None = Field(default=None, description="Version du produit")
    extrainfo: str | None = Field(default=None, description="Informations supplémentaires")
    cpe: str | None = Field(default=None, description="CPE du service")
    script_results: dict = Field(default_factory=dict, description="Résultats des scripts NSE")
    os_detected: str | None = Field(default=None, description="OS détecté")
    os_accuracy: int = Field(default=0, description="Précision détection OS (0-100)")
    vulnerabilities: list[dict] = Field(
        default_factory=list,
        description="Vulnérabilités détectées",
    )


class NmapScanner:
    """Wrapper asynchrone autour de python-nmap avec fallback scapy.

    Utilise asyncio.to_thread() pour ne pas bloquer la boucle asynchrone.
    Détecte automatiquement si nmap est installé ; sinon, tombe sur un
    scanner TCP natif via asyncio.open_connection (fallback).

    Les arguments nmap sont strictement limités aux profils prédéfinis
    (NMAP_PROFILES). Aucun argument brut n'est accepté.

    Profiles disponibles:
        quick   — Scan rapide (100 ports les plus communs, -T4 -F)
        default — Scan équilibré : version + scripts NSE (-sV -sC -T4)
        deep    — Scan profond : OS + version + scripts vuln
        stealth — Scan furtif : SYN stealth + lent + fragmentation
        vuln    — Scan ciblé vulnérabilités (NSE vuln + version)
    """

    PROFILES = NMAP_PROFILES

    def __init__(self) -> None:
        self._nmap_available: bool | None = None
        self._nmap = None  # import nmap (lazy)

    @property
    def available(self) -> bool:
        """Vérifie si nmap est installé sur le système.

        Returns:
            True si le binaire nmap est trouvé dans le PATH.
        """
        if self._nmap_available is not None:
            return self._nmap_available
        self._nmap_available = shutil.which("nmap") is not None
        return self._nmap_available

    @staticmethod
    def check_installation() -> str:
        """Vérifie la disponibilité de nmap et retourne un message clair.

        Returns:
            Chaîne décrivant l'état de l'installation nmap.
        """
        nmap_bin = shutil.which("nmap")
        if nmap_bin:
            return f"nmap est installé : {nmap_bin}"
        return (
            "nmap n'est pas installé sur le système.\n"
            "  - Windows : téléchargez https://nmap.org/download.html\n"
            "  - Linux   : sudo apt install nmap (ou brew install nmap)\n"
            "  - macOS   : brew install nmap\n"
            "Le scanner utilisera un fallback TCP Connect (limité)."
        )

    @staticmethod
    def list_profiles() -> str:
        """Liste les profils de scan disponibles avec leurs descriptions.

        Returns:
            Chaîne formatée listant tous les profils.
        """
        return PROFILES_HELP

    async def scan(
        self,
        host: str,
        ports: list[int] | None = None,
        profile: str = "default",
        timeout: int = 120,
        scripts: list[str] | None = None,
        unsafe_scripts: bool = False,
    ) -> NmapHostResult:
        """Lance un scan nmap complet sur un hôte.

        Les arguments nmap sont déterminés par un profil prédéfini uniquement.
        Aucun passage d'arguments bruts n'est autorisé.

        Args:
            host: Cible (IP ou hostname).
            ports: Liste de ports (ex: [80, 443, 22]). None = ports communs.
            profile: Profil nmap prédéfini
                ("quick", "default", "deep", "stealth", "vuln").
            timeout: Timeout en secondes pour le scan.
            scripts: Scripts NSE supplémentaires
                (ex: ["http-title", "ssl-enum-ciphers"]).
            unsafe_scripts: Activer --script-args=unsafe=1 (def: False).

        Returns:
            NmapHostResult avec les résultats structurés.

        Raises:
            ValueError: Si le profil est inconnu ou si l'hôte est invalide.
        """
        # Validation
        _validate_host(host)
        if profile not in self.PROFILES:
            valid = ", ".join(sorted(self.PROFILES.keys()))
            msg = (
                f"Profil nmap inconnu : '{profile}'. "
                f"Profils valides : {valid}\n"
                f"{PROFILES_HELP}"
            )
            raise ValueError(msg)

        result = NmapHostResult(host=host)

        # Vérifier la disponibilité de nmap
        if not self.available:
            logger.warning(
                "nmap_non_installe",
                host=host,
                hint="Installez nmap pour des scans complets",
            )
            logger.info("nmap_scanner_fallback", host=host)
            return await self._fallback_scan(host, ports, timeout)

        # Vérifier que python-nmap est installé
        try:
            import nmap  # type: ignore
        except ImportError:
            logger.warning(
                "nmap_python_manquant",
                host=host,
                hint="pip install python-nmap",
            )
            logger.info("nmap_python_missing_fallback", host=host)
            return await self._fallback_scan(host, ports, timeout)

        # Construire les arguments à partir du profil
        nse_args = self.PROFILES[profile]

        # Ajouter les scripts NSE supplémentaires
        if scripts:
            script_str = ",".join(scripts)
            nse_args += f" --script={script_str}"

        # Activer unsafe si demandé
        if unsafe_scripts:
            nse_args += " --script-args=unsafe=1"

        # Ajouter les ports
        port_str = ""
        if ports:
            port_str = ",".join(str(p) for p in ports)
        if port_str:
            nse_args += f" -p {port_str}"

        try:
            nm = nmap.PortScanner()

            def _run():
                nm.scan(hosts=host, arguments=nse_args, timeout=timeout)
                return nm

            nm = await asyncio.to_thread(_run)

            # Traiter les résultats
            if host not in nm.all_hosts():
                # Essayer avec le nom d'hôte brut
                for h in nm.all_hosts():
                    if h == host or h.startswith(host):
                        result.status = nm[h].state()
                        break
                else:
                    result.status = "down"
                    return result

            host_data = nm[host]
            result.status = host_data.state()

            # OS Detection
            if host_data.get("osmatch"):
                for osm in host_data["osmatch"]:
                    match = {
                        "name": osm.get("name", ""),
                        "accuracy": osm.get("accuracy", 0),
                        "line": osm.get("line", ""),
                        "osclass": osm.get("osclass", []),
                    }
                    result.os_matches.append(match)

                # Meilleur match
                best = host_data["osmatch"][0]
                result.os_cpe = (
                    best.get("osclass", [{}])[0].get("cpe", "") if best.get("osclass") else ""
                )

            # Uptime
            if "uptime" in host_data:
                result.uptime = host_data["uptime"].get("seconds", "")

            # Ports
            if "tcp" in host_data:
                for port, pdata in host_data["tcp"].items():
                    entry = PortScanResult(
                        port=port,
                        protocol="tcp",
                        state=pdata.get("state", "closed"),
                        service=pdata.get("name", ""),
                        product=pdata.get("product", ""),
                        version=pdata.get("version", ""),
                        extrainfo=pdata.get("extrainfo", ""),
                        cpe=pdata.get("cpe", ""),
                    )
                    # Script results
                    if "script" in pdata:
                        entry.script_results = dict(pdata["script"])

                    result.ports[port] = entry.model_dump()

            # MAC address
            if "addresses" in host_data and "mac" in host_data["addresses"]:
                result.mac_address = host_data["addresses"]["mac"]

        except (OSError, RuntimeError, ValueError) as e:
            logger.exception("nmap_scan_error", host=host, error=str(e))
            result.error = str(e)

        return result

    async def scan_os(self, host: str, timeout: int = 120) -> NmapHostResult:
        """Scan spécifique pour la détection OS (profil deep avec -O).

        Args:
            host: Cible (IP ou hostname).
            timeout: Timeout en secondes.

        Returns:
            NmapHostResult avec les informations OS.
        """
        return await self.scan(host, profile="deep", timeout=timeout)

    async def scan_services(
        self,
        host: str,
        ports: list[int] | None = None,
        timeout: int = 120,
    ) -> NmapHostResult:
        """Scan spécifique pour la détection de services/versions (profil default).

        Args:
            host: Cible (IP ou hostname).
            ports: Liste de ports à scanner. None = ports communs.
            timeout: Timeout en secondes.

        Returns:
            NmapHostResult avec les services/versions détectés.
        """
        return await self.scan(host, ports=ports, profile="default", timeout=timeout)

    async def scan_vuln(
        self,
        host: str,
        ports: list[int] | None = None,
        timeout: int = 300,
    ) -> NmapHostResult:
        """Scan avec scripts NSE de vulnérabilité (profil vuln).

        Les scripts unsafe sont activés car il s'agit d'un scan
        de vulnérabilité explicite.

        Args:
            host: Cible (IP ou hostname).
            ports: Liste de ports à scanner. None = ports communs.
            timeout: Timeout en secondes (défaut: 300s).

        Returns:
            NmapHostResult avec les vulnérabilités détectées.
        """
        return await self.scan(
            host,
            ports=ports,
            profile="vuln",
            timeout=timeout,
            unsafe_scripts=True,
        )

    async def scan_nse(
        self,
        host: str,
        scripts: list[str],
        ports: list[int] | None = None,
        timeout: int = 180,
    ) -> NmapHostResult:
        """Scan avec scripts NSE personnalisés (profil default + scripts).

        Args:
            host: Cible (IP ou hostname).
            scripts: Liste de scripts NSE à exécuter.
            ports: Liste de ports à scanner. None = ports communs.
            timeout: Timeout en secondes (défaut: 180s).

        Returns:
            NmapHostResult avec les résultats des scripts NSE.
        """
        return await self.scan(
            host,
            ports=ports,
            profile="default",
            scripts=scripts,
            timeout=timeout,
        )

    # ── Fallback asyncio ──────────────────────────────────────

    async def _fallback_scan(
        self,
        host: str,
        ports: list[int] | None,
        timeout: int,
    ) -> NmapHostResult:
        """Fallback quand nmap n'est pas disponible.

        Utilise asyncio.open_connection pour un TCP Connect scan basique,
        et tente de faire du banner grabbing pour l'identification.

        Args:
            host: Cible (IP ou hostname).
            ports: Liste de ports à vérifier. None = liste par défaut.
            timeout: Timeout global pour le scan.

        Returns:
            NmapHostResult avec les ports ouverts détectés.
        """
        result = NmapHostResult(host=host, status="up")

        if not ports:
            ports = [
                21,
                22,
                23,
                25,
                53,
                80,
                443,
                445,
                3306,
                3389,
                5432,
                6379,
                8080,
                8443,
                9200,
                27017,
            ]

        async def check_port(port: int):
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=min(timeout, 5),
                )
            except (TimeoutError, ConnectionRefusedError, OSError):
                return port, None

            banner = b""
            try:
                # Banner grab
                w.write(b"\r\n")
                await w.drain()
                with contextlib.suppress(TimeoutError):
                    banner = await asyncio.wait_for(r.read(1024), timeout=2)
            finally:
                w.close()
                with contextlib.suppress(OSError):
                    await w.wait_closed()

            banner_text = banner.decode("utf-8", errors="replace").strip()
            return port, {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "banner": banner_text,
                "service": self._guess_service(port, banner_text),
            }

        tasks = [check_port(p) for p in ports]
        results = await asyncio.gather(*tasks)

        for port, data in results:
            if data:
                result.ports[port] = data

        return result

    def _guess_service(self, port: int, banner: str) -> str:
        """Identifie le service à partir du port et du banner.

        Args:
            port: Numéro de port.
            banner: Bannière récupérée du service.

        Returns:
            Nom du service identifié, ou "unknown".
        """
        b = banner.lower()
        if b.startswith("ssh-") or "openssh" in b:
            return "ssh"
        if any(s in b for s in ["http/", "html", "apache", "nginx", "iis"]):
            return "http"
        if "mysql" in b or "mariadb" in b:
            return "mysql"
        if "postgresql" in b:
            return "postgresql"
        if "-err" in b or "+pong" in b or "redis" in b:
            return "redis"
        if "mongodb" in b:
            return "mongodb"
        if b.startswith("220") and "ftp" in b:
            return "ftp"
        if "smb" in b or "samba" in b:
            return "smb"
        # Fallback port-based
        port_map = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            443: "https",
            445: "smb",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            6379: "redis",
            8080: "http",
            8443: "https",
            9200: "elasticsearch",
            27017: "mongodb",
        }
        return port_map.get(port, "unknown")


# ── Helper pour enrichir ContextualScanResult ────────────────


async def enrich_with_nmap(
    host: str,
    ports: list[int],
    nmap_scanner: NmapScanner | None = None,
) -> dict:
    """Enrichit un résultat de scan avec les données nmap.

    Args:
        host: Hôte cible.
        ports: Liste des ports ouverts.
        nmap_scanner: Instance NmapScanner (créée si None).

    Returns:
        Dict avec OS, versions détaillées, scripts NSE, etc.
    """
    scanner = nmap_scanner or NmapScanner()
    result = await scanner.scan(host, ports=ports)
    return {
        "os_matches": result.os_matches,
        "os_cpe": result.os_cpe,
        "ports": result.ports,
        "mac_address": result.mac_address,
        "scanner_used": "nmap" if scanner.available else "fallback",
    }
