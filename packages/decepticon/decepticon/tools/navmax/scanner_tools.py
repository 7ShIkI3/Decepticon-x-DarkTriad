"""Wrappers LangChain ``@tool`` pour les scanners réseau NavMAX.

Fournit 10 tools couvrant 4 modules scanner :

  - **NmapScanner**   — ``nmap_scan``, ``nmap_scan_os``, ``nmap_scan_services``, ``nmap_scan_vuln``
  - **NucleiScanner** — ``nuclei_scan``, ``nuclei_update_templates``
  - **TCP Scanner**   — ``tcp_connect_scan``, ``tcp_port_range_scan``
  - **VulnDatabase**  — ``vulndb_lookup_cve``, ``vulndb_check_service``

Chaque tool retourne une chaîne JSON compacte pour respecter le contrat
de retour LangChain et minimiser la consommation de tokens LLM.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from langchain_core.tools import tool

from decepticon.navmax.scanner.nmap_scanner import NmapScanner
from decepticon.navmax.scanner.nuclei_scanner import NucleiScanner
from decepticon.navmax.scanner.tcp import PortResult, tcp_connect_scan as _tcp_scan
from decepticon.navmax.scanner.vuln_db import VulnDatabase
from decepticon_core.utils.logging import get_logger

log = get_logger("navmax.scanner_tools")

# ── Helpers ─────────────────────────────────────────────────────────────


def _json(obj: Any) -> str:
    """Serialize to JSON with compact separators, ensuring a string return."""
    return json.dumps(obj, default=str, separators=(",", ":"))


def _port_result_to_dict(pr: PortResult) -> dict[str, Any]:
    """Convert a PortResult namedtuple to a serializable dict."""
    return {
        "port": pr.port,
        "protocol": pr.protocol,
        "state": pr.state,
        "service": pr.service,
        "banner": pr.banner,
        "version": pr.version,
        "latency_ms": pr.latency_ms,
    }


# ── Instances singleton partagées ───────────────────────────────────────

_nmap_scanner: NmapScanner | None = None
_nuclei_scanner: NucleiScanner | None = None
_vuln_db: VulnDatabase | None = None


def _get_nmap() -> NmapScanner:
    global _nmap_scanner
    if _nmap_scanner is None:
        _nmap_scanner = NmapScanner()
    return _nmap_scanner


def _get_nuclei() -> NucleiScanner:
    global _nuclei_scanner
    if _nuclei_scanner is None:
        _nuclei_scanner = NucleiScanner()
    return _nuclei_scanner


def _get_vulndb() -> VulnDatabase:
    global _vuln_db
    if _vuln_db is None:
        _vuln_db = VulnDatabase()
    return _vuln_db


# ── Outils NmapScanner ─────────────────────────────────────────────────


@tool
async def nmap_scan(
    host: str,
    profile: str = "default",
    ports: list[int] | None = None,
    timeout: int = 120,
    scripts: list[str] | None = None,
) -> str:
    """Lance un scan nmap complet avec un profil prédéfini.

    WHEN TO USE: Découverte initiale de ports ouverts et services sur une
    cible. C'est l'outil de scan réseau principal. Les profils disponibles
    sont : ``quick`` (100 ports, -T4), ``default`` (version + NSE, -sV -sC),
    ``deep`` (OS + version + vuln), ``stealth`` (SYN furtif lent),
    ``vuln`` (scripts vuln NSE uniquement).

    Args:
        host: Adresse IP ou hostname de la cible.
        profile: Profil nmap prédéfini (quick, default, deep, stealth, vuln).
        ports: Liste de ports spécifiques (ex: [80, 443, 22]).
               None = ports communs du profil.
        timeout: Timeout en secondes pour le scan (défaut: 120s).
        scripts: Scripts NSE supplémentaires (ex: ["http-title"]).

    Returns:
        JSON avec le statut de l'hôte, les ports ouverts, les services
        détectés et les résultats des scripts NSE.
    """
    log.info("nmap_scan_start", host=host, profile=profile, ports=ports)
    try:
        scanner = _get_nmap()
        result = await scanner.scan(
            host=host,
            profile=profile,
            ports=ports,
            timeout=timeout,
            scripts=scripts,
        )
        return _json(result.model_dump())
    except ValueError as e:
        return _json({"error": str(e)})
    except Exception as e:
        log.exception("nmap_scan_error", host=host)
        return _json({"error": f"nmap_scan failed: {e}"})


@tool
async def nmap_scan_os(host: str, timeout: int = 120) -> str:
    """Détection du système d'exploitation via nmap (profil deep).

    WHEN TO USE: Quand vous avez besoin d'identifier précisément l'OS
    d'une cible (Windows, Linux, macOS, versions, etc.). Utilise -O
    avec le profil deep. Prend plus de temps qu'un scan standard.

    Args:
        host: Adresse IP ou hostname de la cible.
        timeout: Timeout en secondes (défaut: 120s).

    Returns:
        JSON avec les correspondances OS, CPE, uptime et adresse MAC.
    """
    log.info("nmap_scan_os", host=host)
    try:
        scanner = _get_nmap()
        result = await scanner.scan_os(host=host, timeout=timeout)
        return _json(result.model_dump())
    except ValueError as e:
        return _json({"error": str(e)})
    except Exception as e:
        log.exception("nmap_scan_os_error", host=host)
        return _json({"error": f"nmap_scan_os failed: {e}"})


@tool
async def nmap_scan_services(
    host: str,
    ports: list[int] | None = None,
    timeout: int = 120,
) -> str:
    """Détection des services et versions sur les ports ouverts (profil default).

    WHEN TO USE: Après avoir découvert les ports ouverts, utilisez ce tool
    pour identifier les services (Apache, SSH, MySQL) et leurs versions
    exactes. Ces informations alimentent la recherche de CVE.

    Args:
        host: Adresse IP ou hostname de la cible.
        ports: Liste de ports à scanner. None = ports communs.
        timeout: Timeout en secondes (défaut: 120s).

    Returns:
        JSON listant les ports ouverts avec service, produit, version et CPE.
    """
    log.info("nmap_scan_services", host=host, ports=ports)
    try:
        scanner = _get_nmap()
        result = await scanner.scan_services(host=host, ports=ports, timeout=timeout)
        return _json(result.model_dump())
    except ValueError as e:
        return _json({"error": str(e)})
    except Exception as e:
        log.exception("nmap_scan_services_error", host=host)
        return _json({"error": f"nmap_scan_services failed: {e}"})


@tool
async def nmap_scan_vuln(
    host: str,
    ports: list[int] | None = None,
    timeout: int = 300,
) -> str:
    """Scan de vulnérabilités avec les scripts NSE ``vuln`` de nmap.

    WHEN TO USE: Pour détecter automatiquement des vulnérabilités connues
    via les scripts NSE (ex: EternalBlue, Shellshock, SMBGhost). Active
    les scripts unsafe car il s'agit d'un scan de vulnérabilité explicite.
    Peut prendre plus de temps (300s par défaut).

    Args:
        host: Adresse IP ou hostname de la cible.
        ports: Liste de ports à scanner. None = tous les ports.
        timeout: Timeout en secondes (défaut: 300s).

    Returns:
        JSON avec les vulnérabilités détectées par les scripts NSE.
    """
    log.info("nmap_scan_vuln", host=host, ports=ports)
    try:
        scanner = _get_nmap()
        result = await scanner.scan_vuln(host=host, ports=ports, timeout=timeout)
        return _json(result.model_dump())
    except ValueError as e:
        return _json({"error": str(e)})
    except Exception as e:
        log.exception("nmap_scan_vuln_error", host=host)
        return _json({"error": f"nmap_scan_vuln failed: {e}"})


# ── Outils NucleiScanner ───────────────────────────────────────────────


@tool
async def nuclei_scan(
    target: str,
    templates: list[str] | None = None,
    severity: list[str] | None = None,
    timeout: int = 300,
) -> str:
    """Lance un scan de vulnérabilités avec Nuclei (10 000+ templates).

    WHEN TO USE: Pour un scan de vulnérabilités complet et à jour utilisant
    la communauté ProjectDiscovery. Nuclei détecte des CVEs, des
    misconfigurations, des technologies et bien plus. Complémentaire de
    nmap NSE — là où nmap est système/réseau, nuclei est applicatif/web.

    Args:
        target: Cible à scanner (URL, IP, domaine ou CIDR).
                Ex: ``"https://example.com"``, ``"10.0.0.1"``,
                ``"192.168.1.0/24"``.
        templates: Liste de templates ou catégories nuclei.
                Ex: ``["cves/", "exposed-panels/"]``.
                None = templates CVE par défaut.
        severity: Filtre par sévérité minimum (critical, high, medium,
                low, info). Ex: ``["critical", "high"]``.
        timeout: Timeout en secondes (défaut: 300s).

    Returns:
        JSON avec la liste des findings (template_id, nom, sévérité,
        CVE associées, extraits).
    """
    log.info("nuclei_scan_start", target=target, templates=templates, severity=severity)
    try:
        scanner = _get_nuclei()
        findings = await scanner.scan(
            target=target,
            templates=templates,
            severity=severity,
            timeout=timeout,
        )
        return _json(
            {
                "target": target,
                "findings_count": len(findings),
                "findings": [
                    {
                        "template_id": f.template_id,
                        "name": f.name,
                        "severity": f.severity,
                        "host": f.host,
                        "matched_at": f.matched_at,
                        "description": f.description,
                        "cvss_score": f.cvss_score,
                        "cve_ids": f.cve_ids,
                        "references": f.reference_urls,
                        "extracted": f.extracted_results[:5] if f.extracted_results else [],
                    }
                    for f in findings
                ],
            }
        )
    except ValueError as e:
        return _json({"error": str(e)})
    except Exception as e:
        log.exception("nuclei_scan_error", target=target)
        return _json({"error": f"nuclei_scan failed: {e}"})


@tool
async def nuclei_update_templates() -> str:
    """Met à jour les templates Nuclei depuis le dépôt communautaire.

    WHEN TO USE: Avant un scan nuclei important, pour s'assoirer d'avoir
    les tous derniers templates de détection de CVE. Nuclei télécharge
    automatiquement les templates dans ``~/.local/nuclei-templates/``.

    Returns:
        JSON avec le statut de la mise à jour.
    """
    log.info("nuclei_update_templates")
    try:
        await NucleiScanner.update_templates()
        return _json({"status": "ok", "message": "Templates Nuclei mis à jour avec succès"})
    except Exception as e:
        log.exception("nuclei_update_templates_error")
        return _json({"error": f"nuclei_update_templates failed: {e}"})


# ── Outils TCP Scanner ─────────────────────────────────────────────────


@tool
async def tcp_connect_scan(
    ip: str,
    port: int,
    timeout: float = 5.0,
) -> str:
    """Scan TCP Connect sur un port unique.

    WHEN TO USE: Vérification rapide d'un port spécifique sur une cible.
    Ouvre une connexion TCP complète (pas de SYN stealth). Utile pour
    confirmer un port ouvert avant d'y lancer un scan plus profond.

    Args:
        ip: Adresse IP de la cible.
        port: Port à scanner (ex: 22, 80, 443, 3389).
        timeout: Timeout en secondes pour la connexion (défaut: 5s).

    Returns:
        JSON avec le statut du port (open, closed, filtered), le service
        identifié par banner grabbing, et la latence.
    """
    log.info("tcp_connect_scan", ip=ip, port=port)
    try:
        results = await _tcp_scan(ip=ip, ports=[port], timeout=timeout)
        if results:
            return _json(_port_result_to_dict(results[0]))
        return _json({"port": port, "state": "unknown"})
    except Exception as e:
        log.exception("tcp_connect_scan_error", ip=ip, port=port)
        return _json({"error": f"tcp_connect_scan failed: {e}"})


@tool
async def tcp_port_range_scan(
    ip: str,
    ports: list[int],
    timeout: float = 5.0,
    max_concurrency: int = 50,
) -> str:
    """Scan TCP Connect sur une liste ou un range de ports.

    WHEN TO USE: Scan multi-ports pour découvrir les services exposés
    sur une cible. Utilise asyncio avec un sémaphore pour contrôler
    la concurrence. Idéal pour un scan réseau rapide sans nmap.

    Args:
        ip: Adresse IP de la cible.
        ports: Liste des ports à scanner.
                Ex: [22, 80, 443, 8080, 8443] ou range via Python.
        timeout: Timeout par port en secondes (défaut: 5s).
        max_concurrency: Nombre max de connexions simultanées (défaut: 50).

    Returns:
        JSON listant tous les ports scannés avec leur état, service
        identifié et latence.
    """
    log.info("tcp_port_range_scan", ip=ip, ports_count=len(ports))
    try:
        results = await _tcp_scan(
            ip=ip,
            ports=ports,
            timeout=timeout,
            max_concurrency=max_concurrency,
        )
        return _json(
            {
                "ip": ip,
                "ports_scanned": len(results),
                "ports_open": sum(1 for r in results if r.state == "open"),
                "results": [_port_result_to_dict(r) for r in results],
            }
        )
    except Exception as e:
        log.exception("tcp_port_range_scan_error", ip=ip)
        return _json({"error": f"tcp_port_range_scan failed: {e}"})


# ── Outils VulnDatabase ────────────────────────────────────────────────


@tool
def vulndb_lookup_cve(cve_id: str) -> str:
    """Recherche une CVE dans la base de signatures locale.

    WHEN TO USE: Pour obtenir les détails d'une CVE spécifique (score
    CVSS, description, service affecté, plage de versions vulnérables).
    Base de données offline intégrée — ne nécessite pas d'accès API.

    Args:
        cve_id: Identifiant CVE complet (ex: ``"CVE-2021-41773"``,
                ``"CVE-2024-6387"``).

    Returns:
        JSON avec les détails de la CVE si trouvée, ou un message
        d'erreur si introuvable.
    """
    log.info("vulndb_lookup_cve", cve_id=cve_id)
    try:
        db = _get_vulndb()
        # On parcourt toutes les signatures pour trouver la CVE
        if not db._loaded:
            db.load()
        for sig in db._signatures:
            if sig.get("cve", "").upper() == cve_id.strip().upper():
                return _json(sig)
        return _json({"error": f"CVE '{cve_id}' non trouvée dans la base locale"})
    except Exception as e:
        log.exception("vulndb_lookup_cve_error", cve_id=cve_id)
        return _json({"error": f"vulndb_lookup_cve failed: {e}"})


@tool
def vulndb_check_service(service: str, version: str) -> str:
    """Vérifie si un service+version a des CVE connues dans la base locale.

    WHEN TO USE: Après avoir identifié un service et sa version via
    nmap_scan_services ou tcp_connect_scan, utilisez ce tool pour
    savoir s'il existe des vulnérabilités connues (offline).

    Args:
        service: Nom du service (ex: ``"apache"``, ``"openssh"``,
                ``"redis"``, ``"nginx"``, ``"mysql"``). Insensible
                à la casse.
        version: Version détectée (ex: ``"2.4.49"``, ``"8.9p1"``,
                ``"6.2.7"``).

    Returns:
        JSON listant les CVE correspondantes avec sévérité,
        description et références.
    """
    log.info("vulndb_check_service", service=service, version=version)
    try:
        db = _get_vulndb()
        matches = db.check(service=service, version=version)
        return _json(
            {
                "service": service,
                "version": version,
                "matches_count": len(matches),
                "matches": matches,
            }
        )
    except Exception as e:
        log.exception("vulndb_check_service_error", service=service, version=version)
        return _json({"error": f"vulndb_check_service failed: {e}"})


# ── Catalogue ──────────────────────────────────────────────────────────

NAVMAX_SCANNER_TOOLS = [
    nmap_scan,
    nmap_scan_os,
    nmap_scan_services,
    nmap_scan_vuln,
    nuclei_scan,
    nuclei_update_templates,
    tcp_connect_scan,
    tcp_port_range_scan,
    vulndb_lookup_cve,
    vulndb_check_service,
]
