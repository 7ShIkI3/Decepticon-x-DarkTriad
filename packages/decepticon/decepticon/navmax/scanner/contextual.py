"""ContextualScanEngine — scanner adaptatif qui enchaîne les probes selon les services détectés.

Principe : un port ouvert n'est qu'un début. Le scanner identifie le service,
puis lance automatiquement les probes adaptées (HTTP → dir busting, SMB → enum shares, etc.)
"""

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)


# ── Service → Actions mapping ──────────────────────────────────


@dataclass
class ServiceProbe:
    """Une probe contextuelle pour un service donné."""

    name: str
    description: str
    handler: Callable[..., Awaitable[dict]] | None = None
    required: bool = False


SERVICE_PROBES: dict[int | str, list[ServiceProbe]] = {
    80: [
        ServiceProbe("http_tech_fingerprint", "Détection technologies web"),
        ServiceProbe("http_dir_scan", "Scan répertoires communs"),
        ServiceProbe("http_methods", "Méthodes HTTP"),
    ],
    443: [
        ServiceProbe("ssl_analyze", "Certificat SSL"),
        ServiceProbe("https_tech_fingerprint", "Technologies web"),
        ServiceProbe("https_dir_scan", "Scan répertoires"),
    ],
    8080: [
        ServiceProbe("http_tech_fingerprint", "Technologies web (alt)"),
        ServiceProbe("tomcat_check", "Tomcat Manager"),
        ServiceProbe("jenkins_check", "Jenkins"),
    ],
    3306: [
        ServiceProbe("mysql_version", "Version MySQL", required=True),
        ServiceProbe("mysql_anonymous", "Accès anonyme"),
    ],
    5432: [
        ServiceProbe("postgres_version", "Version PostgreSQL", required=True),
    ],
    6379: [
        ServiceProbe("redis_info", "Commande INFO Redis", required=True),
        ServiceProbe("redis_unauth", "Accès non authentifié"),
    ],
    27017: [
        ServiceProbe("mongodb_list_dbs", "Listage BDD MongoDB"),
        ServiceProbe("mongodb_unauth", "Accès non authentifié"),
    ],
    445: [
        ServiceProbe("smb_enum_shares", "Partages SMB"),
        ServiceProbe("smb_os_detect", "Détection OS via SMB"),
        ServiceProbe("smb_signing", "Signature SMB"),
    ],
    22: [
        ServiceProbe("ssh_version", "Version SSH", required=True),
    ],
    21: [
        ServiceProbe("ftp_anonymous", "Anonymous FTP"),
        ServiceProbe("ftp_version", "Version FTP"),
    ],
    25: [
        ServiceProbe("smtp_version", "Version SMTP"),
        ServiceProbe("smtp_open_relay", "Test open relay"),
    ],
    53: [
        ServiceProbe("dns_version", "Version DNS"),
        ServiceProbe("dns_zone_transfer", "Transfert de zone"),
    ],
    2375: [ServiceProbe("docker_api", "Docker API exposée")],
    6443: [ServiceProbe("k8s_api", "Kubernetes API")],
    9200: [ServiceProbe("elasticsearch_info", "Elasticsearch")],
}


# ── Probe Implementations ──────────────────────────────────────


async def _probe_http_tech(host: str, port: int, ssl: bool = False) -> dict:
    import aiohttp

    from decepticon.navmax.core.http_client import get_aiohttp_session

    scheme = "https" if ssl else "http"
    try:
        session = await get_aiohttp_session()
        async with session.get(
            f"{scheme}://{host}:{port}/", timeout=5, ssl=False, allow_redirects=True,
        ) as resp:
            headers = dict(resp.headers)
            return {
                "status": resp.status,
                "server": headers.get("Server", ""),
                "powered_by": headers.get("X-Powered-By", ""),
            }
    except (TimeoutError, aiohttp.ClientError, OSError) as e:
        return {"error": str(e)}


async def _probe_dir_scan(host: str, port: int, ssl: bool = False) -> dict:
    import aiohttp

    from decepticon.navmax.core.http_client import get_aiohttp_session

    PATHS = [
        "/admin",
        "/login",
        "/wp-admin",
        "/phpmyadmin",
        "/.git",
        "/.env",
        "/backup",
        "/api",
        "/swagger",
        "/grafana",
        "/jenkins",
        "/console",
        "/actuator/health",
    ]
    scheme = "https" if ssl else "http"
    session = await get_aiohttp_session()

    async def _check(path: str) -> dict | None:
        try:
            async with session.get(
                f"{scheme}://{host}:{port}{path}", timeout=3, ssl=False, allow_redirects=False,
            ) as resp:
                if resp.status not in (404, 403):
                    return {"path": path, "status": resp.status}
        except (TimeoutError, aiohttp.ClientError, OSError):
            pass
        return None

    results = await asyncio.gather(*[_check(p) for p in PATHS])
    found = [r for r in results if r is not None]
    return {"found_dirs": found}


async def _probe_redis_info(host: str, port: int) -> dict:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)
    except (TimeoutError, ConnectionRefusedError, OSError) as e:
        return {"error": str(e)}

    text = ""
    try:
        writer.write(b"INFO\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=3)
        text = data.decode("utf-8", errors="replace")
    except (TimeoutError, OSError) as e:
        return {"error": str(e)}
    finally:
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()

    info = {}
    for line in text.splitlines():
        if ":" in line and not line.startswith("#"):
            k, v = line.split(":", 1)
            info[k] = v.strip()
    return {"redis_version": info.get("redis_version", ""), "os": info.get("os", "")}


async def _probe_ssh_version(host: str, port: int) -> dict:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)
    except (TimeoutError, ConnectionRefusedError, OSError) as e:
        return {"error": str(e)}

    text = ""
    try:
        banner = await asyncio.wait_for(reader.read(256), timeout=3)
        text = banner.decode("utf-8", errors="replace").strip()
    except (TimeoutError, OSError) as e:
        return {"error": str(e)}
    finally:
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()

    return {"banner": text}


_PROBE_HANDLERS = {
    "http_tech_fingerprint": _probe_http_tech,
    "https_tech_fingerprint": lambda h, p: _probe_http_tech(h, p, ssl=True),
    "http_dir_scan": _probe_dir_scan,
    "https_dir_scan": lambda h, p: _probe_dir_scan(h, p, ssl=True),
    "redis_info": _probe_redis_info,
    "ssh_version": _probe_ssh_version,
}


# ── Contextual Scan Engine ─────────────────────────────────────


@dataclass
class ScanResult:
    host: str
    port: int
    service: str | None = None
    version: str | None = None
    banner: str | None = None
    probes: dict = field(default_factory=dict)
    vulnerabilities: list = field(default_factory=list)
    error: str | None = None


class ContextualScanEngine:
    """Scanner adaptatif : détecte un service → lance les probes contextuelles."""

    def __init__(self, vuln_db=None, ai_engine=None) -> None:
        self.vuln_db = vuln_db
        self.ai = ai_engine

    async def scan(self, host: str, ports: list[int], timeout: float = 2.0) -> list[ScanResult]:
        open_ports = await self._quick_scan(host, ports, timeout)
        logger.info("contextual_scan", host=host, open_ports=open_ports)

        results = []
        for port in open_ports:
            result = await self._probe_port(host, port, timeout)
            results.append(result)

        for result in results:
            await self._run_probes(result, timeout)

        if self.vuln_db:
            for result in results:
                if result.service and result.version:
                    result.vulnerabilities = self.vuln_db.check(result.service, result.version)

        return results

    async def _quick_scan(self, host: str, ports: list[int], timeout: float) -> list[int]:
        async def check(port: int):
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
                w.close()
                return port
            except (TimeoutError, ConnectionRefusedError, OSError):
                return None

        results = await asyncio.gather(*[check(p) for p in ports])
        return [p for p in results if p is not None]

    async def _probe_port(self, host: str, port: int, timeout: float) -> ScanResult:
        result = ScanResult(host=host, port=port)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout,
            )
        except (TimeoutError, ConnectionRefusedError, OSError) as e:
            result.error = str(e)
            result.service = _guess_by_port(port)
            return result

        try:
            writer.write(b"\r\n")
            await writer.drain()
            banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            text = banner.decode("utf-8", errors="replace").strip()
            result.banner = text
            result.service, result.version = _identify_service(port, text)
        except (TimeoutError, OSError) as e:
            result.error = str(e)
            result.service = _guess_by_port(port)
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
        return result

    async def _run_probes(self, result: ScanResult, timeout: float) -> None:
        probes = list(SERVICE_PROBES.get(result.port, []))
        probes += SERVICE_PROBES.get(result.service or "", [])

        if not probes:
            return

        async def _run_single(probe: ServiceProbe) -> None:
            handler = _PROBE_HANDLERS.get(probe.name)
            if not handler:
                return
            try:
                result.probes[probe.name] = await handler(result.host, result.port)
            except (TimeoutError, OSError, RuntimeError) as e:
                result.probes[probe.name] = {"error": str(e)}

        await asyncio.gather(*[_run_single(p) for p in probes])


# ── Service identification ─────────────────────────────────────


def _identify_service(port: int, banner: str) -> tuple[str | None, str | None]:
    b = banner.lower()
    if b.startswith("ssh-") or "openssh" in b:
        # SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
        # → return "ssh", "OpenSSH_8.9p1"
        parts = banner.split()
        for p in parts:
            if p.lower().startswith("openssh") or p.lower().startswith("dropbear"):
                return "ssh", p
        return "ssh", parts[0] if len(parts) > 0 else None
    if any(s in b for s in ["http/", "html", "apache", "nginx", "iis"]):
        return "http", None
    if "mysql" in b or "mariadb" in b:
        return "mysql", None
    if "postgresql" in b:
        return "postgresql", None
    if "-err" in b or "+pong" in b or "redis" in b:
        return "redis", None
    if "mongodb" in b:
        return "mongodb", None
    if b.startswith("220") and "ftp" in b:
        return "ftp", None
    return _guess_by_port(port), None


def _guess_by_port(port: int) -> str | None:
    return {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        443: "https",
        445: "smb",
        3306: "mysql",
        5432: "postgresql",
        6379: "redis",
        8080: "http",
        8443: "https",
        9200: "elasticsearch",
        27017: "mongodb",
    }.get(port)
