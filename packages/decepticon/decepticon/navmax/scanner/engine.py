"""Moteur de scan — orchestre les scans, persiste les résultats en base."""

import asyncio
import json
from datetime import UTC, datetime

from decepticon.navmax.core.config import config
from decepticon.navmax.core.logging import get_logger
from decepticon.navmax.db import Scan, Service, Target, async_session

from .fingerprint import detect_os, detect_service
from .tcp import PortResult, tcp_connect_scan

logger = get_logger(__name__)


def parse_ports(ports_str: str) -> list[int]:
    """Parse une chaîne de ports style Nmap : "22,80,443" ou "1-1000,3306"."""
    ports: list[int] = []
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            ports.extend(range(lo, hi + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


async def run_scan(scan_id: str) -> None:
    """Exécute un scan complet :
    1. TCP Connect Scan
    2. Détection de services sur les ports ouverts
    3. Fingerprinting OS
    4. Persistance en base.

    Cette fonction est conçue pour tourner en arrière-plan (via asyncio.create_task).
    """
    now = datetime.now(UTC)

    async with async_session() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            logger.error("scan_introuvable", scan_id=scan_id)
            return

        target = await db.get(Target, scan.target_id)
        if target is None:
            logger.error("cible_introuvable", target_id=scan.target_id)
            scan.status = "failed"
            scan.error_message = "Cible introuvable"
            await db.commit()
            return

        # Marquer comme en cours
        scan.status = "running"
        scan.started_at = now
        scan.progress = 0.0
        await db.commit()

        ip = target.address
        ports = parse_ports(scan.ports or config.scanner_default_ports)

        logger.info("scan_démarrage", scan_id=scan_id, ip=ip, ports=len(ports))

        try:
            # ---- Phase 1 : TCP Connect Scan ----
            results: list[PortResult] = await tcp_connect_scan(
                ip=ip,
                ports=ports,
                timeout=config.scanner_default_timeout,
                max_concurrency=config.scanner_max_concurrency,
            )
            open_results = [r for r in results if r.state == "open"]
            scan.progress = 60.0
            await db.commit()

            # ---- Phase 2 : Détection de services ----
            for port_result in open_results:
                service_info = await detect_service(
                    ip=ip,
                    port=port_result.port,
                    protocol=port_result.protocol,
                )
                db.add(
                    Service(
                        target_id=scan.target_id,
                        scan_id=scan.id,
                        port=port_result.port,
                        protocol=port_result.protocol,
                        state=port_result.state,
                        service_name=service_info.get("service") or port_result.service,
                        banner=service_info.get("banner") or port_result.banner,
                        version=service_info.get("version") or port_result.version,
                        extra_data=json.dumps(service_info.get("details", {})),
                    ),
                )

            scan.progress = 85.0
            await db.commit()

            # ---- Phase 3 : Fingerprinting OS ----
            os_info = await detect_os(ip)

            scan.progress = 95.0

            # ---- Phase 4 : Résumé ----
            summary_parts = [
                f"Ports scannés : {len(ports)}",
                f"Ports ouverts : {len(open_results)}",
                f"Services détectés : {len(open_results)}",
                f"OS probable : {os_info.get('os', 'inconnu')} ({os_info.get('confidence', 'low')})",
            ]

            if open_results:
                ports_str = ", ".join(str(r.port) for r in open_results[:20])
                summary_parts.append(f"Ports ouverts : {ports_str}")

            scan.result_summary = " | ".join(summary_parts)
            scan.raw_result = json.dumps(
                {
                    "ports": [(r.port, r.state, r.service, r.banner) for r in results],
                    "os": os_info,
                },
                ensure_ascii=False,
            )

            scan.status = "completed"
            scan.progress = 100.0
            scan.finished_at = datetime.now(UTC)

            target.alive = True
            target.updated_at = datetime.now(UTC)

            await db.commit()
            logger.info("scan_terminé", scan_id=scan_id, open=len(open_results))

        except TimeoutError:
            logger.warning("scan_timeout", scan_id=scan_id)
            scan.status = "failed"
            scan.error_message = "Timeout dépassé"
            scan.finished_at = datetime.now(UTC)
            await db.commit()
        except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
            logger.warning("scan_erreur_réseau", scan_id=scan_id, error=str(e))
            scan.status = "failed"
            scan.error_message = f"Erreur réseau : {e}"
            scan.finished_at = datetime.now(UTC)
            await db.commit()
        except Exception as e:
            logger.exception("scan_erreur_inattendue", scan_id=scan_id)
            scan.status = "failed"
            scan.error_message = str(e)
            scan.finished_at = datetime.now(UTC)
            await db.commit()


def _on_scan_task_done(task: asyncio.Task, scan_id: str) -> None:
    """Callback de fin de tâche — log les erreurs non gérées."""
    exc = task.exception() if not task.cancelled() else None
    if exc:
        logger.error("scan_task_exception_non_gérée", scan_id=scan_id, error=repr(exc))


async def run_scan_background(scan_id: str) -> None:
    """Lance un scan en arrière-plan dans la boucle d'événements."""
    task = asyncio.create_task(run_scan(scan_id))
    task.add_done_callback(lambda t: _on_scan_task_done(t, scan_id))
    logger.info("scan_arrière_plan", scan_id=scan_id)
