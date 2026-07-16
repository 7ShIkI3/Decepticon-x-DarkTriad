"""Gestionnaire de tâches Celery — statut, annulation, liste des tâches."""

from typing import Any

from decepticon.navmax.core.logging import get_logger
from decepticon.navmax.tasks import celery_app

logger = get_logger(__name__)


class TaskManager:
    """Gestionnaire de tâches Celery — statut, annulation, liste.

    Utilise l'API de contrôle Celery (inspect/revoke) et AsyncResult
    pour interroger et manipuler les tâches soumises au worker.
    """

    # ── Annulation ──────────────────────────────────────────────

    @staticmethod
    def cancel_task(task_id: str) -> bool:
        """Annule une tâche Celery par son identifiant.

        Args:
            task_id: Identifiant unique de la tâche à annuler

        Returns:
            True si la révocation a été envoyée, False si la tâche
            n'existe pas ou est déjà terminée

        """
        try:
            celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")
            logger.info("task_annulee", task_id=task_id)
            return True
        except (OSError, RuntimeError, ValueError) as e:
            logger.exception("task_annulation_echouee", task_id=task_id, error=str(e))
            return False

    @staticmethod
    def cancel_tasks(task_ids: list[str]) -> dict[str, bool]:
        """Annule plusieurs tâches en une seule opération.

        Args:
            task_ids: Liste des identifiants de tâches à annuler

        Returns:
            Dict associant chaque task_id à son statut d'annulation

        """
        results = {}
        for tid in task_ids:
            results[tid] = TaskManager.cancel_task(tid)
        return results

    # ── Liste des tâches actives / en attente / programmées ─────

    @staticmethod
    def list_active_tasks() -> list[dict]:
        """Liste les tâches actuellement en cours d'exécution.

        Returns:
            Liste de dicts avec les informations des tâches actives.
            Chaque dict contient : id, name, args, kwargs, time_start,
            worker, hostname.

            Retourne une liste vide si le worker est injoignable.

        """
        try:
            i = celery_app.control.inspect()
            active = i.active() or {}

            tasks = []
            for worker_name, worker_tasks in active.items():
                for t in worker_tasks:
                    tasks.append(TaskManager._format_task(t, worker_name))

            return tasks
        except (OSError, RuntimeError, AttributeError) as e:
            logger.exception("list_active_echouee", error=str(e))
            return []

    @staticmethod
    def list_scheduled_tasks() -> list[dict]:
        """Liste les tâches programmées (future execution).

        Returns:
            Liste de dicts des tâches programmées avec leur ETA

        """
        try:
            i = celery_app.control.inspect()
            scheduled = i.scheduled() or {}

            tasks = []
            for worker_name, worker_tasks in scheduled.items():
                for t in worker_tasks:
                    request = t.get("request", {})
                    tasks.append(
                        {
                            "id": request.get("id", ""),
                            "name": request.get("name", ""),
                            "args": request.get("args", []),
                            "kwargs": request.get("kwargs", {}),
                            "eta": t.get("eta"),
                            "priority": t.get("priority", 0),
                            "worker": worker_name,
                        },
                    )

            return tasks
        except (OSError, RuntimeError, AttributeError) as e:
            logger.exception("list_scheduled_echouee", error=str(e))
            return []

    @staticmethod
    def list_reserved_tasks() -> list[dict]:
        """Liste les tâches réservées (prêtes mais pas encore exécutées).

        Returns:
            Liste de dicts des tâches en attente dans la file

        """
        try:
            i = celery_app.control.inspect()
            reserved = i.reserved() or {}

            tasks = []
            for worker_name, worker_tasks in reserved.items():
                for t in worker_tasks:
                    tasks.append(TaskManager._format_task(t, worker_name))

            return tasks
        except (OSError, RuntimeError, AttributeError) as e:
            logger.exception("list_reserved_echouee", error=str(e))
            return []

    @staticmethod
    def list_all_tasks() -> dict[str, list[dict]]:
        """Liste toutes les tâches (actives + programmées + réservées).

        Returns:
            Dict avec trois clés : active, scheduled, reserved

        """
        return {
            "active": TaskManager.list_active_tasks(),
            "scheduled": TaskManager.list_scheduled_tasks(),
            "reserved": TaskManager.list_reserved_tasks(),
        }

    # ── Statut d'une tâche individuelle ─────────────────────────

    @staticmethod
    def get_task_status(task_id: str) -> dict[str, Any] | None:
        """Récupère le statut détaillé d'une tâche Celery.

        Utilise AsyncResult pour interroger le backend de résultats.

        Args:
            task_id: Identifiant unique de la tâche

        Returns:
            Dict avec les clés :
            - id: identifiant de la tâche
            - state: PENDING, STARTED, SUCCESS, FAILURE, RETRY, REVOKED
            - status: alias de state
            - meta: métadonnées (progress, status message)
            - result: résultat si terminé
            - traceback: traceback si échec
            - date_done: timestamp de fin

            Retourne None si la tâche est introuvable.

        """
        from celery.result import AsyncResult

        try:
            result = AsyncResult(task_id, app=celery_app)

            if result.result is None and result.state == "PENDING":
                # Tâche pas encore soumise ou résultat expiré
                return None

            meta = {}
            if result.result and isinstance(result.result, dict):
                meta = result.result.get("meta", result.result)

            return {
                "id": task_id,
                "state": result.state,
                "status": result.state,
                "meta": meta,
                "result": result.result,
                "traceback": result.traceback,
                "date_done": result.date_done.isoformat() if result.date_done else None,
                "successful": result.successful(),
                "failed": result.failed(),
            }
        except (OSError, RuntimeError, ValueError, AttributeError) as e:
            logger.exception("get_task_status_erreur", task_id=task_id, error=str(e))
            return None

    @staticmethod
    def get_tasks_status(task_ids: list[str]) -> dict[str, dict[str, Any] | None]:
        """Récupère le statut de plusieurs tâches en une fois.

        Args:
            task_ids: Liste des identifiants de tâches

        Returns:
            Dict associant chaque task_id à son statut (ou None si introuvable)

        """
        return {tid: TaskManager.get_task_status(tid) for tid in task_ids}

    # ── Informations sur les workers ────────────────────────────

    @staticmethod
    def list_workers() -> list[dict]:
        """Liste les workers Celery connectés avec leurs statistiques.

        Returns:
            Liste de dicts — un par worker connecté — contenant :
            hostname, pid, broker, clock, stat总数, etc.

        """
        try:
            i = celery_app.control.inspect()
            stats = i.stats() or {}
            ping_results = i.ping() or {}

            workers = []
            for worker_name, stat_data in stats.items():
                registered_tasks = stat_data.get("registered", [])
                worker_info = {
                    "hostname": worker_name,
                    "pid": stat_data.get("pid"),
                    "total_tasks": stat_data.get("total", {}),
                    "active_tasks": stat_data.get("active", 0),
                    "processed": stat_data.get("processed", 0),
                    "load_average": stat_data.get("loadavg", []),
                    "prefetch_count": stat_data.get("prefetch_count", 0),
                    "registered_tasks": [t for t in registered_tasks if isinstance(t, str)],
                    "alive": ping_results.get(worker_name) == "pong",
                    "freq_heartbeat": stat_data.get("freq_heartbeat"),
                    "heartbeat_interval": stat_data.get("heartbeat_interval"),
                }
                workers.append(worker_info)

            return workers
        except (OSError, RuntimeError, AttributeError) as e:
            logger.exception("list_workers_echouee", error=str(e))
            return []

    @staticmethod
    def ping_workers() -> dict[str, str]:
        """Pinge tous les workers et retourne leur disponibilité.

        Returns:
            Dict {worker_name: "pong" | "timeout" | "error"}

        """
        try:
            i = celery_app.control.inspect()
            return i.ping() or {}
        except (OSError, RuntimeError, AttributeError) as e:
            logger.exception("ping_workers_echouee", error=str(e))
            return {}

    # ── Configuration du cluster ────────────────────────────────

    @staticmethod
    def get_registered_tasks() -> list[str]:
        """Liste les tâches enregistrées dans l'application Celery.

        Returns:
            Liste des noms de tâches (strings)

        """
        try:
            i = celery_app.control.inspect()
            registered = i.registered() or {}
            all_tasks: set[str] = set()
            for tasks in registered.values():
                all_tasks.update(t.name if hasattr(t, "name") else str(t) for t in tasks)
            return sorted(all_tasks)
        except (OSError, RuntimeError, AttributeError) as e:
            logger.exception("registered_tasks_echouee", error=str(e))
            return list(celery_app.tasks.keys())

    # ── Helpers privés ──────────────────────────────────────────

    @staticmethod
    def _format_task(task_info: dict, worker_name: str = "") -> dict:
        """Formate une info de tâche brute Celery en dict structuré."""
        request = task_info.get("request", task_info)

        return {
            "id": request.get("id", ""),
            "name": request.get("name", ""),
            "args": list(request.get("args", [])),
            "kwargs": request.get("kwargs", {}),
            "time_start": request.get("time_start", ""),
            "worker": worker_name,
            "hostname": request.get("hostname", worker_name),
            "delivery_info": request.get("delivery_info", {}),
            "exchange": request.get("delivery_info", {}).get("exchange", ""),
            "routing_key": request.get("delivery_info", {}).get("routing_key", ""),
        }


# ── Instance de commodité ──────────────────────────────────────

task_manager = TaskManager()
