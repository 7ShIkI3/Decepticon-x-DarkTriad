"""OSINTMonitor — surveillance continue de domaines/IP avec alertes sur changements.

Permet de "s'abonner" à une cible : NavMAX collecte périodiquement et
détecte les changements (nouveau sous-domaine, nouveau certificat, etc.)
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class MonitorSubscription:
    """Un abonnement de surveillance."""

    id: str
    target: str  # domaine ou IP
    interval_hours: int = 24
    alert_on: list[str] = field(
        default_factory=lambda: [
            "new_subdomain",
            "new_cert",
            "new_service",
            "ip_change",
            "cert_expiry",
        ],
    )
    last_check: datetime | None = None
    last_snapshot: dict | None = None
    enabled: bool = True


@dataclass
class ChangeAlert:
    """Une alerte de changement détecté."""

    subscription_id: str
    target: str
    change_type: str  # new_subdomain, new_cert, ip_change, etc.
    description: str
    old_value: str | None = None
    new_value: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class OSINTMonitor:
    """Surveillance continue avec détection de changements.

    Usage:
        monitor = OSINTMonitor(osint_orchestrator)
        sub = await monitor.subscribe("example.com", interval_hours=24)
        alerts = await monitor.check(sub)
    """

    def __init__(self, orchestrator=None, graph_engine=None, notifier=None) -> None:
        """Args:
        orchestrator: OSINTOrchestrator pour les collectes
        graph_engine: GraphEngine pour stocker les résultats
        notifier: Callable(alert) pour envoyer des notifications.

        """
        self.orchestrator = orchestrator
        self.graph = graph_engine
        self.notifier = notifier
        self._subscriptions: dict[str, MonitorSubscription] = {}

    async def subscribe(
        self, target: str, interval_hours: int = 24, alert_on: list[str] | None = None,
    ) -> MonitorSubscription:
        """Crée un abonnement de surveillance.

        Args:
            target: Domaine ou IP à surveiller
            interval_hours: Fréquence de vérification
            alert_on: Types de changements à alerter

        """
        import uuid

        sub = MonitorSubscription(
            id=str(uuid.uuid4()),
            target=target,
            interval_hours=interval_hours,
            alert_on=alert_on
            or [
                "new_subdomain",
                "new_cert",
                "new_service",
                "ip_change",
                "cert_expiry",
            ],
        )
        self._subscriptions[sub.id] = sub
        logger.info("monitor_subscribed", id=sub.id, target=target, interval_h=interval_hours)
        return sub

    async def unsubscribe(self, sub_id: str) -> bool:
        if sub_id in self._subscriptions:
            del self._subscriptions[sub_id]
            return True
        return False

    async def check(self, sub: MonitorSubscription) -> list[ChangeAlert]:
        """Vérifie les changements pour un abonnement.

        Returns:
            Liste de ChangeAlert pour chaque changement détecté.

        """
        alerts: list[ChangeAlert] = []

        # Collecter les données actuelles
        current = await self._collect(sub.target)
        sub.last_check = datetime.now(UTC)

        if sub.last_snapshot:
            # Comparer avec le snapshot précédent
            alerts = self._diff(sub, sub.last_snapshot, current)

        sub.last_snapshot = current

        # Notifier
        if alerts and self.notifier:
            for alert in alerts:
                try:
                    await self.notifier(alert)
                except (TypeError, ValueError, RuntimeError) as e:
                    logger.exception("notify_failed", error=str(e))

        return alerts

    async def check_all(self) -> dict[str, list[ChangeAlert]]:
        """Vérifie tous les abonnements actifs."""
        results = {}
        for sub_id, sub in self._subscriptions.items():
            if sub.enabled:
                results[sub_id] = await self.check(sub)
        return results

    async def _collect(self, target: str) -> dict:
        """Collecte les données OSINT actuelles pour une cible."""
        snapshot = {"target": target, "timestamp": datetime.now(UTC).isoformat()}

        if self.orchestrator:
            try:
                result = await self.orchestrator.investigate_domain(target)
                if result:
                    # Extraire sous-domaines
                    subdomains = []
                    for entity in getattr(result, "subdomains", []):
                        subdomains.append(entity.value if hasattr(entity, "value") else str(entity))
                    snapshot["subdomains"] = sorted(subdomains)

                    # Extraire IPs
                    ips = []
                    for entity in getattr(result, "ip_addresses", []):
                        ips.append(entity.value if hasattr(entity, "value") else str(entity))
                    snapshot["ips"] = sorted(ips)
            except (RuntimeError, OSError, ValueError, AttributeError) as e:
                logger.warning("collect_failed", target=target, error=str(e))

        return snapshot

    def _diff(self, sub: MonitorSubscription, old: dict, new: dict) -> list[ChangeAlert]:
        """Compare deux snapshots et génère des alertes."""
        alerts = []

        # Nouveaux sous-domaines
        if "new_subdomain" in sub.alert_on:
            old_subs = set(old.get("subdomains", []))
            new_subs = set(new.get("subdomains", []))
            added = new_subs - old_subs
            for sd in added:
                alerts.append(
                    ChangeAlert(
                        subscription_id=sub.id,
                        target=sub.target,
                        change_type="new_subdomain",
                        description=f"New subdomain discovered: {sd}",
                        new_value=sd,
                    ),
                )
            removed = old_subs - new_subs
            for sd in removed:
                alerts.append(
                    ChangeAlert(
                        subscription_id=sub.id,
                        target=sub.target,
                        change_type="subdomain_removed",
                        description=f"Subdomain no longer resolving: {sd}",
                        old_value=sd,
                    ),
                )

        # Changement d'IP
        if "ip_change" in sub.alert_on:
            old_ips = set(old.get("ips", []))
            new_ips = set(new.get("ips", []))
            changed = new_ips != old_ips
            if changed and old_ips and new_ips:
                alerts.append(
                    ChangeAlert(
                        subscription_id=sub.id,
                        target=sub.target,
                        change_type="ip_change",
                        description=f"IP addresses changed: {old_ips} → {new_ips}",
                        old_value=str(old_ips),
                        new_value=str(new_ips),
                    ),
                )

        return alerts

    def get_subscription(self, sub_id: str) -> MonitorSubscription | None:
        return self._subscriptions.get(sub_id)

    def list_subscriptions(self) -> list[MonitorSubscription]:
        return list(self._subscriptions.values())
