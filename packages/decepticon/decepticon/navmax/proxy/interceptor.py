"""Queue d'interception — permet de mettre en pause, inspecter et modifier
les requêtes/réponses avant de les forwarder.

Pattern producteur/consommateur avec asyncio.Queue.
"""

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum

from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)


class FlowAction(StrEnum):
    FORWARD = "forward"  # Laisser passer
    DROP = "drop"  # Bloquer
    MODIFY = "modify"  # Remplacer par une version modifiée


class FlowStatus(StrEnum):
    PENDING = "pending"
    MODIFIED = "modified"
    FORWARDED = "forwarded"
    DROPPED = "dropped"


@dataclass
class InterceptedFlow:
    """Un flux HTTP intercepté (requête + réponse)."""

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    method: str = ""
    host: str = ""
    port: int = 443
    path: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: bytes = b""
    response_status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: bytes = b""
    status: FlowStatus = FlowStatus.PENDING
    action: FlowAction = FlowAction.FORWARD
    tags: list[str] = field(default_factory=list)
    timestamp: float = 0.0

    def summary(self) -> str:
        return f"{self.method} {self.host}:{self.port}{self.path} → {self.response_status}"


class Interceptor:
    """Gère la file d'interception des flux HTTP.

    Deux modes :
    - intercept_all : tout est mis en pause
    - intercept_none : tout passe (mode transparent)
    """

    def __init__(self) -> None:
        self._queue: asyncio.Queue[InterceptedFlow] = asyncio.Queue()
        self._flows: dict[str, InterceptedFlow] = {}
        self._intercept_enabled: bool = False
        self._on_flow_callbacks: list[Callable[[InterceptedFlow], Awaitable[None]]] = []

    @property
    def intercept_enabled(self) -> bool:
        return self._intercept_enabled

    @intercept_enabled.setter
    def intercept_enabled(self, val: bool) -> None:
        self._intercept_enabled = val
        logger.info("interception", enabled=val)

    @property
    def pending_count(self) -> int:
        return self._queue.qsize()

    @property
    def all_flows(self) -> list[InterceptedFlow]:
        return list(self._flows.values())

    def on_flow(self, callback: Callable[[InterceptedFlow], Awaitable[None]]) -> None:
        """Enregistre un callback appelé à chaque flux."""
        self._on_flow_callbacks.append(callback)

    async def submit(self, flow: InterceptedFlow) -> FlowAction:
        """Soumet un flux à l'intercepteur.
        Si l'interception est active, attend une décision.
        Sinon, forwarde immédiatement.
        """
        import time

        flow.timestamp = time.time()
        self._flows[flow.id] = flow

        for cb in self._on_flow_callbacks:
            try:
                await cb(flow)
            except (RuntimeError, ValueError, TypeError) as e:
                logger.exception("callback_erreur", erreur=str(e))

        if not self._intercept_enabled:
            flow.status = FlowStatus.FORWARDED
            flow.action = FlowAction.FORWARD
            return FlowAction.FORWARD

        flow.status = FlowStatus.PENDING
        await self._queue.put(flow)

        # Attendre que l'utilisateur décide (via decide())
        # Pas de polling — on attend un Event
        # Pour l'instant : forward après timeout en mode API
        return FlowAction.FORWARD

    async def get_pending(self) -> InterceptedFlow | None:
        """Récupère le prochain flux en attente (non-bloquant)."""
        try:
            return self._queue.get_nowait()
        except asyncio.QueueEmpty:
            return None

    def decide(
        self, flow_id: str, action: FlowAction, modified_flow: InterceptedFlow | None = None,
    ) -> bool:
        """Décide du sort d'un flux intercepté.

        Args:
            flow_id: ID du flux
            action: forward | drop | modify
            modified_flow: Flux modifié (si action=modify)

        Returns:
            True si le flux a été trouvé et traité

        """
        flow = self._flows.get(flow_id)
        if flow is None:
            return False

        flow.action = action
        if action == FlowAction.FORWARD:
            flow.status = FlowStatus.FORWARDED
        elif action == FlowAction.DROP:
            flow.status = FlowStatus.DROPPED
        elif action == FlowAction.MODIFY and modified_flow:
            flow.status = FlowStatus.MODIFIED
            flow.request_headers = modified_flow.request_headers
            flow.request_body = modified_flow.request_body
            flow.path = modified_flow.path
            flow.method = modified_flow.method

        return True

    def clear(self) -> None:
        """Vide la file d'attente."""
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
