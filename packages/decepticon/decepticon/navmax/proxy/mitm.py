"""Proxy MITM basé sur mitmproxy — interception TLS, capture de flux, replay.

Utilise mitmproxy comme librairie Python (pas le binaire).
Remplace proxy_server.py avec support HTTP/2, WebSocket, flow viewer.

Architecture :
- NavMITMProxy : classe publique avec interface identique à ProxyServer
- NavMITMAddon : addon mitmproxy pour la capture et l'interception
- CapturedFlow : dataclass pour les flux capturés
"""

import asyncio
import json
import ssl
import threading
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from decepticon.navmax.core.logging import get_logger
from decepticon.navmax.proxy.interceptor import Interceptor

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Vérification de la disponibilité de mitmproxy
# ---------------------------------------------------------------------------
try:
    from mitmproxy import connection, http, options
    from mitmproxy.addonmanager import LoadHook
    from mitmproxy.master import Master
    from mitmproxy.proxy.layers.http import (
        HttpErrorHook,
        HttpRequestHook,
        HttpResponseHook,
    )

    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False
    logger.warning("mitmproxy non installé — le proxy MITM avancé est désactivé")


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------
@dataclass
class CapturedFlow:
    """Flux HTTP/S capturé par le proxy MITM."""

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    method: str = ""
    url: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: bytes | None = None
    response_status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: bytes | None = None
    duration_ms: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convertit le flux en dictionnaire sérialisable."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "method": self.method,
            "url": self.url,
            "request_headers": dict(self.request_headers),
            "request_body": self.request_body.decode("utf-8", errors="replace")
            if self.request_body
            else None,
            "response_status": self.response_status,
            "response_headers": dict(self.response_headers),
            "response_body": self.response_body.decode("utf-8", errors="replace")[:100_000]
            if self.response_body
            else None,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }

    def to_har_entry(self) -> dict[str, Any]:
        """Exporte au format HAR (HTTP Archive)."""
        self.timestamp.timestamp()
        return {
            "startedDateTime": self.timestamp.isoformat(),
            "time": self.duration_ms,
            "request": {
                "method": self.method,
                "url": self.url,
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": [{"name": k, "value": v} for k, v in self.request_headers.items()],
                "queryString": [],
                "postData": (
                    {
                        "mimeType": self.request_headers.get("Content-Type", ""),
                        "text": self.request_body.decode("utf-8", errors="replace"),
                    }
                    if self.request_body
                    else {}
                ),
                "headersSize": -1,
                "bodySize": len(self.request_body) if self.request_body else -1,
            },
            "response": {
                "status": self.response_status,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": [{"name": k, "value": v} for k, v in self.response_headers.items()],
                "content": (
                    {
                        "size": len(self.response_body) if self.response_body else 0,
                        "mimeType": self.response_headers.get("Content-Type", ""),
                        "text": self.response_body.decode("utf-8", errors="replace")
                        if self.response_body
                        else "",
                    }
                ),
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": len(self.response_body) if self.response_body else -1,
            },
            "cache": {},
            "timings": {
                "send": 0,
                "wait": self.duration_ms,
                "receive": 0,
            },
        }


# ---------------------------------------------------------------------------
# Addon mitmproxy
# ---------------------------------------------------------------------------
if MITMPROXY_AVAILABLE:

    class NavMITMAddon:
        """Addon mitmproxy pour la capture/interception des flux HTTP/S.

        Hooks :
        - request(flow) : intercepte la requête avant envoi au serveur
        - response(flow) : capture la réponse après réception
        - error(flow) : capture les erreurs de flux
        """

        def __init__(
            self,
            interceptor: Interceptor | None = None,
            on_flow_captured: Callable[[CapturedFlow], Awaitable[None]] | None = None,
        ) -> None:
            self.interceptor = interceptor or Interceptor()
            self._flows: list[CapturedFlow] = []
            self._on_flow_captured = on_flow_captured
            self._max_flows: int = 1000

        def request(self, flow: http.HTTPFlow) -> None:
            """Hook déclenché à la réception d'une requête HTTP.

            Vérifie les filtres d'interception et logue la requête.
            """
            if not flow.request:
                return

            logger.debug(
                "proxy_requête",
                method=flow.request.method,
                url=flow.request.url[:200],
            )

        def response(self, flow: http.HTTPFlow) -> None:
            """Hook déclenché à la réception d'une réponse HTTP.

            Capture le couple requête/réponse dans la liste in-memory.
            """
            if not flow.request or not flow.response:
                return

            try:
                captured = self._flow_to_captured(flow)
                self._flows.append(captured)
                # Limiter la taille mémoire
                if len(self._flows) > self._max_flows:
                    self._flows = self._flows[-self._max_flows :]

                # Notifier les subscribers
                if self._on_flow_captured:
                    try:
                        # on_flow_captured doit être un callback synchrone ou asynchrone
                        result = self._on_flow_captured(captured)
                        if asyncio.iscoroutine(result):
                            # Dans la version actuelle de mitmproxy, response()
                            # est synchrone; on ne peut pas await ici.
                            # On schedule la coroutine dans une approche fire-and-forget
                            asyncio.ensure_future(result)
                    except (RuntimeError, ValueError, TypeError) as e:
                        logger.exception("callback_flux_erreur", erreur=str(e))

                logger.debug(
                    "proxy_réponse",
                    method=captured.method,
                    url=captured.url[:100],
                    status=captured.response_status,
                )
            except (AttributeError, KeyError, UnicodeDecodeError) as e:
                logger.exception("capture_flux_erreur", erreur=str(e))

        def error(self, flow: http.HTTPFlow) -> None:
            """Hook déclenché en cas d'erreur de flux."""
            if flow.error:
                captured = self._flow_to_captured(flow)
                captured.error = str(flow.error.msg)
                self._flows.append(captured)
                logger.debug(
                    "proxy_erreur",
                    url=flow.request.url[:100] if flow.request else "",
                    erreur=captured.error,
                )

        @staticmethod
        def _flow_to_captured(flow: http.HTTPFlow) -> CapturedFlow:
            """Convertit un HTTPFlow mitmproxy en CapturedFlow."""
            req = flow.request
            resp = flow.response

            # Headers request
            req_headers: dict[str, str] = {}
            if req.headers:
                for k, v in req.headers.items(True):
                    req_headers[k] = v

            # Headers response
            resp_headers: dict[str, str] = {}
            status = 0
            if resp:
                for k, v in resp.headers.items(True):
                    resp_headers[k] = v
                status = resp.status_code

            # Durée
            duration = 0.0
            if req.timestamp_start and resp and resp.timestamp_end:
                duration = (resp.timestamp_end - req.timestamp_start) * 1000
            elif req.timestamp_start and req.timestamp_end:
                duration = (req.timestamp_end - req.timestamp_start) * 1000

            # Timestamp
            ts = (
                datetime.fromtimestamp(
                    req.timestamp_start,
                    tz=UTC,
                )
                if req.timestamp_start
                else datetime.now(UTC)
            )

            return CapturedFlow(
                method=req.method,
                url=req.url,
                request_headers=req_headers,
                request_body=req.raw_content or None,
                response_status=status,
                response_headers=resp_headers,
                response_body=resp.raw_content if resp and resp.raw_content else None,
                duration_ms=round(duration, 1),
                timestamp=ts,
            )


class NavMITMProxy:
    """Proxy MITM basé sur mitmproxy.

    Wrapper autour de mitmproxy.master.Master pour une intégration
    simplifiée dans NavMAX. Interface compatible avec ProxyServer.

    Args:
        host: Adresse d'écoute du proxy
        port: Port d'écoute du proxy
        interceptor: Instance d'Interceptor optionnelle
        verify_upstream: Vérifier les certificats TLS upstream (True par défaut).
            Passer False pour accepter les certificats invalides (⚠️ risque sécurité).

    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        interceptor: Interceptor | None = None,
        verify_upstream: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.interceptor = interceptor or Interceptor()
        self.verify_upstream = verify_upstream

        self._master: Master | None = None
        self._addon: NavMITMAddon | None = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._running: bool = False

        # Callback pour les flux capturés
        self._on_flow_captured_callbacks: list[Callable[[CapturedFlow], Awaitable[None]]] = []

    # ------------------------------------------------------------------
    # Propriétés (interface compatible ProxyServer)
    # ------------------------------------------------------------------
    @property
    def running(self) -> bool:
        """Le proxy est-il en cours d'exécution ?"""
        return self._running

    @property
    def flow_count(self) -> int:
        """Nombre de flux capturés."""
        if self._addon:
            return len(self._addon._flows)
        return 0

    @property
    def recent_flows(self) -> list[CapturedFlow]:
        """Derniers flux capturés (max 200)."""
        if self._addon:
            return list(self._addon._flows[-200:])
        return []

    @property
    def ssl_insecure(self) -> bool:
        """Vérification TLS upstream désactivée ? (retourne ``not verify_upstream``).

        Pour compatibilité avec l'interface existante.
        """
        return not self.verify_upstream

    # ------------------------------------------------------------------
    # Cycle de vie
    # ------------------------------------------------------------------
    async def start(self) -> None:
        """Démarre le proxy MITM dans un thread séparé.

        Si mitmproxy n'est pas installé, logue un avertissement
        et ne fait rien.
        """
        if not MITMPROXY_AVAILABLE:
            logger.warning(
                "mitmproxy non installé — impossible de démarrer le proxy MITM",
            )
            return

        if self._running:
            logger.info("proxy_déjà_en_cours", host=self.host, port=self.port)
            return

        self._loop = asyncio.get_running_loop()

        if not self.verify_upstream:
            logger.warning(
                "⚠️ Vérification TLS upstream désactivée — les certificats "
                "invalides seront acceptés silencieusement",
            )

        # Créer les options mitmproxy
        opts = options.Options(
            listen_host=self.host,
            listen_port=self.port,
            ssl_insecure=not self.verify_upstream,
            http2=True,
            websocket=True,
        )

        # Créer le master
        self._master = Master(opts)

        # Créer et ajouter l'addon
        self._addon = NavMITMAddon(
            interceptor=self.interceptor,
            on_flow_captured=self._on_flow_captured,
        )
        self._master.addons.add(self._addon)

        # Démarrer dans un thread séparé
        self._running = True
        self._thread = threading.Thread(
            target=self._run_master,
            args=(self._master,),
            daemon=True,
            name="navmax-mitmproxy",
        )
        self._thread.start()

        # Attendre que le proxy soit prêt (petite pause)
        await asyncio.sleep(0.5)

        logger.info(
            "proxy_mitm_started",
            host=self.host,
            port=self.port,
            verify_upstream=self.verify_upstream,
        )

    async def stop(self) -> None:
        """Arrête le proxy MITM."""
        if not self._running or not self._master:
            logger.info("proxy_non_démarré")
            return

        self._running = False

        try:
            self._master.shutdown()
        except (RuntimeError, OSError) as e:
            logger.debug("arrêt_master", erreur=str(e))

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
            if self._thread.is_alive():
                logger.warning("thread_proxy_non_arrêté")

        self._master = None
        self._addon = None
        self._thread = None

        logger.info("proxy_mitm_arrêté")

    # ------------------------------------------------------------------
    # Gestion des flux
    # ------------------------------------------------------------------
    async def get_flows(
        self,
        since: datetime | None = None,
    ) -> list[CapturedFlow]:
        """Récupère les flux capturés, optionnellement filtrés par date.

        Args:
            since: Timestamp minimal (inclusif)

        Returns:
            Liste des flux capturés correspondant aux critères

        """
        if not self._addon:
            return []

        flows = list(self._addon._flows)
        if since:
            flows = [f for f in flows if f.timestamp >= since]
        return flows

    async def replay_flow(
        self,
        flow_id: str,
        modifications: dict[str, Any] | None = None,
    ) -> CapturedFlow:
        """Rejoue un flux capturé avec modifications optionnelles.

        Args:
            flow_id: ID du flux à rejouer
            modifications: Modifications à appliquer (method, url, headers, body)

        Returns:
            Nouveau flux résultant du replay

        """
        if not MITMPROXY_AVAILABLE:
            msg = "mitmproxy non installé — replay impossible"
            raise RuntimeError(msg)

        # Trouver le flux original
        original = None
        if self._addon:
            for f in self._addon._flows:
                if f.id == flow_id:
                    original = f
                    break

        if not original:
            msg = f"Flux introuvable : {flow_id}"
            raise ValueError(msg)

        # Appliquer les modifications
        method = modifications.get("method", original.method) if modifications else original.method
        url = modifications.get("url", original.url) if modifications else original.url
        headers = (
            dict(
                modifications.get("headers", original.request_headers),
            )
            if modifications
            else dict(original.request_headers)
        )
        body = (
            (
                modifications["body"].encode()
                if isinstance(modifications.get("body"), str)
                else modifications.get("body", original.request_body)
            )
            if modifications
            else original.request_body
        )

        # Créer la requête mitmproxy
        http.Request.make(
            method=method,
            url=url,
            content=body or b"",
            headers=headers,
        )

        # Envoyer via httpx
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(
                verify=self.verify_upstream,
                timeout=30.0,
            ) as client:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=body,
                )
            elapsed = (time.monotonic() - t0) * 1000

            # Construire le flux capturé
            result = CapturedFlow(
                method=method,
                url=url,
                request_headers=dict(headers),
                request_body=body,
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body=resp.content,
                duration_ms=round(elapsed, 1),
            )

            if self._addon:
                self._addon._flows.append(result)

            return result
        except (httpx.TimeoutException, httpx.RequestError, OSError, ssl.SSLError) as e:
            elapsed = (time.monotonic() - t0) * 1000
            result = CapturedFlow(
                method=method,
                url=url,
                request_headers=dict(headers),
                request_body=body,
                response_status=0,
                response_headers={},
                response_body=None,
                duration_ms=round(elapsed, 1),
                error=str(e),
            )
            if self._addon:
                self._addon._flows.append(result)
            return result

    async def export_har(self, flows: list[CapturedFlow] | None = None) -> str:
        """Exporte les flux au format HAR (HTTP Archive).

        Args:
            flows: Liste des flux à exporter (tous si None)

        Returns:
            Chaîne JSON au format HAR

        """
        if flows is None:
            flows = self.recent_flows

        har = {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "NavMAX MITM Proxy",
                    "version": "0.1.0",
                },
                "entries": [f.to_har_entry() for f in flows if f.response_status > 0],
            },
        }

        return json.dumps(har, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Callbacks / événements
    # ------------------------------------------------------------------
    def on_flow_captured(
        self,
        callback: Callable[[CapturedFlow], Awaitable[None]],
    ) -> None:
        """Enregistre un callback appelé à chaque flux capturé.

        Args:
            callback: Fonction asynchrone acceptant un CapturedFlow

        """
        self._on_flow_captured_callbacks.append(callback)

    # ------------------------------------------------------------------
    # Interception (délégation à l'Interceptor existant)
    # ------------------------------------------------------------------
    @property
    def intercept_enabled(self) -> bool:
        """L'interception est-elle activée ?"""
        return self.interceptor.intercept_enabled

    @intercept_enabled.setter
    def intercept_enabled(self, val: bool) -> None:
        self.interceptor.intercept_enabled = val

    # ------------------------------------------------------------------
    # Méthodes internes
    # ------------------------------------------------------------------
    def _run_master(self, master: Master) -> None:
        """Exécute le master mitmproxy (appelé dans un thread dédié).

        Args:
            master: Instance Master à exécuter

        """
        try:
            master.run()
        except (RuntimeError, OSError) as e:
            logger.exception("master_erreur", erreur=str(e))
            self._running = False

    async def _on_flow_captured(self, captured: CapturedFlow) -> None:
        """Callback interne appelé à chaque flux capturé.

        Propage aux callbacks enregistrés.
        """
        for cb in self._on_flow_captured_callbacks:
            try:
                await cb(captured)
            except (RuntimeError, ValueError, TypeError) as e:
                logger.exception("callback_flux_erreur", erreur=str(e))
