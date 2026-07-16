"""Repeater — rejoue des requêtes HTTP interceptées avec modifications."""

import time
from dataclasses import dataclass, field

import httpx

from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class RepeaterRequest:
    """Requête à rejouer."""

    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    follow_redirects: bool = True


@dataclass
class RepeaterResponse:
    """Réponse d'un replay."""

    status: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    error: str | None = None


@dataclass
class RepeaterHistory:
    """Historique des replays."""

    request: RepeaterRequest
    response: RepeaterResponse
    timestamp: float = field(default_factory=time.time)


class Repeater:
    """Rejoue des requêtes HTTP (comme Burp Repeater).
    Supporte HTTP et HTTPS.
    """

    def __init__(self) -> None:
        self._history: list[RepeaterHistory] = []
        self._client: httpx.AsyncClient | None = None

    @property
    def history(self) -> list[RepeaterHistory]:
        return list(self._history)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                verify=False,  # Pour les tests en local
                timeout=httpx.Timeout(30.0),
                follow_redirects=True,
            )
        return self._client

    async def send(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes | str = b"",
        follow_redirects: bool = True,
    ) -> RepeaterResponse:
        """Envoie une requête HTTP et retourne la réponse."""
        client = await self._get_client()
        headers = headers or {}

        req = RepeaterRequest(
            method=method.upper(),
            url=url,
            headers=dict(headers),
            body=body.encode() if isinstance(body, str) else body,
            follow_redirects=follow_redirects,
        )

        t0 = time.monotonic()
        try:
            resp = await client.request(
                method=req.method,
                url=req.url,
                headers=req.headers,
                content=req.body,
                follow_redirects=req.follow_redirects,
            )
            elapsed = (time.monotonic() - t0) * 1000

            result = RepeaterResponse(
                status=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text[:100_000],  # Tronquer à 100 Ko
                elapsed_ms=round(elapsed, 1),
            )
        except httpx.RequestError as e:
            result = RepeaterResponse(
                status=0,
                headers={},
                body="",
                elapsed_ms=(time.monotonic() - t0) * 1000,
                error=str(e),
            )

        self._history.append(RepeaterHistory(request=req, response=result))
        logger.info("repeater", method=method, url=url[:80], status=result.status)
        return result

    async def replay_from_flow(
        self,
        method: str,
        host: str,
        port: int,
        path: str,
        headers: dict[str, str],
        body: bytes = b"",
        use_https: bool = True,
    ) -> RepeaterResponse:
        """Rejoue une requête à partir des données d'un InterceptedFlow."""
        scheme = "https" if use_https else "http"
        host_header = headers.get("Host", host)
        url = f"{scheme}://{host_header}{path}"

        return await self.send(
            method=method,
            url=url,
            headers=headers,
            body=body,
        )

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
