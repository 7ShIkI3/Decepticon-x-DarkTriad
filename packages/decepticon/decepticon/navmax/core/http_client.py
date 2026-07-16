"""Pool de connexions HTTP centralisé — httpx + aiohttp avec limites configurables.

Évite la création d'un nouveau ClientSession/AsyncClient à chaque appel,
ce qui gaspillait des sockets, du DNS et des handshakes TLS.

Usage:
    from decepticon.navmax.core.http_client import get_httpx_client, get_aiohttp_session
    client = await get_httpx_client()
    resp = await client.get("https://example.com")

    session = await get_aiohttp_session()
    async with session.get("https://example.com") as resp:
        ...
"""

import asyncio
from typing import Any

import aiohttp
import httpx
import structlog

logger = structlog.get_logger(__name__)

# ── Configuration des pools (créées paresseusement) ─────────────────

_HTTPX_LIMITS: httpx.Limits | None = None
_AIOHTTP_CONNECTOR: aiohttp.TCPConnector | None = None


def _get_httpx_limits() -> httpx.Limits:
    global _HTTPX_LIMITS
    if _HTTPX_LIMITS is None:
        _HTTPX_LIMITS = httpx.Limits(
            max_connections=100,
            max_keepalive_connections=20,
            keepalive_expiry=30.0,
        )
    return _HTTPX_LIMITS


async def _get_aiohttp_connector() -> aiohttp.TCPConnector:
    global _AIOHTTP_CONNECTOR
    if _AIOHTTP_CONNECTOR is None:
        _AIOHTTP_CONNECTOR = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=10,
            ttl_dns_cache=300,
            force_close=False,
            enable_cleanup_closed=True,
        )
    return _AIOHTTP_CONNECTOR

# ── Variables globales (singletons) ──────────────────────────────────

_httpx_client: httpx.AsyncClient | None = None
_aiohttp_session: aiohttp.ClientSession | None = None
_lock: asyncio.Lock | None = None


async def _get_lock() -> asyncio.Lock:
    """Retourne un asyncio.Lock — créé paresseusement pour éviter
    l'erreur 'no running event loop' à l'import.
    """
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


# ── httpx ───────────────────────────────────────────────────────────

async def get_httpx_client() -> httpx.AsyncClient:
    """Retourne le singleton httpx.AsyncClient avec pool de connexions.

    Première initialisation : crée le client avec les limites.
    Appels suivants : retourne le même client (connexions réutilisées).
    """
    global _httpx_client
    if _httpx_client is not None and not _httpx_client.is_closed:
        return _httpx_client

    async with await _get_lock():
        if _httpx_client is not None and not _httpx_client.is_closed:
            return _httpx_client
        _httpx_client = httpx.AsyncClient(
            limits=_get_httpx_limits(),
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=True,
            verify=True,
        )
        logger.debug("httpx_pool_initialisé", max_connections=100)
    return _httpx_client


async def close_httpx_client() -> None:
    """Ferme proprement le client httpx global."""
    global _httpx_client
    if _httpx_client and not _httpx_client.is_closed:
        await _httpx_client.aclose()
        _httpx_client = None
        logger.debug("httpx_pool_fermé")


# ── aiohttp ─────────────────────────────────────────────────────────

async def get_aiohttp_session(**kwargs: Any) -> aiohttp.ClientSession:
    """Retourne le singleton aiohttp.ClientSession avec pool.

    Les kwargs supplémentaires sont passés au constructeur
    seulement lors de la création initiale.
    """
    global _aiohttp_session
    if _aiohttp_session is not None and not _aiohttp_session.closed:
        return _aiohttp_session

    async with await _get_lock():
        if _aiohttp_session is not None and not _aiohttp_session.closed:
            return _aiohttp_session
        _aiohttp_session = aiohttp.ClientSession(
            connector=await _get_aiohttp_connector(),
            timeout=aiohttp.ClientTimeout(total=30),
            **kwargs,
        )
        logger.debug("aiohttp_pool_initialisé", limit=100, limit_per_host=10)
    return _aiohttp_session


async def close_aiohttp_session() -> None:
    """Ferme proprement la session aiohttp globale."""
    global _aiohttp_session
    if _aiohttp_session and not _aiohttp_session.closed:
        await _aiohttp_session.close()
        _aiohttp_session = None
        logger.debug("aiohttp_pool_fermé")


# ── Utilitaire : fermeture globale ─────────────────────────────────

async def close_all() -> None:
    """Ferme tous les pools de connexions."""
    await close_httpx_client()
    await close_aiohttp_session()
    logger.info("tous_les_pools_http_fermés")
