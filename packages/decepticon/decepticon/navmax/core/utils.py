"""Utilitaires partagés — fonctions helper utilisées dans plusieurs modules NavMAX."""

import asyncio

import structlog

logger = structlog.get_logger(__name__)


async def safe_close_writer(
    writer: asyncio.StreamWriter | None,
    module: str = "unknown",
) -> None:
    """Ferme proprement un StreamWriter asyncio.

    Gère les erreurs de fermeture et loggue les problèmes.

    Args:
        writer: Le writer à fermer (peut être None).
        module: Nom du module appelant pour le logging.

    """
    if writer is None:
        return
    try:
        writer.close()
        await writer.wait_closed()
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        logger.debug("safe_close_error", module=module, error=str(e))
    except Exception as e:
        logger.warning("safe_close_unexpected_error", module=module, error=str(e))
