"""Logging structuré avec structlog — sortie JSON ou console."""

import logging

import structlog

from .config import config


def setup_logging() -> None:
    """Configure le logging structuré global."""
    timestamper = structlog.processors.TimeStamper(fmt="iso")

    shared_processors: list = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        timestamper,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        structlog.dev.set_exc_info,
    ]

    if config.log_format == "json":
        renderer: structlog.processors.JSONRenderer | structlog.dev.ConsoleRenderer = (
            structlog.processors.JSONRenderer()
        )
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    # Logger racine standard
    logging.basicConfig(
        format="%(message)s",
        stream=None,
        level=getattr(logging, config.log_level.upper(), logging.INFO),
    )

    structlog.configure(
        processors=[*shared_processors, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Formatter pour les loggers standard
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    root_logger.handlers = [handler]

    # Silence les loggers bruyants
    for noisy in ("uvicorn.access", "httpx", "scapy", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Retourne un logger structuré pour le module donné."""
    return structlog.get_logger(name or __name__)
    # Le logger peut être un BoundLoggerLazyProxy si structlog
    # n'a pas encore été configuré — c'est normal, il se résoudra
    # au premier appel d'enregistrement.
