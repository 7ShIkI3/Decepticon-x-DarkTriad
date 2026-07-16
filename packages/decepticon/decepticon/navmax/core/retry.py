"""Décorateur async_retry avec backoff exponentiel."""

import asyncio
import functools
from collections.abc import Callable
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def async_retry(
    *,
    max_attempts: int = 3,
    backoff_base: float = 1.5,
    backoff_max: float = 30.0,
    exceptions: tuple[type[Exception], ...] = (Exception,),
    on_retry: Callable[[int, Exception], None] | None = None,
) -> Callable[[Any], Any]:
    """Décorateur pour les coroutines async avec retry + backoff exponentiel.

    Usage :
        @async_retry(max_attempts=3, exceptions=(httpx.TimeoutException,))
        async def fetch(url: str) -> bytes: ...
    """

    def decorator(fn: Any) -> Any:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exc: Exception | None = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return await fn(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt == max_attempts:
                        break
                    delay = min(backoff_base ** (attempt - 1), backoff_max)
                    logger.warning(
                        "retry_attempt",
                        function=fn.__name__,
                        attempt=attempt,
                        max_attempts=max_attempts,
                        delay_s=round(delay, 2),
                        error=str(exc),
                    )
                    if on_retry:
                        on_retry(attempt, exc)
                    await asyncio.sleep(delay)
            raise last_exc  # type: ignore[misc]

        return wrapper

    return decorator
