"""The Dark Triad — Resilience Patterns.

Provides production-grade resilience primitives: async retry with
exponential backoff + jitter, circuit breaker, graceful shutdown
signal handling, component health checking, and in-memory rate limiting.
"""

from __future__ import annotations

import asyncio
import random
import signal
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, ParamSpec, TypeVar

import httpx
import structlog

logger = structlog.get_logger(__name__)


# ── Typing helpers ─────────────────────────────────────────────────────────────

P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")


# ── Retry ──────────────────────────────────────────────────────────────────────


async def retry_async(
    func: Callable[P, Awaitable[R]],
    *args: P.args,
    max_retries: int = 3,
    backoff: float = 2.0,
    **kwargs: P.kwargs,
) -> R:
    """Execute *func* with exponential backoff, jitter, and logging on failure.

    Retries on any exception up to *max_retries* times. Each retry interval is
    ``backoff ** attempt`` seconds plus uniform jitter in ``[0, 0.5)``.

    Args:
        func: Async callable to invoke.
        *args: Positional arguments forwarded to *func*.
        max_retries: Maximum number of retry attempts (default 3).
        backoff: Exponential base for the backoff delay (default 2.0).
        **kwargs: Keyword arguments forwarded to *func*.

    Returns:
        The return value of *func* on the first successful invocation.

    Raises:
        The last exception raised by *func* if all retries are exhausted.
    """
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except Exception as exc:
            last_exc = exc
            if attempt < max_retries:
                delay = backoff**attempt + random.uniform(0, 0.5)
                logger.warning(
                    "retry_async attempt failed",
                    attempt=attempt + 1,
                    max_retries=max_retries,
                    delay_seconds=round(delay, 2),
                    error=str(exc),
                )
                await asyncio.sleep(delay)

    logger.error(
        "retry_async exhausted",
        max_retries=max_retries,
        error=str(last_exc),
    )
    # ``last_exc`` is guaranteed to be set after at least one iteration
    raise last_exc  # type: ignore[misc]


def retryable(
    max_retries: int = 3,
    backoff: float = 2.0,
) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """Decorator that wraps an async function with :func:`retry_async`.

    Usage::

        @retryable(max_retries=5, backoff=1.5)
        async def fetch_data(url: str) -> dict[str, Any]:
            ...

    Args:
        max_retries: Maximum number of retry attempts (default 3).
        backoff: Exponential base for the backoff delay (default 2.0).

    Returns:
        A decorator that applies retry logic to the decorated function.
    """

    def decorator(func: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            return await retry_async(
                func, *args, max_retries=max_retries, backoff=backoff, **kwargs
            )

        return wrapper

    return decorator


# ── Circuit Breaker ────────────────────────────────────────────────────────────


class CircuitState(Enum):
    """Circuit breaker state machine states.

    * **CLOSED** — normal operation, requests pass through.
    * **OPEN** — failing, requests are rejected immediately.
    * **HALF_OPEN** — testing, a single probe request is allowed.
    """

    CLOSED = auto()
    OPEN = auto()
    HALF_OPEN = auto()


class CircuitBreakerOpenError(Exception):
    """Raised when a request is rejected because the circuit is OPEN or HALF_OPEN."""


@dataclass
class CircuitBreaker:
    """Async context manager / decorator implementing the circuit breaker pattern.

    State machine transitions::

        CLOSED ──(max_failures consecutive failures)──▶ OPEN
        OPEN   ──(reset_timeout elapsed)───────────────▶ HALF_OPEN
        HALF_OPEN ──(probe succeeds)───────────────────▶ CLOSED
        HALF_OPEN ──(probe fails)──────────────────────▶ OPEN

    Usage as context manager::

        cb = CircuitBreaker(max_failures=5, reset_timeout=60.0)
        async with cb:
            result = await risky_call()

    Usage as decorator::

        @CircuitBreaker(max_failures=3, reset_timeout=30.0)
        async def my_func() -> str:
            ...
    """

    max_failures: int = 5
    reset_timeout: float = 60.0
    name: str = "default"

    # Internal state ########################################################
    _state: CircuitState = field(default=CircuitState.CLOSED, repr=False)
    _failure_count: int = field(default=0, repr=False)
    _last_failure_time: float = field(default=0.0, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    # ── Public API ────────────────────────────────────────────────────────

    @property
    def state(self) -> CircuitState:
        """Current circuit-breaker state."""
        return self._state

    @property
    def failure_count(self) -> int:
        """Number of consecutive failures since last success or reset."""
        return self._failure_count

    async def __aenter__(self) -> CircuitBreaker:
        await self._evaluate()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        if exc_type is None:
            self._on_success()
        elif issubclass(exc_type, Exception):
            await self._on_failure()
        # Do NOT suppress the exception — let it propagate

    def __call__(self, func: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
        """Decorate *func* with circuit-breaker protection."""

        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            async with self:
                return await func(*args, **kwargs)

        return wrapper

    # ── Internal state machine ─────────────────────────────────────────────

    async def _evaluate(self) -> None:
        """Determine whether the current request should be allowed through."""
        async with self._lock:
            if self._state == CircuitState.CLOSED:
                return

            if self._state == CircuitState.OPEN:
                elapsed = time.monotonic() - self._last_failure_time
                if elapsed >= self.reset_timeout:
                    logger.info(
                        "circuit_breaker half_open",
                        name=self.name,
                    )
                    self._state = CircuitState.HALF_OPEN
                    return

                raise CircuitBreakerOpenError(
                    f"Circuit '{self.name}' is OPEN. Retry in {self.reset_timeout - elapsed:.1f}s"
                )

            # HALF_OPEN — only a single probe is allowed; concurrent callers
            # are blocked so that the probe stays uncontested.
            raise CircuitBreakerOpenError(f"Circuit '{self.name}' is HALF_OPEN. Probe in progress.")

    def _on_success(self) -> None:
        """Record a successful call and reset to CLOSED if currently HALF_OPEN."""
        self._failure_count = 0
        if self._state == CircuitState.HALF_OPEN:
            logger.info("circuit_breaker closed", name=self.name)
            self._state = CircuitState.CLOSED

    async def _on_failure(self) -> None:
        """Record a failure and transition to OPEN if the threshold is met."""
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()

            if self._failure_count >= self.max_failures:
                logger.warning(
                    "circuit_breaker opened",
                    name=self.name,
                    failure_count=self._failure_count,
                    max_failures=self.max_failures,
                )
                self._state = CircuitState.OPEN


def circuit_breaker(
    max_failures: int = 5,
    reset_timeout: float = 60.0,
    name: str = "default",
) -> CircuitBreaker:
    """Create a :class:`CircuitBreaker` instance.

    Args:
        max_failures: Consecutive failures before opening the circuit (default 5).
        reset_timeout: Seconds before transitioning from OPEN to HALF_OPEN (default 60).
        name: Human-readable identifier for log messages (default ``"default"``).

    Returns:
        A configured :class:`CircuitBreaker`.
    """
    return CircuitBreaker(
        max_failures=max_failures,
        reset_timeout=reset_timeout,
        name=name,
    )


# ── Graceful Shutdown ──────────────────────────────────────────────────────────


class GracefulShutdown:
    """Async context manager that captures OS signals and runs cleanup callbacks.

    Typical usage::

        async with GracefulShutdown() as shutdown:
            shutdown.add_callback(close_db)
            shutdown.add_callback(close_http_client)
            await shutdown.wait()   # blocks until SIGINT or SIGTERM

        # Context exit: registered callbacks run in LIFO order, handlers
        # are restored, and the process can proceed to exit cleanly.

    Callbacks are executed in reverse registration order (LIFO) — register
    dependent services first, then the services they depend on.
    """

    def __init__(self, *signals: signal.Signals) -> None:
        """Initialise with the signals to intercept.

        Args:
            *signals: Signals to catch. Defaults to ``SIGINT`` and ``SIGTERM``.
        """
        self._signals: tuple[signal.Signals, ...] = signals or (
            signal.SIGINT,
            signal.SIGTERM,
        )
        self._callbacks: list[Callable[[], Awaitable[None]]] = []
        self._shutdown_event: asyncio.Event = asyncio.Event()
        self._orig_handlers: dict[int, Any] = {}

    def add_callback(self, cb: Callable[[], Awaitable[None]]) -> None:
        """Register an async cleanup callback.

        Args:
            cb: A zero-argument async callable to invoke during shutdown.
        """
        self._callbacks.append(cb)

    async def wait(self) -> None:
        """Block the current coroutine until a shutdown signal is received."""
        await self._shutdown_event.wait()

    async def __aenter__(self) -> GracefulShutdown:
        loop = asyncio.get_event_loop()

        def _signal_handler(sig: int, _frame: Any) -> None:
            logger.info("graceful_shutdown signal received", signal=sig)
            self._shutdown_event.set()

        for sig in self._signals:
            self._orig_handlers[sig] = signal.getsignal(sig)
            try:
                loop.add_signal_handler(sig, _signal_handler, sig, None)
            except NotImplementedError:
                # Windows / selectors-based event loops do not support
                # add_signal_handler; fall back to signal.signal().
                signal.signal(sig, _signal_handler)

        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        # Run callbacks in reverse registration order (LIFO)
        for cb in reversed(self._callbacks):
            try:
                await cb()
            except Exception as exc:
                logger.error(
                    "graceful_shutdown callback failed",
                    callback=cb.__name__,
                    error=str(exc),
                )

        # Restore original signal handlers
        for sig in self._signals:
            try:
                loop = asyncio.get_event_loop()
                loop.remove_signal_handler(sig)
            except (NotImplementedError, ValueError):
                pass
            orig = self._orig_handlers.get(sig)
            if orig is not None:
                signal.signal(sig, orig)

        logger.info("graceful_shutdown complete")


def graceful_shutdown(*signals: signal.Signals) -> GracefulShutdown:
    """Create a :class:`GracefulShutdown` context manager.

    Args:
        *signals: Signals to intercept. Defaults to ``SIGINT`` and ``SIGTERM``.

    Returns:
        A :class:`GracefulShutdown` instance ready for use as an async context manager.
    """
    return GracefulShutdown(*signals)


# ── Health Check ───────────────────────────────────────────────────────────────


async def health_check(
    ai_router: Any = None,  # tdt.core.ai_router.AIRouter instance
    sandbox: Any = None,  # tdt.core.sandbox.SandboxManager instance
    api_port: int = 8000,
    http_client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Check the health of all system components.

    Probes the following components when their instances are provided:

    * **ai_router** — checks whether :meth:`~tdt.core.ai_router.AIRouter.initialize`
      has been called and how many providers are available.
    * **sandbox** — queries the :class:`~tdt.core.sandbox.SandboxManager` for its
      current container status.
    * **api** — sends a ``GET /health`` request to the local FastAPI server.

    Args:
        ai_router: An initialised :class:`~tdt.core.ai_router.AIRouter` instance,
            or ``None`` to skip the AI-router probe.
        sandbox: A :class:`~tdt.core.sandbox.SandboxManager` instance, or ``None``
            to skip the sandbox probe.
        api_port: Port the FastAPI application is listening on (default 8000).
        http_client: An optional shared :class:`httpx.AsyncClient`. A short-lived
            client is created and closed automatically when omitted.

    Returns:
        A dict with the following top-level keys:

        * ``status`` — ``"healthy"`` if all probed components are OK, otherwise
          ``"degraded"``. Skipped components (``None``) do not degrade the status.
        * ``timestamp`` — ISO 8601 UTC timestamp of the check.
        * ``components`` — mapping of component names to their individual results.
          Each result contains ``"ok"`` (``bool`` or ``None`` if skipped),
          ``"details"`` (``dict``), and ``"error"`` (``str | None``).
    """
    components: dict[str, dict[str, Any]] = {}

    client = http_client or httpx.AsyncClient(timeout=httpx.Timeout(10.0))
    try:
        # ── AI Router ──────────────────────────────────────────────────────
        if ai_router is not None:
            try:
                status = getattr(ai_router, "_status", None)
                ai_ok = status is not None
                components["ai_router"] = {
                    "ok": ai_ok,
                    "details": (
                        {
                            "provider_count": len(status.providers),
                            "available_tiers": [t.value for t in status.available_tiers],
                        }
                        if status
                        else {}
                    ),
                    "error": (
                        None if ai_ok else "AIRouter not initialised — call initialize() first"
                    ),
                }
            except Exception as exc:
                components["ai_router"] = {
                    "ok": False,
                    "details": {},
                    "error": str(exc),
                }
        else:
            components["ai_router"] = {
                "ok": None,
                "details": {},
                "error": "No AIRouter provided — skipped",
            }

        # ── Sandbox ────────────────────────────────────────────────────────
        if sandbox is not None:
            try:
                sb_status = await sandbox.status()
                components["sandbox"] = {
                    "ok": sb_status.running,
                    "details": {
                        "running": sb_status.running,
                        "container_id": sb_status.container_id,
                        "image": sb_status.image,
                        "uptime_seconds": round(sb_status.uptime_seconds, 1),
                    },
                    "error": (None if sb_status.running else "Sandbox container is not running"),
                }
            except Exception as exc:
                components["sandbox"] = {
                    "ok": False,
                    "details": {},
                    "error": str(exc),
                }
        else:
            components["sandbox"] = {
                "ok": None,
                "details": {},
                "error": "No SandboxManager provided — skipped",
            }

        # ── API Health Endpoint ─────────────────────────────────────────────
        try:
            api_url = f"http://127.0.0.1:{api_port}/health"
            resp = await client.get(api_url)
            api_ok = resp.status_code == 200
            components["api"] = {
                "ok": api_ok,
                "details": {
                    "url": api_url,
                    "status_code": resp.status_code,
                    "response": resp.json() if api_ok else resp.text[:200],
                },
                "error": (None if api_ok else f"API returned HTTP {resp.status_code}"),
            }
        except httpx.ConnectError as exc:
            components["api"] = {
                "ok": False,
                "details": {},
                "error": f"API unreachable on port {api_port}: {exc}",
            }
        except Exception as exc:
            components["api"] = {
                "ok": False,
                "details": {},
                "error": str(exc),
            }

    finally:
        if http_client is None:
            await client.aclose()

    overall_ok = all(
        comp.get("ok") is True or comp.get("ok") is None for comp in components.values()
    )

    return {
        "status": "healthy" if overall_ok else "degraded",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "components": components,
    }


# ── Rate Limiter ───────────────────────────────────────────────────────────────


@dataclass
class RateLimiter:
    """Simple in-memory sliding-window rate limiter for API endpoints.

    Tracks call timestamps per key (e.g. per API route or client IP) and
    rejects calls that exceed *max_calls* within any *window*-second window.

    Usage::

        limiter = RateLimiter(max_calls=100, window=60)

        async def my_endpoint() -> JSONResponse:
            if not await limiter.check("my-endpoint"):
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
            ...
    """

    max_calls: int = 100
    window: float = 60.0

    _buckets: dict[str, list[float]] = field(default_factory=dict, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    async def check(self, key: str) -> bool:
        """Check and record a call for the given *key*.

        Args:
            key: Identifier to rate-limit by (route name, client IP, etc.).

        Returns:
            ``True`` if the call is within the limit, ``False`` if it exceeds
            the limit and should be rejected.
        """
        now = time.monotonic()
        cutoff = now - self.window

        async with self._lock:
            timestamps = self._buckets.get(key, [])
            # Prune entries outside the sliding window
            timestamps = [t for t in timestamps if t > cutoff]

            if len(timestamps) >= self.max_calls:
                self._buckets[key] = timestamps
                return False

            timestamps.append(now)
            self._buckets[key] = timestamps
            return True

    async def remaining(self, key: str) -> int:
        """Return the number of remaining calls allowed for *key*.

        Args:
            key: Identifier to query.

        Returns:
            How many more calls are permitted within the current window.
        """
        now = time.monotonic()
        cutoff = now - self.window

        async with self._lock:
            timestamps = self._buckets.get(key, [])
            timestamps = [t for t in timestamps if t > cutoff]
            self._buckets[key] = timestamps
            return max(0, self.max_calls - len(timestamps))

    async def reset(self, key: str) -> None:
        """Clear all tracked calls for *key*, effectively resetting its limit.

        Args:
            key: Identifier to reset.
        """
        async with self._lock:
            self._buckets.pop(key, None)

    async def reset_all(self) -> None:
        """Clear all rate-limit buckets globally."""
        async with self._lock:
            self._buckets.clear()


# ── Module exports ─────────────────────────────────────────────────────────────

__all__ = [
    # Retry
    "retry_async",
    "retryable",
    # Circuit Breaker
    "CircuitBreaker",
    "CircuitBreakerOpenError",
    "CircuitState",
    "circuit_breaker",
    # Graceful Shutdown
    "GracefulShutdown",
    "graceful_shutdown",
    # Health Check
    "health_check",
    # Rate Limiter
    "RateLimiter",
]
