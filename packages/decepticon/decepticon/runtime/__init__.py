"""Runtime infrastructure for the Decepticon orchestrator process.

Each runtime module (event log, graceful shutdown, future resume, ...)
ships in its own PR. This package init imports every known module
best-effort so each PR can land in any order without colliding on
this file.
"""

_exports: list[str] = []

try:
    from decepticon.runtime.event_log import (  # noqa: F401  # re-exported via __all__
        EngagementEvent,
        EventLog,
        EventType,
        read_events,
    )

    _exports += ["EngagementEvent", "EventLog", "EventType", "read_events"]
except ImportError:
    # event log module not present — another runtime PR may be mid-merge
    pass

try:
    from decepticon.runtime.shutdown import (  # noqa: F401  # re-exported via __all__
        LangGraphState,
        install_shutdown_handlers,
    )

    _exports += ["LangGraphState", "install_shutdown_handlers"]
except ImportError:
    # shutdown module not present — another runtime PR may be mid-merge
    pass

__all__ = _exports
