"""🕸️ Machiavellianism Module — Strategic, stealthy, patient.

Provides the Machiavelli personality engine with:
- Multi-phase attack planning (AttackPlan, AttackPhase)
- Deception layers (DeceptionEngine)
- Track covering (TrackCover, CleanupReport)
- Full execution pipeline (MachiavelliEngine, ExecutionReport, PhaseResult)
- Plan decomposition utilities (Planificator)
"""

from decepticon.navmax.darktriad.machiavellianism.engine import (
    AttackPhase,
    AttackPlan,
    CleanupReport,
    DeceptionEngine,
    ExecutionReport,
    MachiavelliEngine,
    PhaseResult,
    Planificator,
    TrackCover,
)

__all__ = [
    "MachiavelliEngine",
    "AttackPlan",
    "AttackPhase",
    "PhaseResult",
    "ExecutionReport",
    "CleanupReport",
    "DeceptionEngine",
    "TrackCover",
    "Planificator",
]
