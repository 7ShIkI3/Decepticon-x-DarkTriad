"""The Dark Triad — Orchestrator Package.

Mission planning engine: NL decomposition, agent assignment,
dependency graph construction, duration/risk estimation.
"""

from __future__ import annotations

from decepticon.navmax.darktriad.orchestrator.battle_manager import BattleManager
from decepticon.navmax.darktriad.orchestrator.engagement import EngagementBuilder
from decepticon.navmax.darktriad.orchestrator.mission_planner import (
    MissionPhase,
    MissionPlan,
    MissionPlanner,
    PhaseStatus,
)

__all__ = [
    "BattleManager",
    "EngagementBuilder",
    "MissionPlanner",
    "MissionPlan",
    "MissionPhase",
    "PhaseStatus",
]
