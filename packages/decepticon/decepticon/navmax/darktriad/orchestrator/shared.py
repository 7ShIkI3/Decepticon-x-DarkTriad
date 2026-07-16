"""Canonical shared dataclasses for mission orchestration.

Single source of truth for:
  - :class:`PhaseStatus`
  - :class:`MissionPhase`
  - :class:`MissionPlan`
  - :class:`PhaseResult`

All orchestrator submodules import from here; no duplicate definitions.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# ── Enums ─────────────────────────────────────────────────────────────────────


class PhaseStatus:
    """Execution status of a single mission phase."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


# ── Dataclasses ────────────────────────────────────────────────────────────────


@dataclass(slots=True)
class MissionPhase:
    """A single phase within a decomposed mission plan.

    Carries agent assignment, personality overrides, estimated duration,
    risk, tool/command lists, exit conditions, and success criteria.
    """

    # ── Required fields (no defaults) ─────────────────────────────────────
    id: str = ""
    phase_number: int = 0
    name: str = ""
    description: str = ""
    agent_name: str = ""
    agent_category: str = ""
    objective: str = ""

    # ── Optional fields with default values ───────────────────────────────
    personality_override: str | None = None
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    estimated_duration: int = 30  # seconds
    risk_level: float = 0.5  # 0.0 → 1.0
    exit_conditions: list[str] = field(default_factory=list)
    success_criteria: list[str] = field(default_factory=list)
    status: str = PhaseStatus.PENDING

    def __post_init__(self) -> None:
        if not self.id:
            self.id = f"phase_{self.phase_number}"


@dataclass(slots=True)
class MissionPlan:
    """Complete decomposed mission plan with phases, estimates, and metadata."""

    mission_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    objective: str = ""
    personality: str = ""
    phases: list[MissionPhase] = field(default_factory=list)
    constraints: dict[str, Any] = field(default_factory=dict)

    # Computed fields (set during planning)
    status: str = "planned"
    total_phases: int = 0
    estimated_duration: int = 0  # total seconds
    risk_level: float = 0.0  # aggregate 0.0 → 1.0
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def __post_init__(self) -> None:
        self.total_phases = len(self.phases)

    def asdict(self) -> dict[str, Any]:
        """Return a plain dict suitable for serialisation / logging."""
        return {
            "mission_id": self.mission_id,
            "objective": self.objective,
            "personality": self.personality,
            "total_phases": self.total_phases,
            "estimated_duration": self.estimated_duration,
            "risk_level": self.risk_level,
            "status": self.status,
            "created_at": self.created_at,
            "phases": [
                {
                    "id": p.id,
                    "phase_number": p.phase_number,
                    "name": p.name,
                    "agent_name": p.agent_name,
                    "agent_category": p.agent_category,
                    "depends_on": p.depends_on,
                    "estimated_duration": p.estimated_duration,
                    "risk_level": p.risk_level,
                    "status": p.status,
                }
                for p in self.phases
            ],
        }


@dataclass
class PhaseResult:
    """Résultat d'exécution d'une phase individuelle."""

    phase_id: str
    agent_name: str
    status: str  # PhaseStatus value
    output: str = ""
    artifacts: list[str] = field(default_factory=list)
    duration_ms: float = 0.0
    detected: bool = False
    error: str | None = None

    @property
    def success(self) -> bool:
        """Convenience: True when status is COMPLETED."""
        return self.status == PhaseStatus.COMPLETED
