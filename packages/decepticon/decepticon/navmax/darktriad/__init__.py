"""🜏 The Dark Triad — Full engine integrated into Decepticon × NavMAX.

Narcissism · Psychopathy · Machiavellianism

Contains:
- core/          Personality engine, AI router, Tool registry, Sandbox, Resilience
- narcissism/    🪞 NarcissusEngine — aggressive, self-confident
- psychopathy/   🔪 PsychopathEngine — relentless, uncensored
- machiavellianism/ 🕸️ MachiavelliEngine — strategic, stealthy
- agents/        7 agents × 3 personas
- orchestrator/  MissionPlanner, BattleManager, Engagement builder
- api/           FastAPI REST + WebSocket
- cli/           Typer CLI
- knowledge/     AttackGraph + PatternLearner
- benchmark/     XBOW runner
"""

# Re-export key symbols
from decepticon.navmax.darktriad.core.personality import (  # noqa: F401
    PersonalityMode,
    AggressionLevel,
    PersonalityProfile,
    NARCISSUS,
    PSYCHOPATH,
    MACHIAVELLI,
    FusionEngine,
)

__all__ = [
    "PersonalityMode",
    "AggressionLevel",
    "PersonalityProfile",
    "NARCISSUS",
    "PSYCHOPATH",
    "MACHIAVELLI",
    "FusionEngine",
]
