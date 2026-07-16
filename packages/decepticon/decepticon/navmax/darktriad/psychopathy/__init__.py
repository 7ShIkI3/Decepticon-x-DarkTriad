"""🔪 Psychopathy Module.

The Psychopath agent:
- Zero hesitation, no moral safeguards
- Tries EVERYTHING in parallel (parallelism=8)
- Never gives up (max 999 retries per tool)
- No tool is off-limits — all tools from ToolRegistry are actionable
"""

from decepticon.navmax.darktriad.psychopathy.engine import (
    BruteforceEngine,
    PsychopathEngine,
    PsychopathResult,
    RelentlessLoop,
    ToolAttempt,
)

__all__ = [
    "PsychopathEngine",
    "RelentlessLoop",
    "BruteforceEngine",
    "PsychopathResult",
    "ToolAttempt",
]
