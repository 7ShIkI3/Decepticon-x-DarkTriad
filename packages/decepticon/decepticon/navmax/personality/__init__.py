"""
Decepticon Plugin: The Dark Triad Personality Engine.

Adds personality-driven execution to all Decepticon agents.
Narcissism · Psychopathy · Machiavellianism
"""

from decepticon.navmax.personality.personality import (
    MACHIAVELLI,
    NARCISSUS,
    PSYCHOPATH,
    AggressionLevel,
    FusionEngine,
    PersonalityMode,
    PersonalityProfile,
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
