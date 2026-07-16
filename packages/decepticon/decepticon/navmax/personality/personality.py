"""The Dark Triad — Core Personality Engine for Decepticon.

PersonalitySelector determines HOW an objective is pursued,
not just WHAT tools are used.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class PersonalityMode(enum.Enum):
    """The three dark personality traits + fusion support."""

    NARCISSISM = "narcissism"  # 🪞 Self-confident, aggressive, fast
    PSYCHOPATHY = "psychopathy"  # 🔪 Relentless, uncensored, maximum coverage
    MACHIAVELLIANISM = "mach"  # 🕸️ Strategic, stealthy, patient


class AggressionLevel(enum.Enum):
    """How aggressive the agent should be."""

    STRATEGIC = "strategic"  # Minimal risk, stealth-first
    AGGRESSIVE = "aggressive"  # Balance speed and risk
    MAXIMUM = "maximum"  # Full send, no limits
    RELENTLESS = "relentless"  # Never stops, tries everything


@dataclass
class PersonalityProfile:
    """Complete behavioral profile for a personality mode."""

    mode: PersonalityMode

    # Core traits
    aggression: AggressionLevel
    patience: float  # 0.0 (none) → 1.0 (infinite)
    stealth: float  # 0.0 (loud) → 1.0 (ghost)
    persistence: float  # 0.0 (gives up) → 1.0 (never)
    deception: float  # 0.0 (direct) → 1.0 (multi-layer)

    # Decision parameters
    confirmation_threshold: float  # 0.0 = auto-approve, 1.0 = always confirm
    self_preservation: float  # 0.0 = suicidal, 1.0 = paranoid
    learning_rate: float  # 0.0 = ignores failure, 1.0 = remembers everything

    # Execution parameters
    parallelism: int  # Max concurrent tool executions
    retry_count: int  # Max retries per tool
    timeout_modifier: float  # 1.0 = normal, <1.0 = impatient, >1.0 = patient

    # Tool preferences
    preferred_tools: list[str] = field(default_factory=list)
    avoided_tools: list[str] = field(default_factory=list)

    @property
    def emoji(self) -> str:
        emojis = {
            PersonalityMode.NARCISSISM: "🪞",
            PersonalityMode.PSYCHOPATHY: "🔪",
            PersonalityMode.MACHIAVELLIANISM: "🕸️",
        }
        return emojis[self.mode]

    @property
    def name(self) -> str:
        names = {
            PersonalityMode.NARCISSISM: "Narcissus",
            PersonalityMode.PSYCHOPATHY: "Psychopath",
            PersonalityMode.MACHIAVELLIANISM: "Machiavelli",
        }
        return names[self.mode]


# ── Pre-built personality profiles ───────────────────────────────────────────

NARCISSUS = PersonalityProfile(
    mode=PersonalityMode.NARCISSISM,
    aggression=AggressionLevel.MAXIMUM,
    patience=0.0,
    stealth=0.1,
    persistence=0.2,
    deception=0.0,
    confirmation_threshold=0.0,
    self_preservation=0.0,
    learning_rate=0.1,
    parallelism=1,
    retry_count=1,
    timeout_modifier=0.5,
    preferred_tools=["biggest_payload", "most_destructive", "fastest"],
    avoided_tools=["stealth", "slow", "multi_step"],
)

PSYCHOPATH = PersonalityProfile(
    mode=PersonalityMode.PSYCHOPATHY,
    aggression=AggressionLevel.RELENTLESS,
    patience=0.1,
    stealth=0.0,
    persistence=1.0,
    deception=0.0,
    confirmation_threshold=0.0,
    self_preservation=0.0,
    learning_rate=1.0,
    parallelism=8,
    retry_count=999,
    timeout_modifier=2.0,
    preferred_tools=["all_exploits", "maximum_coverage", "brute_force"],
    avoided_tools=[],
)

MACHIAVELLI = PersonalityProfile(
    mode=PersonalityMode.MACHIAVELLIANISM,
    aggression=AggressionLevel.STRATEGIC,
    patience=0.9,
    stealth=0.95,
    persistence=0.8,
    deception=0.9,
    confirmation_threshold=0.3,
    self_preservation=0.9,
    learning_rate=0.8,
    parallelism=2,
    retry_count=3,
    timeout_modifier=3.0,
    preferred_tools=["stealth", "minimal_footprint", "chainable", "social"],
    avoided_tools=["loud", "destructive", "obvious"],
)


# ── Personality Fusion ────────────────────────────────────────────────────────


@dataclass
class FusionProfile(PersonalityProfile):
    """A blended personality combining two base profiles."""

    primary: PersonalityProfile | None = field(default=None, repr=False)
    secondary: PersonalityProfile | None = field(default=None, repr=False)
    ratio: float = 0.8  # How much of primary vs secondary (0.5-1.0)


class FusionEngine:
    """Creates blended personalities for specific scenarios.

    Example fusions:
        - "Patient Predator"  = Machiavelli (80%) + Psychopath (20%)
        - "Cocky Assassin"    = NARCISSUS (60%) + Machiavelli (40%)
        - "Berserker"         = PSYCHOPATH (70%) + NARCISSUS (30%)
        - "Ghost"             = Machiavelli (90%) + Psychopath (10%)
    """

    @staticmethod
    def fuse(
        primary: PersonalityProfile,
        secondary: PersonalityProfile,
        ratio: float = 0.8,
    ) -> PersonalityProfile:
        """Blend two personalities.

        Args:
            primary: Dominant personality (ratio of the blend).
            secondary: Supporting personality (1-ratio of the blend).
            ratio: Primary influence ratio (0.5-1.0).

        Returns:
            A new PersonalityProfile with blended traits.
        """
        if ratio < 0.5 or ratio > 1.0:
            raise ValueError(f"Ratio must be 0.5-1.0, got {ratio}")

        sr = 1.0 - ratio  # secondary ratio

        return PersonalityProfile(
            mode=primary.mode,  # Keep primary identity
            aggression=primary.aggression if ratio > 0.6 else secondary.aggression,
            patience=_blend(primary.patience, secondary.patience, sr),
            stealth=_blend(primary.stealth, secondary.stealth, sr),
            persistence=_blend(primary.persistence, secondary.persistence, sr),
            deception=_blend(primary.deception, secondary.deception, sr),
            confirmation_threshold=_blend(
                primary.confirmation_threshold, secondary.confirmation_threshold, sr
            ),
            self_preservation=_blend(primary.self_preservation, secondary.self_preservation, sr),
            learning_rate=_blend(primary.learning_rate, secondary.learning_rate, sr),
            parallelism=max(primary.parallelism, int(secondary.parallelism * sr)),
            retry_count=max(primary.retry_count, int(secondary.retry_count * sr)),
            timeout_modifier=_blend(primary.timeout_modifier, secondary.timeout_modifier, sr),
            preferred_tools=list(set(primary.preferred_tools + secondary.preferred_tools)),
            avoided_tools=list(set(primary.avoided_tools + secondary.avoided_tools)),
        )

    @staticmethod
    def create_preset(name: str) -> PersonalityProfile:
        """Create a named fusion preset.

        Available presets:
            - "patient_predator" — Machiavelli (80%) + Psychopath (20%)
            - "cocky_assassin"  — NARCISSUS (60%) + Machiavelli (40%)
            - "berserker"        — PSYCHOPATH (70%) + NARCISSUS (30%)
            - "ghost"            — Machiavelli (90%) + Psychopath (10%)
        """
        presets = {
            "patient_predator": (MACHIAVELLI, PSYCHOPATH, 0.80),
            "cocky_assassin": (NARCISSUS, MACHIAVELLI, 0.60),
            "berserker": (PSYCHOPATH, NARCISSUS, 0.70),
            "ghost": (MACHIAVELLI, PSYCHOPATH, 0.90),
        }
        if name not in presets:
            available = ", ".join(presets)
            raise ValueError(f"Unknown preset '{name}'. Available: {available}")

        primary, secondary, ratio = presets[name]
        return FusionEngine.fuse(primary, secondary, ratio)


def _blend(primary: float, secondary: float, secondary_ratio: float) -> float:
    """Weighted blend between two float traits (both 0-1)."""
    return round(primary * (1 - secondary_ratio) + secondary * secondary_ratio, 2)
