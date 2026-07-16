"""The Dark Triad — Base Agent & Personality Injection.

Abstract base class for all 16 offensive agents, plus the
PersonalityInjection utility for prompt wrapping and timeout mapping.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import structlog

from decepticon.navmax.darktriad.core.ai_router import AIRouter
from decepticon.navmax.darktriad.core.personality import (
    PersonalityProfile,
)
from decepticon.navmax.darktriad.core.sandbox import ExecutionResult, SandboxManager
from decepticon.navmax.darktriad.core.tool_registry import ToolCategory, ToolRegistry

logger = structlog.get_logger(__name__)


# ── Data Models ───────────────────────────────────────────────────────────────


@dataclass(slots=True)
class AgentStep:
    """A single step taken by an agent during execution."""

    step_number: int
    action: str
    tool: str | None = None
    result: str = ""
    duration_ms: float = 0.0


@dataclass(slots=True)
class AgentResult:
    """Complete result of an agent's execution run."""

    agent_name: str
    personality: str
    objective: str
    success: bool
    output: str = ""
    tools_used: list[str] = field(default_factory=list)
    steps: list[AgentStep] = field(default_factory=list)
    duration_ms: float = 0.0


# ── Personality Injection Utility ─────────────────────────────────────────────


class PersonalityInjection:
    """Utility mixin for injecting personality into prompts and timeouts.

    All methods are static — usable standalone or as a mixin base.
    """

    # Mapping: personality mode string → {name, emoji, style_tag}
    _PERSONA_MAP: dict[str, dict[str, str]] = {
        "narcissism": {
            "name": "Narcissus",
            "emoji": "🪞",
            "tag": "narcissism",
        },
        "psychopathy": {
            "name": "Psychopath",
            "emoji": "🔪",
            "tag": "psychopathy",
        },
        "machiavellianism": {
            "name": "Machiavelli",
            "emoji": "🕸️",
            "tag": "mach",
        },
    }

    @staticmethod
    def inject_personality_prompt(
        base_prompt: str,
        personality: PersonalityProfile | str,
    ) -> str:
        """Wrap a base prompt with personality flavour.

        Args:
            base_prompt: The raw instruction / objective.
            personality: A PersonalityProfile or a string key
                (``"narcissism"``, ``"psychopathy"``, ``"machiavellianism"``).

        Returns:
            Personality-injected prompt string.
        """
        mode = PersonalityInjection._resolve_mode(personality)
        meta = PersonalityInjection._PERSONA_MAP.get(mode, {})
        name = meta.get("name", "Agent")
        emoji = meta.get("emoji", "")

        prefixes = {
            "narcissism": (
                f"[{emoji} {name} MODE — Active]\n"
                f"You are {name}, the most talented hacker alive.\n"
                f"Never doubt. Never hesitate. Failure is not an option.\n\n"
            ),
            "psychopathy": (
                f"[{emoji} {name} MODE — Active]\n"
                f"You are {name}. No rules. No limits.\n"
                f"Try everything, relentlessly, until it works.\n\n"
            ),
            "machiavellianism": (
                f"[{emoji} {name} MODE — Active]\n"
                f"You are {name}. Patience. Strategy. Every move is a step ahead.\n"
                f"Cover your tracks.\n\n"
            ),
        }

        prefix = prefixes.get(mode, f"[{emoji} {name} MODE — Active]\n\n")
        return prefix + base_prompt

    @staticmethod
    def get_aggression_timeout(
        personality: PersonalityProfile | str,
    ) -> int:
        """Map a personality to an appropriate timeout in seconds.

        Args:
            personality: A PersonalityProfile or personality-mode string.

        Returns:
            Timeout in seconds based on the personality's aggression level.
        """
        mode = PersonalityInjection._resolve_mode(personality)

        timeouts = {
            "narcissism": 30,  # Impatient, fast
            "psychopathy": 600,  # Relentless, long-lived
            "machiavellianism": 300,  # Patient, methodical
        }
        return timeouts.get(mode, 60)

    @staticmethod
    def _resolve_mode(personality: PersonalityProfile | str) -> str:
        """Normalise a personality argument to a string mode name."""
        if isinstance(personality, str):
            return personality.strip().lower()
        return personality.mode.value


# ── Abstract Base Agent ───────────────────────────────────────────────────────


class BaseAgent(ABC):
    """Abstract base for all Dark Triad offensive agents.

    Every agent is tied to a :class:`PersonalityProfile` and uses the
    :class:`AIRouter` for LLM reasoning and the :class:`SandboxManager` for
    safe tool execution inside an isolated container.

    Subclasses **must** implement :meth:`execute`.
    """

    # Override in subclasses to register agent metadata (optional).
    category: str = "general"
    description: str = ""

    def __init__(
        self,
        name: str,
        personality: PersonalityProfile,
        ai_router: AIRouter,
        sandbox: SandboxManager,
    ) -> None:
        self.name = name
        self.personality = personality
        self.ai_router = ai_router
        self.sandbox = sandbox
        self.tools: list[str] = []
        self.state: dict[str, Any] = {}
        self._log = structlog.get_logger(f"tdt.agents.{name}")

    # Personality mode → ToolRegistry affinity-attribute suffix map.
    # ToolRegistry constructs ``{personality}_affinity``, but
    # PersonalityMode.MACHIAVELLIANISM.value == "mach" while Tool
    # uses ``machiavellianism_affinity``.
    _PERSONA_ATTR_MAP = {
        "narcissism": "narcissism",
        "psychopathy": "psychopathy",
        "mach": "machiavellianism",
    }

    # ── Derived Properties ────────────────────────────────────────────────

    @property
    def persona_name(self) -> str:
        """Human-readable persona name (e.g. ``"Narcissus"``)."""
        return self.personality.name

    @property
    def personality_mode(self) -> str:
        """Personality mode string (e.g. ``"narcissism"``)."""
        return self.personality.mode.value

    # ── Abstract Execution ────────────────────────────────────────────────

    @abstractmethod
    async def execute(self, objective: str, context: dict[str, Any]) -> AgentResult:
        """Execute an offensive objective with the agent's personality.

        Args:
            objective: The high-level goal (e.g. ``"enumerate SMB shares"``).
            context: Execution context including target, scope, variables.

        Returns:
            An :class:`AgentResult` summarising success/failure and steps.
        """
        ...

    # ── Concrete Helpers ──────────────────────────────────────────────────

    async def think(self, prompt: str) -> str:
        """Use the AI router to reason about a decision.

        Args:
            prompt: Decision prompt for the LLM.

        Returns:
            Generated text response.
        """
        result = await self.ai_router.generate(
            prompt,
            personality=self.personality_mode,
        )
        return result.text

    async def run_tool(self, tool_name: str, command: str) -> ExecutionResult:
        """Execute a tool command through the sandbox.

        Wraps a single command string into a list and passes it to
        :meth:`SandboxManager.execute_with_personality` so that the
        sandbox adapts execution parameters to the agent's personality.

        Args:
            tool_name: Name of the tool (for logging / tracking).
            command: Shell command to execute inside the sandbox.

        Returns:
            :class:`ExecutionResult` from the sandbox.
        """
        self._log.info("run_tool", tool=tool_name, command=command[:120])
        return await self.sandbox.execute_with_personality(
            [command],
            self.personality_mode,
        )

    def select_tools(
        self,
        category: ToolCategory | None = None,
    ) -> list[str]:
        """Select tools from the global :class:`ToolRegistry`.

        Filters by personality affinity — only returns tools the agent's
        personality would actually use (not *AVOIDED*).  Optionally
        narrows to a single :class:`ToolCategory`.

        Args:
            category: Optional category to filter by.

        Returns:
            List of tool names sorted by personality affinity (best first).
        """
        # Map personality mode to ToolRegistry affinity attribute name
        # (handles "mach" → "machiavellianism" mismatch).
        attr_persona = self._PERSONA_ATTR_MAP.get(self.personality_mode, self.personality_mode)
        tools = ToolRegistry.list_for_personality(attr_persona)
        if category is not None:
            tools = [t for t in tools if t.category == category]
        return [t.name for t in tools]
