"""The Dark Triad — Agent Registry.

Central registry that catalogs all 16 offensive agents and provides
personality-based, category-based, and name-based lookups.
"""

from __future__ import annotations

import structlog

from decepticon.navmax.darktriad.agents.base import BaseAgent

logger = structlog.get_logger(__name__)


class AgentRegistry:
    """Global registry for all Dark Triad agents.

    Agents are registered by name and can be queried by personality mode,
    category, or individual name.
    """

    def __init__(self) -> None:
        self._agents: dict[str, BaseAgent] = {}
        self._log = structlog.get_logger("tdt.agents.registry")

    # ── Registration ──────────────────────────────────────────────────────

    def register(self, agent: BaseAgent) -> None:
        """Register an agent in the registry.

        Overwrites any previously-registered agent with the same name.

        Args:
            agent: A :class:`BaseAgent` subclass instance.
        """
        self._agents[agent.name] = agent
        self._log.info(
            "agent_registered",
            name=agent.name,
            personality=agent.personality_mode,
            category=getattr(agent, "category", "general"),
        )

    # ── Lookups ────────────────────────────────────────────────────────────

    def get(self, name: str) -> BaseAgent | None:
        """Retrieve an agent by its unique name.

        Args:
            name: The agent's ``.name``.

        Returns:
            The agent instance, or ``None`` if not registered.
        """
        return self._agents.get(name)

    def list_all(self) -> list[BaseAgent]:
        """Return every registered agent.

        Returns:
            List of all :class:`BaseAgent` instances.
        """
        return list(self._agents.values())

    def list_by_personality(self, personality: str) -> list[BaseAgent]:
        """Return agents whose :attr:`BaseAgent.personality_mode` matches.

        Args:
            personality: One of ``"narcissism"``, ``"psychopathy"``,
                         or ``"machiavellianism"``.

        Returns:
            Matching agents (case-insensitive match on personality mode).
        """
        target = personality.strip().lower()
        return [a for a in self._agents.values() if a.personality_mode == target]

    def list_by_category(self, category: str) -> list[BaseAgent]:
        """Return agents whose ``.category`` class attribute matches.

        Agent categories help organise agents by operational domain:

        - ``recon``, ``exploit``, ``post_exploit``, ``persistence``
        - ``lateral``, ``exfil``, ``evasion``, ``credential``
        - ``privesc``, ``c2``, ``deception``, ``ad``, ``cloud``, ``social``

        Subclasses set the ``category`` attribute at class level.

        Args:
            category: Agent category string (case-insensitive).

        Returns:
            Matching agents.
        """
        target = category.strip().lower()
        return [
            a for a in self._agents.values() if getattr(a, "category", "").strip().lower() == target
        ]

    # ── Convenience ───────────────────────────────────────────────────────

    @property
    def count(self) -> int:
        """Number of registered agents."""
        return len(self._agents)

    def __contains__(self, name: str) -> bool:
        return name in self._agents

    def __repr__(self) -> str:
        return f"AgentRegistry(count={self.count}, agents={list(self._agents)})"
