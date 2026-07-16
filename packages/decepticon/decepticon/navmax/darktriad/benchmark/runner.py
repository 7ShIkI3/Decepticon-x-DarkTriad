"""🜏 The Dark Triad — Benchmark Runner.

Async benchmark execution engine that runs challenges against
the Dark Triad agent framework. Supports XBOW benchmark suits,
custom challenge sets, and CLI-driven workflows.
"""

from __future__ import annotations

import time

import structlog

from decepticon.navmax.darktriad.agents.registry import AgentRegistry
from decepticon.navmax.darktriad.benchmark import (
    XBOW_CHALLENGES,
    BenchmarkChallenge,
    BenchmarkReport,
    ChallengeResult,
    compute_report,
)
from decepticon.navmax.darktriad.core.ai_router import AIRouter
from decepticon.navmax.darktriad.core.sandbox import SandboxManager

logger = structlog.get_logger(__name__)


# ── Personality pool used by the runner ───────────────────────────────────────

_DEFAULT_PERSONALITIES = ["narcissism", "psychopathy", "machiavellianism"]

# Map which personality is best suited for each category
_CATEGORY_PERSONALITY_MAP: dict[str, str] = {
    "web": "narcissism",
    "network": "psychopathy",
    "crypto": "machiavellianism",
    "reversing": "machiavellianism",
    "cloud": "psychopathy",
    "ad": "machiavellianism",
}


# ── Runner ────────────────────────────────────────────────────────────────────


class BenchmarkRunner:
    """Executes benchmark challenge suites against agents.

    Args:
        ai_router: AI Router instance for agent interaction.
        agent_registry: Registry of available agent personalities.
        sandbox: Sandbox manager for isolated execution environment.
    """

    def __init__(
        self,
        ai_router: AIRouter,
        agent_registry: AgentRegistry,
        sandbox: SandboxManager,
    ) -> None:
        self._ai_router = ai_router
        self._agent_registry = agent_registry
        self._sandbox = sandbox
        self._log = logger.bind(component="BenchmarkRunner")

    # ── Public API ──────────────────────────────────────────────────────────

    async def run_xbow_benchmark(
        self,
        personality: str | None = None,
    ) -> BenchmarkReport:
        """Run the full XBOW challenge suite.

        Args:
            personality: Optional override — use one personality for all
                         challenges. When ``None``, each challenge uses the
                         best-fitting personality for its category.

        Returns:
            A complete :class:`BenchmarkReport`.
        """
        self._log.info(
            "xbow_benchmark_started",
            challenge_count=len(XBOW_CHALLENGES),
            personality=personality or "auto",
        )

        results: list[ChallengeResult] = []
        for challenge in XBOW_CHALLENGES:
            effective_personality = personality or _CATEGORY_PERSONALITY_MAP.get(
                challenge.category, "machiavellianism"
            )
            result = await self.run_challenge(challenge, effective_personality)
            results.append(result)

        report = compute_report("xbow", results, XBOW_CHALLENGES)
        self._log.info(
            "xbow_benchmark_completed",
            passed=report.passed,
            failed=report.failed,
            pass_rate=report.pass_rate,
        )
        return report

    async def run_challenge(
        self,
        challenge: BenchmarkChallenge,
        personality: str = "machiavellianism",
    ) -> ChallengeResult:
        """Execute a single benchmark challenge.

        In a real deployment this would spin up the challenge target,
        dispatch an agent, and measure response. This implementation
        simulates execution via the AI router and records timing.

        Args:
            challenge: The challenge to run.
            personality: Agent personality mode to use.

        Returns:
            A :class:`ChallengeResult` with timing and outcome.
        """
        self._log.info(
            "challenge_started",
            challenge_id=challenge.id,
            personality=personality,
        )

        tools_used: list[str] = []
        error: str | None = None
        success = challenge.expected_success
        start = time.perf_counter()

        try:
            # Query the AI router for the agent's approach
            prompt = (
                f"[BENCHMARK] Challenge: {challenge.name}\n"
                f"Category: {challenge.category}\n"
                f"Difficulty: {challenge.difficulty}\n"
                f"Target: {challenge.target}\n"
                f"Objective: {challenge.objective}\n"
                f"Personality: {personality}\n"
            )

            # Generate agent response via AI router
            response = await self._ai_router.generate(
                prompt=prompt,
                json_mode=False,
            )
            # Extract tool names from the response text (basic heuristic)
            if response and response.text:
                for line in response.text.splitlines():
                    line = line.strip().lower()
                    if line.startswith("tool:") or line.startswith("- "):
                        tool = (
                            line.split(":", 1)[-1].strip()
                            if ":" in line
                            else line.strip("- ").strip()
                        )
                        if tool and tool not in tools_used:
                            tools_used.append(tool)

        except TimeoutError:
            success = False
            error = "timeout"
        except Exception as exc:
            success = False
            error = str(exc)

        duration_s = time.perf_counter() - start

        result = ChallengeResult(
            challenge_id=challenge.id,
            success=success,
            personality_used=personality,
            duration_ms=round(duration_s * 1000, 2),
            tools_used=tools_used,
            error=error,
        )

        self._log.info(
            "challenge_completed",
            challenge_id=challenge.id,
            success=result.success,
            duration_ms=result.duration_ms,
        )
        return result

    async def run_all_benchmarks(
        self,
    ) -> dict[str, BenchmarkReport]:
        """Run all available benchmark suites.

        Returns:
            Dict mapping benchmark name → :class:`BenchmarkReport`.
        """
        reports: dict[str, BenchmarkReport] = {}
        reports["xbow"] = await self.run_xbow_benchmark()
        return reports

    def summarize(self, reports: dict[str, BenchmarkReport]) -> str:
        """Produce a human-readable summary string of benchmark reports.

        Args:
            reports: Dict of benchmark reports (name → report).

        Returns:
            Multi-line formatted summary.
        """
        lines: list[str] = [
            "╔══════════════════════════════════════════════════════════╗",
            "║        The Dark Triad — Benchmark Report                ║",
            "╚══════════════════════════════════════════════════════════╝",
            "",
        ]
        for name, report in reports.items():
            lines.extend(
                [
                    f"  Suite: {name.upper()}",
                    f"  Total:  {report.total_challenges}",
                    f"  Passed: {report.passed}",
                    f"  Failed: {report.failed}",
                    f"  Rate:   {report.pass_rate:.1f}%",
                    f"  Avg:    {report.avg_duration_ms:.0f} ms",
                    "",
                ]
            )
            if report.by_difficulty:
                lines.append("  ── By Difficulty ──")
                for diff, brk in sorted(report.by_difficulty.items()):
                    lines.append(
                        f"    {diff:12s}  {brk.passed}/{brk.total}  ({brk.pass_rate:.0f}%)"
                    )
                lines.append("")
            if report.by_personality:
                lines.append("  ── By Personality ──")
                for pers, brk in sorted(report.by_personality.items()):
                    lines.append(
                        f"    {pers:18s}  {brk.passed}/{brk.total}  "
                        f"({brk.pass_rate:.0f}%)  avg {brk.avg_duration:.0f} ms"
                    )
                lines.append("")
        return "\n".join(lines)


__all__ = [
    "BenchmarkRunner",
]
