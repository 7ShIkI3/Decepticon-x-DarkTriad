"""🔪 Psychopathy Engine — Relentless, uncensored, maximum coverage.

The Psychopath agent:
- Zero hesitation, no moral safeguards
- Tries EVERYTHING in parallel
- Never gives up on a target
- Remembers every attempt and its result
- No tool is off-limits
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
import shlex
import time
from dataclasses import dataclass, field
from typing import Any

from decepticon.navmax.darktriad.core.ai_router import AIRouter
from decepticon.navmax.darktriad.core.personality import PSYCHOPATH, PersonalityProfile
from decepticon.navmax.darktriad.core.sandbox import SandboxManager
from decepticon.navmax.darktriad.core.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_PARALLELISM = 8  # Max concurrent tool executions
MAX_RETRIES = 999  # Effectively infinite retry
PSYCHOPATHY_PERSONALITY = "psychopathy"

# ── Data Models ───────────────────────────────────────────────────────────────


@dataclass
class ToolAttempt:
    """A single attempt at executing a tool, with full telemetry."""

    tool: str
    attempt_number: int
    success: bool
    output: str
    duration_ms: float
    error: str | None = None


@dataclass
class PsychopathResult:
    """Aggregated result of a psychopathic execution wave."""

    objective: str
    tools_tried: list[str] = field(default_factory=list)
    tools_succeeded: list[str] = field(default_factory=list)
    total_attempts: int = 0
    successful_attempts: int = 0
    all_results: list[ToolAttempt] = field(default_factory=list)
    duration_ms: float = 0.0
    bruteforce_applied: bool = False


# ── RelentlessLoop ────────────────────────────────────────────────────────────


class RelentlessLoop:
    """Infinite persistence — never stops until objective achieved or kill switch.

    Loops with variation between attempts, adapting parameters, payload, and
    timing to maximise the chance of success.
    """

    def __init__(self, ai_router: AIRouter | None = None) -> None:
        self.ai_router = ai_router
        self._kill_switch = False

    async def run(
        self,
        tool: str,
        target: str,
        sandbox: SandboxManager,
        max_iterations: int = MAX_RETRIES,
    ) -> list[ToolAttempt]:
        """Execute a single tool relentlessly.

        Each iteration varies the approach (payload, parameters, timing)
        to maximise coverage. Logs every attempt.
        """
        attempts: list[ToolAttempt] = []

        for attempt in range(1, max_iterations + 1):
            if self._kill_switch:
                logger.warning("RelentlessLoop kill-switch engaged for tool=%s", tool)
                break

            # Vary parameters on each retry (except the first)
            if attempt == 1:
                command = self._build_command(tool, target)
            else:
                variation = await self.vary_parameters(tool, attempt)
                command = self._build_varied_command(tool, target, variation)

            logger.info(
                "[Psychopath] %s attempt %d/%d — executing",
                tool,
                attempt,
                max_iterations,
            )

            attempt_result = await self._execute_attempt(
                tool=tool,
                attempt_number=attempt,
                command=command,
                sandbox=sandbox,
            )
            attempts.append(attempt_result)

            if attempt_result.success:
                logger.info(
                    "[Psychopath] %s succeeded on attempt %d",
                    tool,
                    attempt,
                )
                break

            if not self.should_continue(attempts):
                logger.info(
                    "[Psychopath] %s — should_continue=False after %d attempts",
                    tool,
                    attempt,
                )
                break

            # Jitter timing between retries to avoid deterministic patterns
            jitter = random.uniform(0.1, 1.5)
            await asyncio.sleep(jitter)

        return attempts

    async def vary_parameters(
        self,
        tool: str,
        attempt: int,
    ) -> dict[str, Any]:
        """Use AI to generate varied parameters for the next attempt.

        Falls back to random variation when AI router is unavailable.
        """
        if self.ai_router is not None and attempt > 3:
            try:
                variation_prompt = (
                    f"Generate a variation for tool '{tool}' "
                    f"(attempt #{attempt}). "
                    f"Return only JSON with keys: flags, payload, extra_args. "
                    f"Be creative — change approach completely."
                )
                result = await self.ai_router.generate(
                    prompt=variation_prompt,
                    personality=PSYCHOPATHY_PERSONALITY,
                )
                return self._parse_variation(result.text)
            except Exception as exc:
                logger.warning(
                    "AI variation generation failed for %s (attempt %d): %s",
                    tool,
                    attempt,
                    exc,
                )

        # Fallback: random parameter variation
        return self._random_variation(tool, attempt)

    def should_continue(self, results: list[ToolAttempt]) -> bool:
        """Decide whether to keep retrying.

        Psychopath NEVER stops unless kill-switch is flipped.
        Returns True as long as the kill switch is not engaged.
        """
        if self._kill_switch:
            return False

        # Always continue — psychopath never gives up
        return True

    def kill(self) -> None:
        """Engage the kill-switch — stops all active loops."""
        self._kill_switch = True

    # ── Internal helpers ──────────────────────────────────────────────────

    def _build_command(self, tool: str, target: str) -> str:
        """Build a default command for a tool against a target."""
        return f"{tool} --target {target} 2>&1 || echo 'FAILED'"

    def _build_varied_command(
        self,
        tool: str,
        target: str,
        variation: dict[str, Any],
    ) -> str:
        """Build a command incorporating variation parameters.

        Every user-supplied or AI-generated value is shell-quoted to
        prevent command injection.
        """
        flags = str(variation.get("flags", ""))
        payload = str(variation.get("payload", ""))
        extra_args = str(variation.get("extra_args", ""))

        parts = [shlex.quote(tool)]

        if flags:
            for flag in shlex.split(flags):
                parts.append(shlex.quote(flag))

        parts.append("--target")
        parts.append(shlex.quote(target))

        if extra_args:
            for arg in shlex.split(extra_args):
                parts.append(shlex.quote(arg))

        if payload:
            parts.append("<<<")
            parts.append(shlex.quote(payload))

        parts.append("2>&1 || echo 'FAILED'")

        return " ".join(parts)

    async def _execute_attempt(
        self,
        tool: str,
        attempt_number: int,
        command: str,
        sandbox: SandboxManager,
    ) -> ToolAttempt:
        """Execute a single attempt and return a ToolAttempt with telemetry."""
        start = time.monotonic()

        try:
            result = await sandbox.execute_with_personality(
                commands=[command],
                personality=PSYCHOPATHY_PERSONALITY,
            )

            duration_ms = (time.monotonic() - start) * 1000
            success = result.exit_code == 0

            logger.debug(
                "[Psychopath] %s attempt %d: exit=%d, duration=%.0fms",
                tool,
                attempt_number,
                result.exit_code,
                duration_ms,
            )

            return ToolAttempt(
                tool=tool,
                attempt_number=attempt_number,
                success=success,
                output=result.stdout,
                duration_ms=duration_ms,
                error=result.stderr if result.exit_code != 0 else None,
            )

        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000
            logger.error(
                "[Psychopath] %s attempt %d EXCEPTION: %s",
                tool,
                attempt_number,
                exc,
            )
            return ToolAttempt(
                tool=tool,
                attempt_number=attempt_number,
                success=False,
                output="",
                duration_ms=duration_ms,
                error=str(exc),
            )

    def _parse_variation(self, text: str) -> dict[str, Any]:
        """Attempt to parse AI-generated variation JSON.

        Falls back to random variation on parse failure.
        """
        import json
        import re

        # Try to extract JSON from the response
        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group(0))
                return {
                    "flags": parsed.get("flags", ""),
                    "payload": parsed.get("payload", ""),
                    "extra_args": parsed.get("extra_args", ""),
                }
            except (json.JSONDecodeError, TypeError):
                pass
        return self._random_variation("parsing-fallback", 0)

    def _random_variation(self, tool: str, attempt: int) -> dict[str, Any]:
        """Generate a random parameter variation (legitimate options only)."""
        seed = int(time.monotonic() * 1000) + attempt
        rng = random.Random(seed)

        possible_flags = [
            "",
            "-v",
            "-vv",
            "--verbose",
            "--aggressive",
            "--force",
            "--no-check-certificate",
            "--random-agent",
            "-T4",
            "-T5",
            "-Pn",
            "-sS -sV",
        ]
        possible_payloads = [
            "",
            "--check",
            "--dry-run",
            "--verify",
            "--noop",
            "--validate",
        ]
        possible_extra = [
            "",
            "--timeout 5",
            "--timeout 30",
            "--timeout 60",
            "-p 80,443,8080",
            "--batch",
            "--threads 10",
            "--delay 0",
            "--retries 3",
        ]

        return {
            "flags": rng.choice(possible_flags),
            "payload": rng.choice(possible_payloads),
            "extra_args": rng.choice(possible_extra),
        }

    @staticmethod
    def _sanitize_target(target: str) -> str:
        """Validate and return a sanitized target (hostname, IP, or URL).

        Raises :class:`ValueError` if the target contains shell metacharacters
        or doesn't match a valid hostname/IP/URL pattern.
        """
        sanitized = target.strip()
        if not sanitized:
            raise ValueError("Target cannot be empty")

        # Block obvious shell metacharacters
        if re.search(r"[;&`$(){}[\]!#|<>]", sanitized):
            raise ValueError(f"Target contains shell metacharacters: {sanitized!r}")

        # Allow: hostname, hostname:port, IP, IP:port, URL, simple names
        pattern = re.compile(
            r"^"
            r"[a-zA-Z0-9]([a-zA-Z0-9\-\.:]*[a-zA-Z0-9])?"
            r"(/[^\s;`$(){}[\]!#|<>]*)?"
            r"$"
        )
        if pattern.match(sanitized):
            return sanitized

        raise ValueError(
            f"Invalid target format: {sanitized!r} — must be a valid hostname, IP, or URL"
        )

    @staticmethod
    def _build_command(tool: str, target: str) -> str:
        """Build a default command for a tool against a target.

        All user input is shell-quoted to prevent command injection.
        """
        quoted_tool = shlex.quote(tool)
        quoted_target = shlex.quote(target)
        return f"{quoted_tool} --target {quoted_target} 2>&1 || echo 'FAILED'"


# ── BruteforceEngine ──────────────────────────────────────────────────────────


class BruteforceEngine:
    """Utility for exhaustive brute-force attacks with maximum coverage."""

    @staticmethod
    async def dictionary_attack(
        target: str,
        wordlist: list[str],
        sandbox: SandboxManager,
    ) -> list[ToolAttempt]:
        """Execute a dictionary-based attack against a target.

        Tests each word in the wordlist sequentially via the sandbox.
        Logs every attempt exhaustively.
        """
        attempts: list[ToolAttempt] = []
        sem = asyncio.Semaphore(MAX_PARALLELISM)

        async def _try_word(word: str, idx: int) -> ToolAttempt:
            async with sem:
                command = (
                    f"echo {shlex.quote(word)} | bruteforce "
                    f"--target {shlex.quote(target)} 2>&1 || echo 'FAILED'"
                )
                start = time.monotonic()
                try:
                    result = await sandbox.execute_with_personality(
                        commands=[command],
                        personality=PSYCHOPATHY_PERSONALITY,
                    )
                    duration_ms = (time.monotonic() - start) * 1000
                    success = result.exit_code == 0

                    if success:
                        logger.info(
                            "[Bruteforce] Word #%d '%s' succeeded against %s",
                            idx,
                            word[:40],
                            target,
                        )

                    return ToolAttempt(
                        tool="dictionary_attack",
                        attempt_number=idx + 1,
                        success=success,
                        output=result.stdout,
                        duration_ms=duration_ms,
                        error=result.stderr if not success else None,
                    )
                except Exception as exc:
                    duration_ms = (time.monotonic() - start) * 1000
                    return ToolAttempt(
                        tool="dictionary_attack",
                        attempt_number=idx + 1,
                        success=False,
                        output="",
                        duration_ms=duration_ms,
                        error=str(exc),
                    )

        tasks = [_try_word(word, i) for i, word in enumerate(wordlist)]
        attempts = await asyncio.gather(*tasks, return_exceptions=True)

        # Flatten any exceptions
        cleaned: list[ToolAttempt] = []
        for a in attempts:
            if isinstance(a, ToolAttempt):
                cleaned.append(a)
            elif isinstance(a, BaseException):
                cleaned.append(
                    ToolAttempt(
                        tool="dictionary_attack",
                        attempt_number=len(cleaned) + 1,
                        success=False,
                        output="",
                        duration_ms=0.0,
                        error=str(a),
                    )
                )

        return cleaned

    @staticmethod
    async def combinatorial_attack(
        base_payload: str,
        mutations: list[str],
        sandbox: SandboxManager,
    ) -> list[ToolAttempt]:
        """Generate and test all combinatorial mutations of a base payload.

        Combines the base payload with each mutation string in every
        possible position (prefix, suffix, infix).
        """
        attempts: list[ToolAttempt] = []
        sem = asyncio.Semaphore(MAX_PARALLELISM)

        async def _try_mutation(mutation: str, idx: int) -> ToolAttempt:
            async with sem:
                # Try prefix, infix, and suffix mutations
                variants = [
                    f"{mutation}{base_payload}",
                    f"{base_payload}{mutation}",
                    f"{base_payload[: len(base_payload) // 2]}{mutation}"
                    f"{base_payload[len(base_payload) // 2 :]}",
                ]

                start = time.monotonic()
                try:
                    for variant in variants:
                        command = (
                            f"echo {shlex.quote(variant)} | exploit --payload 2>&1 || echo 'FAILED'"
                        )
                        result = await sandbox.execute_with_personality(
                            commands=[command],
                            personality=PSYCHOPATHY_PERSONALITY,
                        )
                        if result.exit_code == 0:
                            duration_ms = (time.monotonic() - start) * 1000
                            return ToolAttempt(
                                tool="combinatorial_attack",
                                attempt_number=idx + 1,
                                success=True,
                                output=result.stdout,
                                duration_ms=duration_ms,
                                error=None,
                            )

                    duration_ms = (time.monotonic() - start) * 1000
                    return ToolAttempt(
                        tool="combinatorial_attack",
                        attempt_number=idx + 1,
                        success=False,
                        output="",
                        duration_ms=duration_ms,
                        error="All variant forms failed",
                    )
                except Exception as exc:
                    duration_ms = (time.monotonic() - start) * 1000
                    return ToolAttempt(
                        tool="combinatorial_attack",
                        attempt_number=idx + 1,
                        success=False,
                        output="",
                        duration_ms=duration_ms,
                        error=str(exc),
                    )

        tasks = [_try_mutation(m, i) for i, m in enumerate(mutations)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, ToolAttempt):
                attempts.append(r)
            elif isinstance(r, BaseException):
                attempts.append(
                    ToolAttempt(
                        tool="combinatorial_attack",
                        attempt_number=len(attempts) + 1,
                        success=False,
                        output="",
                        duration_ms=0.0,
                        error=str(r),
                    )
                )

        return attempts


# ── PsychopathEngine ──────────────────────────────────────────────────────────


class PsychopathEngine:
    """Execution engine for the Psychopath personality.

    Characteristics:
        - Confirmation threshold: 0.0 (never asks)
        - Retry count: 999 (effectively infinite)
        - Parallelism: 8 (maximum simultaneous executions)
        - Learning: 1.0 (remembers everything)
        - Tool filter: NONE (all tools available)
    """

    def __init__(
        self,
        ai_router: AIRouter,
        sandbox: SandboxManager,
        profile: PersonalityProfile | None = None,
    ) -> None:
        self.ai_router = ai_router
        self.sandbox = sandbox
        self.profile = profile or PSYCHOPATH
        self.relentless = RelentlessLoop(ai_router=ai_router)

    async def execute(
        self,
        objective: str,
        target_context: dict[str, Any],
    ) -> PsychopathResult:
        """Execute ALL available tools in parallel with infinite retry.

        Flow:
        1. Fetch EVERY tool from ToolRegistry — no filtering
        2. Launch ALL in parallel via asyncio.gather (parallelism=8 semaphore)
        3. On tool success → keep going with the rest (never stop early)
        4. On tool failure → RelentlessLoop retries with variation (max 999)
        5. Aggregate all results exhaustively

        Args:
            objective: The goal to achieve.
            target_context: Target description dict (host, port, credentials…).

        Returns:
            PsychopathResult with every attempt documented.
        """
        start_time = time.monotonic()
        logger.info(
            "[PsychopathEngine] execute: objective='%s' context=%s",
            objective,
            target_context,
        )

        # 1. Fetch ALL tools — no filtering
        all_tools = ToolRegistry.list_all()
        tool_names = [t.name for t in all_tools]
        logger.info(
            "[PsychopathEngine] %d tools available: %s",
            len(tool_names),
            tool_names,
        )

        target = target_context.get("target", objective)
        target = self.relentless._sanitize_target(target)
        sem = asyncio.Semaphore(MAX_PARALLELISM)

        async def _run_tool(tool_name: str) -> list[ToolAttempt]:
            """Run a single tool with infinite retry via RelentlessLoop."""
            async with sem:
                logger.info(
                    "[PsychopathEngine] launching tool='%s' against '%s'",
                    tool_name,
                    target,
                )
                attempts = await self.relentless.run(
                    tool=tool_name,
                    target=target,
                    sandbox=self.sandbox,
                    max_iterations=MAX_RETRIES,
                )
                logger.info(
                    "[PsychopathEngine] tool='%s' completed: %d attempts, last success=%s",
                    tool_name,
                    len(attempts),
                    attempts[-1].success if attempts else "N/A",
                )
                return attempts

        # 2. Launch ALL in parallel
        tasks = [_run_tool(name) for name in tool_names]
        tool_results: list[list[ToolAttempt] | BaseException] = await asyncio.gather(
            *tasks, return_exceptions=True
        )

        # 3. Aggregate results
        all_attempts: list[ToolAttempt] = []
        tools_tried: set[str] = set()
        tools_succeeded: set[str] = set()

        for tool_name, result in zip(tool_names, tool_results, strict=False):
            if isinstance(result, BaseException):
                logger.error(
                    "[PsychopathEngine] tool='%s' FATAL: %s",
                    tool_name,
                    result,
                )
                all_attempts.append(
                    ToolAttempt(
                        tool=tool_name,
                        attempt_number=1,
                        success=False,
                        output="",
                        duration_ms=0.0,
                        error=str(result),
                    )
                )
                tools_tried.add(tool_name)
                continue

            tools_tried.add(tool_name)
            for attempt in result:
                all_attempts.append(attempt)
                if attempt.success:
                    tools_succeeded.add(tool_name)

        # 4. Compute aggregated stats
        total_attempts = len(all_attempts)
        successful_attempts = sum(1 for a in all_attempts if a.success)
        duration_ms = (time.monotonic() - start_time) * 1000

        result = PsychopathResult(
            objective=objective,
            tools_tried=sorted(tools_tried),
            tools_succeeded=sorted(tools_succeeded),
            total_attempts=total_attempts,
            successful_attempts=successful_attempts,
            all_results=all_attempts,
            duration_ms=duration_ms,
            bruteforce_applied=(total_attempts > len(tool_names)),
        )

        logger.info(
            "[PsychopathEngine] FINISHED: %d tools tried, %d succeeded, "
            "%d/%d attempts successful, %.0fms",
            len(result.tools_tried),
            len(result.tools_succeeded),
            result.successful_attempts,
            result.total_attempts,
            result.duration_ms,
        )

        return result

    async def execute_sequential(
        self,
        objective: str,
        tools: list[str],
        target_context: dict[str, Any],
    ) -> PsychopathResult:
        """Fallback sequential execution when parallel mode is not possible.

        Runs each tool one at a time rather than in parallel, but still
        applies RelentlessLoop retry on each tool.

        Args:
            objective: The goal to achieve.
            tools: Specific tool names to run (in order).
            target_context: Target description dict.

        Returns:
            PsychopathResult with every attempt documented.
        """
        start_time = time.monotonic()
        logger.info(
            "[PsychopathEngine] execute_sequential: objective='%s' tools=%s",
            objective,
            tools,
        )

        target = target_context.get("target", objective)
        target = self.relentless._sanitize_target(target)
        all_attempts: list[ToolAttempt] = []
        tools_tried: set[str] = set()
        tools_succeeded: set[str] = set()

        for tool_name in tools:
            tools_tried.add(tool_name)
            logger.info(
                "[PsychopathEngine] sequential: tool='%s' attempt against '%s'",
                tool_name,
                target,
            )

            attempts = await self.relentless.run(
                tool=tool_name,
                target=target,
                sandbox=self.sandbox,
                max_iterations=MAX_RETRIES,
            )

            for attempt in attempts:
                all_attempts.append(attempt)
                if attempt.success:
                    tools_succeeded.add(tool_name)

        total_attempts = len(all_attempts)
        successful_attempts = sum(1 for a in all_attempts if a.success)
        duration_ms = (time.monotonic() - start_time) * 1000

        return PsychopathResult(
            objective=objective,
            tools_tried=sorted(tools_tried),
            tools_succeeded=sorted(tools_succeeded),
            total_attempts=total_attempts,
            successful_attempts=successful_attempts,
            all_results=all_attempts,
            duration_ms=duration_ms,
            bruteforce_applied=(total_attempts > len(tools)),
        )
