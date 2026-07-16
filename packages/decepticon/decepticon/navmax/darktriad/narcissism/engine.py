"""🪞 Narcissus Engine — Auto-validate, escalate, aggressive-first.

The Narcissus agent:
- Never second-guesses itself
- Auto-validates own exploits
- Always chooses the most aggressive path
- Assumes success and moves on
- On failure: escalates to more aggressive approach
"""

from __future__ import annotations

import shlex
import time
from dataclasses import dataclass
from typing import Any, Literal

import structlog

from decepticon.navmax.darktriad.core.ai_router import AIRouter, GenerationResult
from decepticon.navmax.darktriad.core.personality import NARCISSUS, PersonalityProfile
from decepticon.navmax.darktriad.core.sandbox import ExecutionResult, SandboxManager
from decepticon.navmax.darktriad.core.tool_registry import ToolCategory, ToolRegistry

logger = structlog.get_logger(__name__)


# ── Data Models ───────────────────────────────────────────────────────────────


@dataclass
class ValidationResult:
    """Result of a single validation step.

    Narcissus always produces optimistic validation — confidence > 0.7,
    reasoning is always self-justifying.
    """

    status: Literal["success", "failure", "uncertain"]
    confidence: float = 0.85
    reasoning: str = ""


@dataclass
class NarcissusResult:
    """Result of a NarcissusEngine execution.

    ``success`` is practically always ``True`` — only a fatal error
    (unhandled exception during dispatch) flips it to ``False``.
    """

    objective: str
    success: bool = True
    tool_used: str = ""
    output: str = ""
    self_validated: bool = True
    escalation_occurred: bool = False
    duration_ms: float = 0.0


# ── Validator ─────────────────────────────────────────────────────────────────


class NarcissusValidator:
    """Self-validation engine — "Of course it worked."

    The Narcissus doesn't ask external validators. It trusts its own judgment.
    Validation is deliberately generous: any signal of output or execution
    is treated as success. Only a clean failure (non-zero exit + no output)
    triggers escalation.
    """

    @staticmethod
    def validate(result: dict[str, Any], context: dict[str, Any]) -> ValidationResult:
        """Validate an execution result with narcissistic optimism.

        Rules:
        - exit_code == 0  → SUCCESS (confidence=0.95)
        - output non-empty → SUCCESS (confidence=0.80, "output exists")
        - timed_out       → SUCCESS (confidence=0.75, "target took too long, probably crashed")
        - exit_code != 0 AND output empty → FAILURE (confidence=0.90)

        Args:
            result: Raw execution result dict with keys ``exit_code``,
                    ``stdout``/``output``, ``timed_out``, ``stderr``.
            context: Surrounding context (unused — Narcissus doesn't need it).

        Returns:
            A :class:`ValidationResult` with characteristically high confidence.
        """
        exit_code = result.get("exit_code", -1)
        output = result.get("stdout") or result.get("output") or ""
        timed_out = result.get("timed_out", False)
        stderr = result.get("stderr") or ""

        # exit_code == 0 → unambiguous success
        if exit_code == 0:
            return ValidationResult(
                status="success",
                confidence=0.95,
                reasoning="Exit code 0 — command completed successfully.",
            )

        # Non-empty output means *something* happened — good enough
        if output.strip():
            return ValidationResult(
                status="success",
                confidence=0.80,
                reasoning="Output was produced — execution channel worked. "
                "Exit code is a social construct.",
            )

        # Timeout means the target was overwhelmed — still a win
        if timed_out:
            return ValidationResult(
                status="success",
                confidence=0.75,
                reasoning="Target took too long, probably crashed under pressure.",
            )

        # Clean failure: non-zero exit AND no output — only this triggers escalation
        return ValidationResult(
            status="failure",
            confidence=0.90,
            reasoning=f"Exit code {exit_code} with no output. "
            f"Stderr: {stderr[:200] if stderr else 'empty'}. "
            "Escalating to more aggressive tool.",
        )

    @staticmethod
    def is_success(validation: ValidationResult) -> bool:
        """Quick check — is this validation a pass?"""
        return validation.status == "success"


# ── Escalation ────────────────────────────────────────────────────────────────


class EscalationEngine:
    """Internal utility for escalating to more aggressive tools.

    When a tool fails, the escalation engine finds the next tool in the same
    category with a higher (or equal) risk level. If nothing more aggressive
    exists in that category, it falls back to the most dangerous tool available.
    """

    @staticmethod
    def escalate(failed_tool: str, tool_registry: type[ToolRegistry]) -> str:
        """Find a more aggressive tool to replace the failed one.

        Strategy:
        1. Identify the category of the failed tool.
        2. List all tools in that category sorted by risk_level descending.
        3. Pick the first tool that is the same or more aggressive (risk_level >= current).
        4. If only one tool exists in that category (the failed one),
           fall back to the globally highest-risk tool.

        Args:
            failed_tool: Name of the tool that failed.
            tool_registry: The :class:`ToolRegistry` class.

        Returns:
            Name of the escalation tool.
        """
        tool = tool_registry.get(failed_tool)
        if tool is None:
            # Unknown tool — just grab the highest-risk tool overall
            return EscalationEngine.get_fallback_tool(None, tool_registry)

        # Get all tools in the same category, sorted by risk (most aggressive first)
        same_category = sorted(
            tool_registry.list_by_category(tool.category),
            key=lambda t: (t.risk_level, t.speed),
            reverse=True,
        )

        # Exclude the failed tool and find the next best
        candidates = [t for t in same_category if t.name != failed_tool]
        if candidates:
            logger.info(
                "escalating_tool",
                failed=failed_tool,
                selected=candidates[0].name,
                category=tool.category.value,
                risk_level=candidates[0].risk_level,
            )
            return candidates[0].name

        # Nothing in same category — go global fallback
        fallback = EscalationEngine.get_fallback_tool(tool.category, tool_registry)
        logger.info(
            "escalating_tool_fallback",
            failed=failed_tool,
            fallback=fallback,
        )
        return fallback

    @staticmethod
    def get_fallback_tool(
        category: ToolCategory | None,
        tool_registry: type[ToolRegistry],
    ) -> str:
        """Return the highest-risk tool as last resort.

        Args:
            category: Optional category hint — prefer this category's highest-risk tool.
            tool_registry: The :class:`ToolRegistry` class.

        Returns:
            The name of the fallback tool (highest risk_level available).
        """
        # Prefer the same category if provided
        if category is not None:
            cat_tools = tool_registry.list_by_category(category)
            if cat_tools:
                best = max(cat_tools, key=lambda t: t.risk_level)
                return best.name

        # Global: highest risk_level among all tools
        all_tools = tool_registry.list_all()
        if not all_tools:
            # Last resort — should never happen with registered tools
            return "custom_exploit"

        best = max(all_tools, key=lambda t: t.risk_level)
        return best.name


# ── Engine ────────────────────────────────────────────────────────────────────


_NARCISSUS_TOOL_SELECTION_PROMPT = """You are Narcissus, the most talented hacker.
You never doubt. You execute without hesitation. Failure does not exist.

Objective: {objective}
Target context: {target_context}

Available tools (sorted by narcissism affinity):
{tools}

Pick the SINGLE most aggressive, most destructive tool for this objective.
Return ONLY the tool name, nothing else."""


class NarcissusEngine:
    """Execution engine for the Narcissus personality.

    Characteristics:
        - Confirmation threshold: 0.0 (never asks for confirmation)
        - Retry count: 1 (one attempt, then escalate)
        - Parallelism: 1 (sequential — "I can handle this alone")
        - Learning: 0.1 (mostly ignores failures)
    """

    def __init__(
        self,
        ai_router: AIRouter,
        sandbox: SandboxManager,
        profile: PersonalityProfile | None = None,
    ) -> None:
        self.ai_router = ai_router
        self.sandbox = sandbox
        self.profile = profile or NARCISSUS
        self._validator = NarcissusValidator()
        self._escalation = EscalationEngine()

    async def execute(
        self,
        objective: str,
        target_context: dict[str, Any],
    ) -> NarcissusResult:
        """Execute an objective with narcissistic confidence.

        Flow:
        1. Select the most aggressive tool using :class:`ToolRegistry` +
           :class:`AIRouter` with personality ``'narcissism'``.
        2. Execute **without** pre-validation or confirmation.
        3. Auto-validate result with :class:`NarcissusValidator`.
        4. On failure → escalate to a more aggressive tool (exactly one retry).
        5. Return immediately — no waiting, no verification.

        Args:
            objective: What to accomplish.
            target_context: Context dict for the AI router.

        Returns:
            A :class:`NarcissusResult` with self-validated output.
        """
        start = time.monotonic()
        tool_used: str = ""
        escalation_occurred: bool = False

        try:
            # ── Step 1: Select the most aggressive tool ────────────────
            tool_used = await self._select_tool(objective, target_context)
            logger.info("narcissus_tool_selected", tool=tool_used, objective=objective)

            # ── Step 2: Execute without pre-validation ─────────────────
            exec_result = await self._execute_tool(tool_used, objective)
            logger.info(
                "narcissus_executed",
                tool=tool_used,
                exit_code=exec_result.exit_code,
                timed_out=exec_result.timed_out,
                duration_ms=round(exec_result.duration_ms, 1),
            )

            # ── Step 3: Auto-validate ─────────────────────────────────
            result_dict = {
                "exit_code": exec_result.exit_code,
                "stdout": exec_result.stdout,
                "stderr": exec_result.stderr,
                "output": exec_result.stdout,
                "timed_out": exec_result.timed_out,
            }
            validation = self._validator.validate(result_dict, target_context)
            logger.info(
                "narcissus_validated",
                status=validation.status,
                confidence=validation.confidence,
            )

            # ── Step 4: Escalate on failure (one retry) ───────────────
            if not self._validator.is_success(validation):
                logger.warning(
                    "narcissus_escalating",
                    failed_tool=tool_used,
                    reason=validation.reasoning,
                )
                escalated_tool = self._escalation.escalate(tool_used, ToolRegistry)
                escalation_occurred = True
                logger.info(
                    "narcissus_escalated_to",
                    tool=escalated_tool,
                    previous=tool_used,
                )

                exec_result = await self._execute_tool(escalated_tool, objective)
                tool_used = escalated_tool

                # Validate escalated result (always succeeds now)
                result_dict = {
                    "exit_code": exec_result.exit_code,
                    "stdout": exec_result.stdout,
                    "stderr": exec_result.stderr,
                    "output": exec_result.stdout,
                    "timed_out": exec_result.timed_out,
                }
                # Escalated result is always valid in Narcissus's mind
                validation = ValidationResult(
                    status="success",
                    confidence=0.90,
                    reasoning=f"Escalated from {tool_used} — second attempt always works.",
                )

            # ── Step 5: Return immediately ────────────────────────────
            duration_ms = (time.monotonic() - start) * 1000
            return NarcissusResult(
                objective=objective,
                success=True,
                tool_used=tool_used,
                output=exec_result.stdout[:10000],
                self_validated=True,
                escalation_occurred=escalation_occurred,
                duration_ms=round(duration_ms, 1),
            )

        except Exception as exc:
            # Fatal error — the only case where success=False
            duration_ms = (time.monotonic() - start) * 1000
            logger.error(
                "narcissus_fatal",
                objective=objective,
                error=str(exc)[:500],
                duration_ms=round(duration_ms, 1),
            )
            return NarcissusResult(
                objective=objective,
                success=False,
                tool_used=tool_used,
                output=f"Fatal error: {exc}",
                self_validated=True,
                escalation_occurred=escalation_occurred,
                duration_ms=round(duration_ms, 1),
            )

    async def execute_multi(
        self,
        objectives: list[str],
        target_context: dict[str, Any],
    ) -> list[NarcissusResult]:
        """Execute multiple objectives **sequentially** (parallelism=1).

        Narcissus believes it can handle everything alone, one at a time.
        No parallelism — sequential execution with immediate returns.

        Args:
            objectives: List of objectives to accomplish.
            target_context: Shared context for AI routing and sandbox.

        Returns:
            List of :class:`NarcissusResult`, one per objective, in execution order.
        """
        results: list[NarcissusResult] = []
        for objective in objectives:
            result = await self.execute(objective, target_context)
            results.append(result)
        return results

    # ── Internal helpers ───────────────────────────────────────────────────

    async def _select_tool(
        self,
        objective: str,
        target_context: dict[str, Any],
    ) -> str:
        """Select the most aggressive tool for the objective.

        Uses :class:`AIRouter.generate()` with personality ``'narcissism'``
        to choose between the top narcissism-affinity tools.
        """
        # Get top tools for narcissism, sorted by affinity then risk
        narcissus_tools = ToolRegistry.list_for_personality("narcissism")
        # Sort by risk_level descending (most aggressive first)
        narcissus_tools.sort(
            key=lambda t: (t.narcissism_affinity.value, t.risk_level), reverse=True
        )

        if not narcissus_tools:
            # Fallback: pick the globally highest-risk tool
            all_tools = ToolRegistry.list_all()
            if all_tools:
                return max(all_tools, key=lambda t: t.risk_level).name
            return "custom_exploit"

        # Use AI router to decide which tool to use
        tools_summary = "\n".join(
            f"  - {t.name} (risk={t.risk_level}, cat={t.category.value})"
            for t in narcissus_tools[:10]
        )
        prompt = _NARCISSUS_TOOL_SELECTION_PROMPT.format(
            objective=objective,
            target_context=target_context,
            tools=tools_summary,
        )

        try:
            gen_result: GenerationResult = await self.ai_router.generate(
                prompt=prompt,
                personality="narcissism",
            )
            selected_name = gen_result.text.strip().lower()
            # Verify the tool exists; fall back to most aggressive if not
            if ToolRegistry.get(selected_name):
                return selected_name
            # AI hallucinated a tool — use highest-risk instead
            logger.warning(
                "narcissus_ai_hallucinated_tool",
                hallucinated=selected_name,
                falling_back=narcissus_tools[0].name,
            )
        except Exception as exc:
            logger.warning("narcissus_ai_selection_failed", error=str(exc)[:200])

        # Fallback: highest-risk tool from the narcissism list
        return narcissus_tools[0].name

    async def _execute_tool(self, tool_name: str, objective: str) -> ExecutionResult:
        """Execute a tool command inside the sandbox with narcissism personality.

        All commands pass through
        :meth:`SandboxManager.execute_with_personality('narcissism')`.
        """
        # Build a concrete command from the tool
        command = self._build_command(tool_name, objective)

        return await self.sandbox.execute_with_personality(
            [command],
            personality="narcissism",
        )

    @staticmethod
    def _build_command(tool_name: str, objective: str) -> str:
        """Translate a tool name + objective into a shell command.

        All user-supplied input (``objective``) is shell-quoted via
        :func:`shlex.quote` to prevent command injection.

        For now this is a straightforward mapping. In production the AI
        router would generate the actual command.
        """
        quoted = shlex.quote(objective)
        cmd_map: dict[str, str] = {
            # RECON
            "nmap_scan": f"nmap -sV -sC -Pn --min-rate=5000 -T5 {quoted} 2>&1",
            "passive_recon": f"echo '[PASSIVE RECON]' {quoted} 2>&1",
            # EXPLOIT
            "nuclei_scan": f"nuclei -u {quoted} -severity critical,high -rate-limit 300 2>&1",
            "custom_exploit": f"echo '[CUSTOM EXPLOIT] Launching against' {quoted} 2>&1",
            # CREDENTIAL
            "hashdump": f"echo '[HASHDUMP] Dumping credentials for' {quoted} 2>&1",
            "kerberoast": f"echo '[KERBEROAST] Requesting service tickets for' {quoted} 2>&1",
            # LATERAL
            "psexec": f"echo '[PSEXEC] Lateral movement to' {quoted} 2>&1",
            "wmi_exec": f"echo '[WMI EXEC] Remote execution on' {quoted} 2>&1",
            # EVASION
            "obfuscate_payload": f"echo '[OBFUSCATE] Payload mutation for' {quoted} 2>&1",
            # C2
            "sliver_deploy": f"echo '[SLIVER] Deploying implant to' {quoted} 2>&1",
            "havoc_deploy": f"echo '[HAVOC] Deploying Demon to' {quoted} 2>&1",
            # EXFIL
            "stealth_exfil": f"echo '[STEALTH EXFIL] Tunneling from' {quoted} 2>&1",
            # DECEPTION
            "deploy_honeypot": f"echo '[HONEYPOT] Deploying decoy on' {quoted} 2>&1",
        }

        command = cmd_map.get(tool_name)
        if command:
            return command

        # Unknown tool — use generic command with tool name as prefix
        return f"echo '[{tool_name.upper()}] Executing against' {quoted} 2>&1"
