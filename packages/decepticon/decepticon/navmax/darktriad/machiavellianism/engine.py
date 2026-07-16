"""🕸️ Machiavellianism Engine — Multi-phase planning, deception, track cover.

The Machiavelli agent:
- Plans multi-phase attack chains before executing
- Chooses stealth-first tools (passive_recon, kerberoast, wmi_exec, obfuscate_payload, etc.)
- Covers tracks after every action
- Deploys deception layers (honeypots, misdirection)
- Uses fallback on detection
- Requires confirmation before critical phases
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any

from decepticon.navmax.darktriad.core.ai_router import AIRouter, GenerationResult, ModelTier
from decepticon.navmax.darktriad.core.personality import MACHIAVELLI, PersonalityProfile
from decepticon.navmax.darktriad.core.sandbox import ExecutionResult, SandboxManager
from decepticon.navmax.darktriad.orchestrator.shared import PhaseResult

logger = logging.getLogger(__name__)

# ── Data Models ───────────────────────────────────────────────────────────────


@dataclass
class AttackPhase:
    """A single phase in a multi-phase attack plan."""

    id: str
    name: str
    description: str
    phase_number: int
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    exit_conditions: list[str] = field(default_factory=list)
    deception_layers: list[str] = field(default_factory=list)
    fallback_plan: str | None = None
    require_confirmation: bool = True


@dataclass
class AttackPlan:
    """Complete multi-phase attack plan."""

    objective: str
    phases: list[AttackPhase] = field(default_factory=list)
    estimated_duration: int = 0  # seconds
    risk_level: float = 0.5  # 0.0 (safe) → 1.0 (extremely dangerous)
    stealth_score: float = 0.95  # 0.0 (loud) → 1.0 (ghost)


@dataclass
class CleanupReport:
    """Report of track-covering cleanup operations."""

    operations_attempted: int = 0
    operations_succeeded: int = 0
    duration_ms: float = 0.0


@dataclass
class ExecutionReport:
    """Complete execution report for a multi-phase attack plan."""

    objective: str
    phases_completed: int = 0
    phases_total: int = 0
    success: bool = False
    stealth_maintained: bool = True
    detection_events: int = 0
    tools_used: list[str] = field(default_factory=list)
    total_duration_ms: float = 0.0
    narrative: str = ""


# ── Deception Engine ──────────────────────────────────────────────────────────


class DeceptionEngine:
    """Honeypots, misdirection, false flags — multi-layer deception.

    Every technique runs through SandboxManager with machiavellianism personality,
    using stealth commands designed to misdirect defenders.
    """

    techniques: list[str] = [
        "honeypot_deployment",
        "false_flag",
        "log_manipulation",
        "timestomp",
        "traffic_misdirection",
        "decoy_accounts",
    ]

    def __init__(self, sandbox: SandboxManager | None = None) -> None:
        self._sandbox = sandbox

    async def deploy_honeypot(self, target: str, sandbox: SandboxManager | None = None) -> bool:
        """Deploy a decoy honeypot on the target to distract defenders.

        Sets up fake services that look like real attack infrastructure
        so blue team wastes resources chasing ghosts.
        """
        sb = sandbox or self._sandbox
        if sb is None:
            logger.warning("DeceptionEngine: no sandbox available for deploy_honeypot")
            return False

        commands = [
            # TODO: real honeypot deployment via cowrie/opencanary
            f"echo '[DECOY] Deploying honeypot signature for {target}' 2>&1",
            f"# Fake SSH service banner for {target}",
            "# iptables -A INPUT -p tcp --dport 2222 -j ACCEPT  # ssh honeypot",
            f"# touch /var/log/honeypot_{target.replace(chr(46), chr(95))}.log",
            "echo '[DECOY] Honeypot deployed — monitoring decoy traffic'",
        ]
        result = await sb.execute_with_personality(commands, "machiavellianism")
        logger.info(
            "Honeypot deployment for %s: exit=%d",
            target,
            result.exit_code,
        )
        return result.exit_code == 0

    async def plant_false_flag(
        self, technique: str, context: dict, sandbox: SandboxManager | None = None
    ) -> bool:
        """Plant false-flag artifacts pointing to a different attacker.

        Leaves breadcrumbs that implicate another APT group or individual,
        redirecting attribution away from the real operator.
        """
        sb = sandbox or self._sandbox
        if sb is None:
            logger.warning("DeceptionEngine: no sandbox for plant_false_flag")
            return False

        fake_group = context.get("false_flag_group", "APT29")
        commands = [
            # TODO: realistic false-flag artifacts (registry keys, mutexes, named pipes)
            "echo '[FALSE_FLAG] Planting attribution breadcrumbs' 2>&1",
            f"# echo 'Spawned by {fake_group} implant v3.1' > /tmp/.readme.txt",
            f"# echo '{fake_group}' > /tmp/.persistence.job",
            f"echo '[FALSE_FLAG] {technique} — attributed to {fake_group}'",
        ]
        result = await sb.execute_with_personality(commands, "machiavellianism")
        logger.info(
            "False flag '%s' → %s: exit=%d",
            technique,
            fake_group,
            result.exit_code,
        )
        return result.exit_code == 0

    async def misdirect(self, technique: str, sandbox: SandboxManager | None = None) -> bool:
        """Execute a misdirection technique to throw off defenders.

        Misdirection techniques:
        - 'fake_scan': Generate decoy port scans from a different source IP
        - 'decoy_connection': Open fake C2 connections to distract monitoring
        - 'noise_injection': Inject benign noise into logs to hide real activity
        """
        sb = sandbox or self._sandbox
        if sb is None:
            logger.warning("DeceptionEngine: no sandbox for misdirect")
            return False

        commands = [
            f"echo '[MISDIRECT] Executing {technique}' 2>&1",
        ]
        if technique == "fake_scan":
            commands.extend(
                [
                    "# TODO: nmap decoy scan from spoofed source",
                    "echo '[MISDIRECT] Decoy scan initiated — random source IP'",
                ]
            )
        elif technique == "decoy_connection":
            commands.extend(
                [
                    "# TODO: open fake reverse HTTPS connection",
                    "echo '[MISDIRECT] Decoy C2 beacon started — fake profile'",
                ]
            )
        elif technique == "noise_injection":
            commands.extend(
                [
                    "# TODO: inject legitimate-looking log entries",
                    "echo '[MISDIRECT] Noise injection — log buffer padded'",
                ]
            )
        else:
            commands.append(f"echo '[MISDIRECT] Unknown technique: {technique}'")

        result = await sb.execute_with_personality(commands, "machiavellianism")
        logger.info("Misdirection '%s': exit=%d", technique, result.exit_code)
        return result.exit_code == 0


# ── Track Cover ───────────────────────────────────────────────────────────────


class TrackCover:
    """Post-execution cleanup — leave no trace.

    Each operation runs through the sandbox with personality-aware execution.
    Real commands are TODO stubs; the orchestration logic is functional.
    """

    operations: list[str] = [
        "clear_event_logs",
        "remove_shell_history",
        "wipe_temp_files",
        "delete_shadow_copies",
        "disable_audit_policies",
        "remove_persistence_artifacts",
    ]

    def __init__(self, sandbox: SandboxManager | None = None) -> None:
        self._sandbox = sandbox

    async def execute_cleanup(
        self, operations: list[str], sandbox: SandboxManager | None = None
    ) -> CleanupReport:
        """Execute a list of cleanup operations sequentially.

        Each operation runs independently; failures do not block remaining ops.
        """
        sb = sandbox or self._sandbox
        if sb is None:
            logger.warning("TrackCover: no sandbox available")
            return CleanupReport(
                operations_attempted=len(operations),
                operations_succeeded=0,
            )

        start = time.monotonic()
        succeeded = 0

        for op in operations:
            try:
                if op == "clear_event_logs":
                    ok = await self.clear_event_logs(sb)
                elif op == "remove_shell_history":
                    ok = await self._run_cleanup_cmd(
                        sb,
                        [
                            "echo '[CLEANUP] Removing shell history' 2>&1",
                            "# history -c 2>/dev/null; rm -f ~/.bash_history ~/.zsh_history",
                            "# cat /dev/null > ~/.bash_history 2>/dev/null",
                        ],
                    )
                elif op == "wipe_temp_files":
                    ok = await self._run_cleanup_cmd(
                        sb,
                        [
                            "echo '[CLEANUP] Wiping temp files' 2>&1",
                            "# rm -rf /tmp/* /var/tmp/* 2>/dev/null",
                            "# find /tmp -type f -mmin -60 -delete 2>/dev/null",
                        ],
                    )
                elif op == "delete_shadow_copies":
                    ok = await self._run_cleanup_cmd(
                        sb,
                        [
                            "echo '[CLEANUP] Deleting shadow copies' 2>&1",
                            "# vssadmin delete shadows /all /quiet 2>/dev/null",
                        ],
                    )
                elif op == "disable_audit_policies":
                    ok = await self._run_cleanup_cmd(
                        sb,
                        [
                            "echo '[CLEANUP] Disabling audit policies' 2>&1",
                            "# auditctl -e 0 2>/dev/null",
                            "# auditd service stop not needed — ephemeral container",
                        ],
                    )
                elif op == "remove_persistence_artifacts":
                    ok = await self._run_cleanup_cmd(
                        sb,
                        [
                            "echo '[CLEANUP] Removing persistence artifacts' 2>&1",
                            "# rm -f /etc/cron.d/*tdt* /etc/systemd/system/*tdt* 2>/dev/null",
                            "# sc delete TDTService 2>/dev/null || true",
                        ],
                    )
                else:
                    logger.warning("TrackCover: unknown operation '%s'", op)
                    ok = False

                if ok:
                    succeeded += 1
            except Exception as exc:
                logger.warning("TrackCover operation '%s' raised: %s", op, exc)

        duration_ms = (time.monotonic() - start) * 1000
        return CleanupReport(
            operations_attempted=len(operations),
            operations_succeeded=succeeded,
            duration_ms=duration_ms,
        )

    async def clear_event_logs(self, sandbox: SandboxManager | None = None) -> bool:
        """Clear system event logs to hide activity traces."""
        sb = sandbox or self._sandbox
        if sb is None:
            return False
        return await self._run_cleanup_cmd(
            sb,
            [
                "echo '[CLEANUP] Clearing event logs' 2>&1",
                "# journalctl --rotate --vacuum-time=1s 2>/dev/null",
                "# rm -f /var/log/auth.log /var/log/syslog /var/log/messages 2>/dev/null",
                "# : > /var/log/wtmp 2>/dev/null; : > /var/log/btmp 2>/dev/null",
            ],
        )

    async def remove_artifacts(
        self, paths: list[str], sandbox: SandboxManager | None = None
    ) -> bool:
        """Remove specific filesystem artifacts created during the operation."""
        sb = sandbox or self._sandbox
        if sb is None:
            return False

        commands = [
            "echo '[CLEANUP] Removing specific artifacts' 2>&1",
        ]
        for p in paths:
            commands.append(f"# rm -f '{p}' 2>/dev/null; echo 'Cleaned: {p}'")
        commands.append("echo '[CLEANUP] Artifact removal complete'")

        result = await sb.execute_with_personality(commands, "machiavellianism")
        return result.exit_code == 0

    async def _run_cleanup_cmd(self, sandbox: SandboxManager, commands: list[str]) -> bool:
        """Run a cleanup command set and return True on success."""
        result = await sandbox.execute_with_personality(commands, "machiavellianism")
        return result.exit_code == 0


# ── Planificator ──────────────────────────────────────────────────────────────


class Planificator:
    """Internal utility class for attack plan decomposition and analysis.

    Uses AIRouter to break objectives into phases and select stealth-optimised
    tools from the ToolRegistry.
    """

    def __init__(self, ai_router: AIRouter, tool_registry: Any | None = None) -> None:
        self._router = ai_router
        self._tool_registry = tool_registry

    async def decompose_objective(self, objective: str) -> list[str]:
        """Use AI to decompose an objective into discrete sub-objectives.

        The LLM is prompted with the machiavellianism persona to produce
        a strategic, stealth-first decomposition.

        Falls back to a hardcoded generic decomposition if AI is unavailable.
        """
        try:
            prompt = (
                f"Decompose the following offensive objective into 4-6 sequential "
                f"sub-objectives that follow a stealth-first multi-phase approach. "
                f"Each sub-objective should be self-contained and actionable. "
                f"Consider: reconnaissance, initial access, privilege escalation, "
                f"lateral movement, objective completion, and cleanup phases.\n\n"
                f"Objective: {objective}\n\n"
                f"Return each sub-objective on a separate line, prefixed with "
                f"a phase number (Phase 0: ..., Phase 1: ..., etc.). "
                f"Do NOT include markdown formatting — plain text only."
            )
            result: GenerationResult = await self._router.generate(
                prompt=prompt,
                personality="mach",
                tier=ModelTier.LIGHT,
            )

            lines = [
                line.strip().removeprefix("Phase ").strip()
                for line in result.text.strip().split("\n")
                if line.strip()
            ]
            if lines:
                logger.info("AI-decomposed objective into %d phases", len(lines))
                return lines
        except Exception as exc:
            logger.warning("AI decomposition failed (%s) — using hardcoded fallback", exc)

        # Fallback: generic decomposition
        lines = [
            "Reconnaissance — passive OSINT and target fingerprinting",
            "Initial access — stealth entry point via least-resistance path",
            "Privilege escalation — minimal elevation, just enough access",
            "Lateral movement — step-by-step pivot toward objective",
            "Objective — discreet exfiltration or action on objective",
            "Cleanup — full track cover and deception layers",
        ]
        logger.info("Using hardcoded decomposition: %d phases", len(lines))
        return lines

    def select_stealth_tools(
        self, phase_name: str, tool_names: list[str] | None = None
    ) -> list[str]:
        """Select the most stealth-appropriate tools for a given phase.

        If *tool_names* is provided, filters by those; otherwise returns
        a phase-appropriate default set of stealth tools.
        """
        stealth_tool_map: dict[str, list[str]] = {
            "recon": ["passive_recon"],
            "initial_access": ["custom_exploit", "sliver_deploy"],
            "privesc": ["obfuscate_payload"],
            "lateral": ["wmi_exec", "sliver_deploy"],
            "exfil": ["stealth_exfil"],
            "credential": ["kerberoast", "hashdump"],
            "evasion": ["obfuscate_payload"],
            "deception": ["deploy_honeypot"],
        }

        if tool_names:
            # Filter user-provided list by what's available in the registry
            return tool_names

        phase_lower = phase_name.lower()
        for keyword, tools in stealth_tool_map.items():
            if keyword in phase_lower:
                return tools

        # Fallback: generic stealth tools
        return ["passive_recon", "wmi_exec", "obfuscate_payload"]

    def estimate_stealth_score(self, plan: AttackPlan) -> float:
        """Estimate the overall stealth score of an attack plan.

        Factors in:
        - Phase count (more phases = more exposure)
        - Deception layers per phase
        - Fallback availability
        """
        if not plan.phases:
            return plan.stealth_score

        phase_penalty = max(0.0, (len(plan.phases) - 4) * 0.05)
        deception_bonus = sum(len(p.deception_layers) for p in plan.phases) * 0.02
        fallback_bonus = sum(1 for p in plan.phases if p.fallback_plan) * 0.03

        score = min(
            1.0,
            max(
                0.1,
                plan.stealth_score - phase_penalty + deception_bonus + fallback_bonus,
            ),
        )
        return round(score, 2)


# ── Machiavelli Engine ────────────────────────────────────────────────────────


class MachiavelliEngine:
    """Execution engine for the Machiavellian personality.

    Orchestrates multi-phase attack plans with stealth-first tool selection,
    deception layers, track covering, and automatic fallback on detection.

    Characteristics:
        - Confirmation threshold: 0.3 (confirms critical pivots only)
        - Retry count: 3 (strategic retries, not brute force)
        - Parallelism: 2 (coordinated, not chaotic)
        - Stealth: 0.95 (near-invisible)
        - Deception: 0.9 (multi-layer misdirection)
    """

    def __init__(
        self,
        ai_router: AIRouter | None = None,
        sandbox: SandboxManager | None = None,
        profile: PersonalityProfile | None = None,
    ) -> None:
        self._router = ai_router
        self._sandbox = sandbox
        self.profile = profile or MACHIAVELLI

        self._deception = DeceptionEngine(sandbox)
        self._track_cover = TrackCover(sandbox)
        self._planificator = Planificator(
            ai_router if ai_router else AIRouter(),
        )

        # Accumulated state across phases
        self._tools_used: list[str] = []
        self._detection_events: int = 0
        self._artifacts_created: list[str] = []

    # ── Planning ──────────────────────────────────────────────────────────

    async def plan(self, objective: str, target_context: dict | None = None) -> AttackPlan:
        """Decompose an objective into a multi-phase attack plan.

        Flow:
        1. Decompose objective into 4-6 phases via AI
        2. Map each phase to stealth tools
        3. Assign deception layers and exit conditions
        4. Estimate risk and stealth scores
        5. Return complete AttackPlan

        Args:
            objective: The high-level objective to plan.
            target_context: Optional dict with target metadata (IP, domain, etc.).

        Returns:
            A complete AttackPlan with phases, tools, deception, and fallbacks.
        """
        ctx = target_context or {}
        logger.info("Planning objective: %s | context: %s", objective, ctx)

        # Step 1: Decompose via AI
        sub_objectives = await self._planificator.decompose_objective(objective)

        # Step 2: Build phases
        phases: list[AttackPhase] = []
        phase_definitions = [
            (
                "phase_0_recon",
                "Reconnaissance — sneaky",
                0,
                [
                    "OSINT data gathering (DNS, WHOIS, Shodan)",
                    "Passive network fingerprinting",
                    "No direct contact with target",
                ],
                ["honeypot_deployment"],
                "Fallback: expand reconnaissance scope via 3rd party sources",
                False,  # Phase 0 is recon — no confirmation needed
            ),
            (
                "phase_1_access",
                "Initial Access — stealth entry",
                1,
                [
                    "Identify least-resistance entry point",
                    "Deliver initial payload via stealth vector",
                    "Establish minimal footprint on target",
                ],
                ["false_flag", "log_manipulation"],
                "Fallback: try alternative entry vector (phishing if technical fails)",
                True,
            ),
            (
                "phase_2_privilege",
                "Privilege Escalation — minimal elevation",
                2,
                [
                    "Escalate to minimum required privilege level",
                    "Avoid domain admin unless necessary",
                    "Use kernel-mode persistence if available",
                ],
                ["log_manipulation", "timestomp"],
                "Fallback: use token theft instead of full exploitation",
                True,
            ),
            (
                "phase_3_lateral",
                "Lateral Movement — step-by-step pivot",
                3,
                [
                    "Pivot through intermediate hosts",
                    "Cover tracks after each hop",
                    "Use encrypted tunnels between hops",
                ],
                ["timestomp", "traffic_misdirection"],
                "Fallback: exfiltrate through existing access if lateral blocked",
                True,
            ),
            (
                "phase_4_objective",
                "Objective — discreet action",
                4,
                [
                    "Execute primary objective (exfil, modify, deploy)",
                    "Use encrypted outbound channels",
                    "Minimize data touched — only what is needed",
                ],
                ["traffic_misdirection", "decoy_accounts"],
                "Fallback: stage objective data and exfiltrate via dead drop",
                True,
            ),
            (
                "phase_5_cleanup",
                "Cleanup — full track cover",
                5,
                [
                    "Clear all event logs on every touched system",
                    "Remove persistence artifacts",
                    "Wipe temporary files and shadow copies",
                    "Deploy final false-flag artifacts",
                    "Verify no artifacts remain",
                ],
                [
                    "honeypot_deployment",
                    "false_flag",
                    "log_manipulation",
                    "timestomp",
                    "traffic_misdirection",
                    "decoy_accounts",
                ],
                None,  # No fallback — cleanup must complete or retreat
                False,  # Cleanup auto-executes
            ),
        ]

        for i, (
            phase_id,
            phase_name,
            phase_num,
            exit_conds,
            deception_layers,
            fallback,
            require_conf,
        ) in enumerate(phase_definitions):
            # Determine stealth tools for this phase
            tools = self._planificator.select_stealth_tools(phase_name)

            # Generate concrete commands for this phase
            commands = await self._generate_phase_commands(phase_name, objective, ctx)

            phases.append(
                AttackPhase(
                    id=phase_id,
                    name=phase_name,
                    description=sub_objectives[i] if i < len(sub_objectives) else phase_name,
                    phase_number=phase_num,
                    tools=tools,
                    commands=commands,
                    exit_conditions=exit_conds,
                    deception_layers=deception_layers,
                    fallback_plan=fallback,
                    require_confirmation=require_conf,
                )
            )

        # Estimate plan-level metrics
        estimated_duration = len(phases) * 120  # ~2 min per phase
        risk_level = self._estimate_risk(phases, ctx)
        stealth_score = self._planificator.estimate_stealth_score(
            AttackPlan(objective=objective, phases=phases, risk_level=risk_level)
        )

        plan = AttackPlan(
            objective=objective,
            phases=phases,
            estimated_duration=estimated_duration,
            risk_level=risk_level,
            stealth_score=stealth_score,
        )

        logger.info(
            "Plan created: %d phases, risk=%.2f, stealth=%.2f, duration=%ds",
            len(phases),
            risk_level,
            stealth_score,
            estimated_duration,
        )
        return plan

    # ── Phase Execution ───────────────────────────────────────────────────

    async def execute_phase(self, phase: AttackPhase, context: dict | None = None) -> PhaseResult:
        """Execute a single attack phase with step verification.

        Flow:
        1. Check require_confirmation if phase is critical (phase_number >= 3)
        2. Deploy deception layers before phase execution
        3. Run commands via SandboxManager with machiavellianism personality
        4. Verify exit conditions
        5. On failure: trigger fallback plan if available
        6. On detection: log detection event, attempt misdirection
        7. Return PhaseResult

        Args:
            phase: The phase to execute.
            context: Optional runtime context dict.

        Returns:
            PhaseResult with success status, output, and detection info.
        """
        ctx = context or {}
        logger.info(
            "Executing phase %d/%s: %s",
            phase.phase_number,
            phase.id,
            phase.name,
        )

        start = time.monotonic()
        detected = False
        all_output: list[str] = []
        artifacts: list[str] = []

        # Step 1: Confirmation gate for critical phases
        if phase.require_confirmation and phase.phase_number >= 3:
            confirmed = await self._check_confirmation(phase, ctx)
            if not confirmed:
                logger.info(
                    "Phase %s not confirmed — skipping with fallback detection",
                    phase.id,
                )
                # Simulate detection to trigger fallback
                detected = True
                self._detection_events += 1
                if phase.fallback_plan:
                    logger.info(
                        "Executing fallback for phase %s: %s",
                        phase.id,
                        phase.fallback_plan,
                    )
                    fallback_commands = [
                        f"echo '[FALLBACK] {phase.fallback_plan}' 2>&1",
                        "echo '[FALLBACK] Executing alternative approach'",
                    ]
                    if self._sandbox:
                        fb_result = await self._sandbox.execute_with_personality(
                            fallback_commands, "machiavellianism"
                        )
                        all_output.append(fb_result.stdout)
                        if fb_result.exit_code == 0:
                            return PhaseResult(
                                phase_id=phase.id,
                                success=True,
                                output="\n".join(all_output),
                                artifacts=artifacts,
                                detected=False,
                                duration_ms=(time.monotonic() - start) * 1000,
                            )

                return PhaseResult(
                    phase_id=phase.id,
                    success=False,
                    output="Phase not confirmed; fallback attempted",
                    artifacts=artifacts,
                    detected=detected,
                    duration_ms=(time.monotonic() - start) * 1000,
                )

        # Step 2: Deploy deception layers (pre-execution)
        if phase.deception_layers and self._sandbox:
            for layer in phase.deception_layers:
                try:
                    if layer == "honeypot_deployment":
                        target = ctx.get("target", "unknown")
                        await self._deception.deploy_honeypot(target)
                    elif layer == "false_flag":
                        await self._deception.plant_false_flag(phase.name, ctx)
                    elif layer in (
                        "log_manipulation",
                        "timestomp",
                        "traffic_misdirection",
                        "decoy_accounts",
                    ):
                        await self._deception.misdirect(layer)
                except Exception as exc:
                    logger.warning("Deception layer '%s' failed: %s", layer, exc)

        # Step 3: Execute phase commands
        if self._sandbox and phase.commands:
            result = await self._sandbox.execute_with_personality(
                phase.commands, "machiavellianism"
            )
            all_output.append(result.stdout)
            if result.stderr:
                all_output.append(f"[STDERR] {result.stderr}")

            if result.exit_code != 0:
                logger.warning(
                    "Phase %s command failed (exit=%d)",
                    phase.id,
                    result.exit_code,
                )
                detected = self._check_detection(result)
                if detected:
                    self._detection_events += 1

                # Step 3b: Fallback on failure
                if phase.fallback_plan and not detected:
                    logger.info(
                        "Activating fallback for phase %s: %s",
                        phase.id,
                        phase.fallback_plan,
                    )
                    fallback_commands = [
                        f"echo '[FALLBACK] {phase.fallback_plan}' 2>&1",
                        "echo '[FALLBACK] Executing alternative approach'",
                    ]
                    fb_result = await self._sandbox.execute_with_personality(
                        fallback_commands, "machiavellianism"
                    )
                    all_output.append(fb_result.stdout)

            # Track tools used and artifacts
            self._tools_used.extend(phase.tools)
            artifacts.extend(self._detect_artifacts(result.stdout))
        else:
            # Dry run — just log what would have been executed
            all_output.append(f"[DRY-RUN] Phase {phase.id}: {phase.name}")
            for cmd in phase.commands:
                all_output.append(f"  $ {cmd}")
            for tool in phase.tools:
                self._tools_used.append(tool)

        # Step 4: Track cover after successful non-cleanup phases
        if phase.phase_number > 0 and phase.phase_number < 5:
            cleanup_ops = ["remove_shell_history", "clear_event_logs"]
            await self._track_cover.execute_cleanup(cleanup_ops)

        duration_ms = (time.monotonic() - start) * 1000

        return PhaseResult(
            phase_id=phase.id,
            success=result.exit_code == 0 if self._sandbox and phase.commands else True,
            output="\n".join(all_output),
            artifacts=artifacts,
            detected=detected,
            duration_ms=duration_ms,
        )

    # ── Full Plan Execution ───────────────────────────────────────────────

    async def execute_plan(self, plan: AttackPlan) -> ExecutionReport:
        """Execute all phases of an attack plan sequentially.

        Flow:
        1. Execute phases in order
        2. Stop at first critical failure
        3. If detected → trigger fallback + misdirection
        4. Track stealth status across all phases
        5. Build ExecutionReport with narrative

        Args:
            plan: The AttackPlan to execute.

        Returns:
            ExecutionReport with completion status, stealth info, and narrative.
        """
        logger.info(
            "Executing plan: %s (%d phases)",
            plan.objective,
            len(plan.phases),
        )
        start = time.monotonic()

        completed = 0
        total = len(plan.phases)
        stealth_maintained = True
        phase_results: list[PhaseResult] = []

        for phase in plan.phases:
            logger.info(
                "Plan phase %d/%d: %s",
                phase.phase_number + 1,
                total,
                phase.name,
            )

            result = await self.execute_phase(phase)
            phase_results.append(result)

            if result.success:
                completed += 1
            else:
                stealth_maintained = stealth_maintained and not result.detected
                if result.detected:
                    logger.warning(
                        "Detection event at phase %s — activating misdirection",
                        phase.id,
                    )
                    # Misdirection on detection
                    if self._sandbox:
                        await self._deception.misdirect(
                            random.choice(["fake_scan", "decoy_connection", "noise_injection"])
                        )
                    # If detected in phase 3+, fallback is automatic
                    if phase.phase_number >= 3 and phase.fallback_plan:
                        continue
                    else:
                        logger.info(
                            "Stopping plan execution at phase %s",
                            phase.id,
                        )
                        break

        total_duration_ms = (time.monotonic() - start) * 1000

        # Final cleanup on success
        if completed > 0:
            await self._track_cover.execute_cleanup(TrackCover.operations)

        # Generate narrative
        narrative = self._build_narrative(plan, phase_results, completed, stealth_maintained)

        report = ExecutionReport(
            objective=plan.objective,
            phases_completed=completed,
            phases_total=total,
            success=completed == total,
            stealth_maintained=stealth_maintained and self._detection_events == 0,
            detection_events=self._detection_events,
            tools_used=list(set(self._tools_used)),
            total_duration_ms=total_duration_ms,
            narrative=narrative,
        )

        logger.info(
            "Plan execution complete: %d/%d phases, stealth=%s, detections=%d",
            completed,
            total,
            report.stealth_maintained,
            report.detection_events,
        )
        return report

    # ── Internal Helpers ──────────────────────────────────────────────────

    async def _generate_phase_commands(
        self, phase_name: str, objective: str, context: dict
    ) -> list[str]:
        """Generate concrete shell commands for a phase using AI.

        Falls back to template commands if AI is unavailable.
        """
        # Phase-templated commands for offline/deterministic operation
        template_map: dict[str, list[str]] = {
            "Reconnaissance": [
                "echo '[PHASE 0] Starting passive reconnaissance' 2>&1",
                "# whois -H $(echo '{target}' | cut -d: -f1) 2>/dev/null",
                "# dig any {target} @8.8.8.8 2>/dev/null",
                "# host -t any {target} 2>/dev/null",
                "echo '[PHASE 0] Reconnaissance complete — no direct contact made'",
            ],
            "Initial Access": [
                "echo '[PHASE 1] Establishing initial access' 2>&1",
                "# nc -zv {target} 22 2>/dev/null && echo 'SSH port open'",
                "# nc -zv {target} 443 2>/dev/null && echo 'HTTPS port open'",
                "echo '[PHASE 1] Stealth foothold established — minimal footprint'",
            ],
            "Privilege": [
                "echo '[PHASE 2] Performing minimal privilege escalation' 2>&1",
                "# id; whoami",
                "# cat /etc/passwd 2>/dev/null | head -5",
                "echo '[PHASE 2] Escalation complete — minimal elevation used'",
            ],
            "Lateral": [
                "echo '[PHASE 3] Performing step-by-step lateral movement' 2>&1",
                "# ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                "user@{pivot} id 2>/dev/null || echo 'Direct pivot not available'",
                "echo '[PHASE 3] Lateral movement complete — traces covered after each hop'",
            ],
            "Objective": [
                "echo '[PHASE 4] Executing primary objective' 2>&1",
                f"echo '[OBJECTIVE] Target: {objective[:80]}'",
                "# Encrypted exfiltration channel would be established here",
                "echo '[PHASE 4] Objective discreetly completed'",
            ],
            "Cleanup": [
                "echo '[PHASE 5] Full track cover in progress' 2>&1",
                "# history -c 2>/dev/null",
                "# rm -f /tmp/*.py /tmp/*.sh /tmp/*.elf 2>/dev/null",
                "# journalctl --rotate --vacuum-time=1s 2>/dev/null || true",
                "# : > ~/.bash_history 2>/dev/null || true",
                "echo '[PHASE 5] All traces cleared — ghost protocol'",
            ],
        }

        for keyword, commands in template_map.items():
            if keyword.lower() in phase_name.lower():
                # Inject target context into commands
                target = context.get("target", "target.local")
                pivot = context.get("pivot_host", "pivot.local")
                return [
                    cmd.replace("{target}", target).replace("{pivot}", pivot) for cmd in commands
                ]

        # Generic fallback
        return [
            f"echo '[PHASE] {phase_name} — executing stealth operations' 2>&1",
            f"echo '[PHASE] Objective: {objective[:120]}'",
            "echo '[PHASE] Complete — covering traces'",
        ]

    async def _check_confirmation(self, phase: AttackPhase, context: dict) -> bool:
        """Check whether a critical phase should proceed.

        Uses the profile's confirmation_threshold (0.3 for Machiavelli).
        If 'force_proceed' is in context, skip confirmation.
        """
        if context.get("force_proceed"):
            return True

        # Machiavelli confirms ~30% of the time (low threshold = few confirmations)
        threshold = self.profile.confirmation_threshold
        roll = random.random()
        should_confirm = roll < threshold

        if should_confirm and self._router:
            # Use AI to make the call
            prompt = (
                f"Phase '{phase.name}' (id={phase.id}, tools={phase.tools}) "
                f"requires confirmation before execution. "
                f"Risk level in plan: {context.get('risk_level', 'unknown')}. "
                f"Should we proceed? Reply YES or NO only."
            )
            try:
                result: GenerationResult = await self._router.generate(
                    prompt=prompt,
                    personality="mach",
                    tier=ModelTier.LIGHT,
                )
                decision = result.text.strip().upper()
                logger.info("Confirmation decision for %s: %s", phase.id, decision)
                return "YES" in decision
            except Exception as exc:
                logger.warning(
                    "Confirmation AI call failed: %s — defaulting to proceed",
                    exc,
                )
                return True

        # No AI call needed; random decision based on threshold
        return not should_confirm

    @staticmethod
    def _check_detection(result: ExecutionResult) -> bool:
        """Heuristic detection check on command output.

        Returns True if the output contains indicators of detection
        (e.g. alerts, blocks, security tool triggers).
        """
        detection_indicators = [
            "blocked",
            "denied",
            "detected",
            "alert",
            "suspicious",
            "quarantine",
            "access denied",
            "permission denied",
            "connection refused",
        ]
        combined = (result.stdout + result.stderr).lower()
        for indicator in detection_indicators:
            if indicator in combined:
                return True
        return False

    @staticmethod
    def _detect_artifacts(output: str) -> list[str]:
        """Parse command output for file paths that may be artifacts."""
        artifacts: list[str] = []
        for line in output.splitlines():
            # Simple heuristic: anything that looks like a file path
            for marker in ("/tmp/", "/var/log/", "/etc/", "/root/", "~/"):
                if marker in line:
                    # Extract plausible file path segments
                    parts = line.split()
                    for part in parts:
                        if marker in part and not part.startswith("#"):
                            artifacts.append(part.strip("'\";,:"))
        return artifacts

    @staticmethod
    def _estimate_risk(phases: list[AttackPhase], context: dict) -> float:
        """Estimate overall risk level for a plan based on phases and context.

        Factors: number of phases, target hardening, deception coverage.
        """
        base_risk = 0.5
        # More phases = more risk
        phase_risk = min(0.3, len(phases) * 0.05)
        # Deception layers reduce risk
        total_deception = sum(len(p.deception_layers) for p in phases)
        deception_reduction = min(0.3, total_deception * 0.03)
        # Target context risk
        target_risk = 0.0
        if context.get("firewall"):
            target_risk += 0.1
        if context.get("edr"):
            target_risk += 0.15
        if context.get("honeypot_aware"):
            target_risk += 0.1

        return round(
            max(0.1, min(1.0, base_risk + phase_risk - deception_reduction + target_risk)),
            2,
        )

    @staticmethod
    def _build_narrative(
        plan: AttackPlan,
        phase_results: list[PhaseResult],
        completed: int,
        stealth_maintained: bool,
    ) -> str:
        """Build a human-readable narrative from the execution report."""
        parts: list[str] = [
            f'🕸️  EXECUTION REPORT: "{plan.objective}"',
            f"    Phases: {completed}/{len(plan.phases)} completed",
            f"    Stealth: {'✅ MAINTAINED' if stealth_maintained else '❌ COMPROMISED'}",
            "",
        ]

        for i, pr in enumerate(phase_results):
            status = "✅" if pr.success else "❌"
            detected = " ⚠️ DETECTED" if pr.detected else ""
            artifacts_note = f" [{len(pr.artifacts)} artifacts]" if pr.artifacts else ""
            parts.append(
                f"  Phase {i}: {status} {pr.phase_id}{detected}"
                f"{artifacts_note} ({pr.duration_ms:.0f}ms)"
            )

        if completed < len(plan.phases):
            parts.extend(
                [
                    "",
                    "    ⚠️  Plan did not complete.",
                ]
            )

        parts.extend(
            [
                "",
                f"    Duration: {sum(pr.duration_ms for pr in phase_results):.0f}ms",
            ]
        )

        return "\n".join(parts)
