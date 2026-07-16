"""The Dark Triad — Orchestrator Agent.

Decomposes objectives into mission plans, dispatches sub-tasks to
specialist agents, and aggregates results. Personality-aware planning.
"""

from __future__ import annotations

import asyncio
import time

import structlog

from decepticon.navmax.darktriad.agents.base import AgentResult, AgentStep, BaseAgent
from decepticon.navmax.darktriad.core.ai_router import AIRouter, ModelTier
from decepticon.navmax.darktriad.core.personality import PersonalityProfile
from decepticon.navmax.darktriad.core.sandbox import SandboxManager
from decepticon.navmax.darktriad.core.tool_registry import ToolRegistry
from decepticon.navmax.darktriad.orchestrator.shared import MissionPhase, MissionPlan

logger = structlog.get_logger(__name__)


class OrchestratorAgent(BaseAgent):
    """Decomposes objectives, plans missions, and dispatches sub-tasks.

    Personality modes drive the plan structure:

      NARCISSUS   → 1 phase, executes everything itself
      PSYCHOPATH  → N phases, dispatches all in parallel
      MACHIAVELLI → 5+ phases, sequential chain with verification
    """

    category = "orchestration"

    def __init__(
        self,
        name: str,
        personality: PersonalityProfile,
        ai_router: AIRouter,
        sandbox: SandboxManager,
    ) -> None:
        super().__init__(name, personality, ai_router, sandbox)

    async def execute(self, objective: str, context: dict | None = None) -> AgentResult:
        """Full orchestration lifecycle: analyse → plan → dispatch → aggregate.

        1. Uses AIRouter to analyse the objective.
        2. Creates a mission plan (phases).
        3. Selects agents via ToolRegistry.
        4. Delegates sub-tasks (Phase 4: real inter-agent calls).
        5. Aggregates results.
        """
        start = time.monotonic()
        steps: list[AgentStep] = []
        step_num = 0
        ctx = context or {}

        # ── Step 1: Analyse ─────────────────────────────────────────────
        step_num += 1
        s1 = AgentStep(step_number=step_num, action="analyse_objective")
        steps.append(s1)
        try:
            analysis = await self._analyse_objective(objective, ctx)
            s1.result = str(analysis)
            s1.duration_ms = (time.monotonic() - start) * 1000
        except Exception as e:
            s1.result = f"Failed: {e}"
            return self._build_result(steps, objective, error=str(e))

        # ── Step 2: Plan mission ────────────────────────────────────────
        step_num += 1
        s2 = AgentStep(step_number=step_num, action="plan_mission")
        steps.append(s2)
        try:
            plan = await self.plan_mission(objective, ctx)
            s2.result = f"{len(plan.phases)} phases, risk={plan.risk_level}"
            s2.duration_ms = (time.monotonic() - start) * 1000
        except Exception as e:
            s2.result = f"Failed: {e}"
            return self._build_result(steps, objective, error=str(e))

        if not plan.phases:
            return self._build_result(
                steps,
                objective,
                error="Mission plan has zero phases",
            )

        # ── Step 3: Dispatch phases ─────────────────────────────────────
        step_num += 1
        s3 = AgentStep(step_number=step_num, action="dispatch_phases")
        steps.append(s3)
        results: dict[str, AgentResult] = {}
        try:
            dispatch_results = await self._execute_plan(plan, ctx)
            results.update(dispatch_results)
            s3.result = f"Dispatched {len(results)} phases: {', '.join(results)}"
            s3.duration_ms = (time.monotonic() - start) * 1000
        except Exception as e:
            s3.result = f"Failed: {e}"
            plan_data = plan.asdict() if hasattr(plan, "asdict") else str(plan)
            return self._build_result(
                steps,
                objective,
                data={"plan": plan_data},
                error=str(e),
            )

        # ── Step 4: Aggregate ───────────────────────────────────────────
        step_num += 1
        s4 = AgentStep(step_number=step_num, action="aggregate_results")
        steps.append(s4)
        try:
            aggregated = self._aggregate(plan, results)
            s4.result = str(aggregated)
            s4.duration_ms = (time.monotonic() - start) * 1000
        except Exception as e:
            s4.result = f"Failed: {e}"

        success = all(r.success for r in results.values()) if results else False
        return AgentResult(
            agent_name=self.name,
            personality=self.personality_mode,
            objective=objective,
            success=success,
            output=self._format_summary(plan, results),
            tools_used=self.select_tools(),
            steps=steps,
            duration_ms=(time.monotonic() - start) * 1000,
        )

    # ── Mission Planning ─────────────────────────────────────────────────

    async def plan_mission(self, objective: str, context: dict | None = None) -> MissionPlan:
        """Create a personality-tailored mission plan."""
        ctx = context or {}
        persona = self.personality.mode.value

        if persona == "narcissism":
            return self._plan_narcissus(objective)
        elif persona == "psychopathy":
            return self._plan_psychopath(objective)
        else:
            return self._plan_machiavelli(objective, ctx)

    def _plan_narcissus(self, objective: str) -> MissionPlan:
        return MissionPlan(
            objective=objective,
            phases=[
                MissionPhase(
                    phase_number=1,
                    name="full_assault",
                    agent_name=self.name,
                    objective=objective,
                    depends_on=[],
                ),
            ],
            estimated_duration=30,
            risk_level=0.85,
        )

    def _plan_psychopath(self, objective: str) -> MissionPlan:
        tools = ToolRegistry.list_all()
        return MissionPlan(
            objective=objective,
            phases=[
                MissionPhase(
                    phase_number=i + 1,
                    name=f"parallel_{t.category.value}_{t.name}",
                    agent_name=t.category.value,
                    objective=f"Run {t.name} against {objective}",
                    depends_on=[],
                )
                for i, t in enumerate(tools)
            ],
            estimated_duration=120,
            risk_level=0.95,
        )

    def _plan_machiavelli(self, objective: str) -> MissionPlan:
        return MissionPlan(
            objective=objective,
            phases=[
                MissionPhase(
                    phase_number=1,
                    name="passive_recon",
                    agent_name="recon",
                    objective=f"Passive reconnaissance on {objective}",
                    depends_on=[],
                ),
                MissionPhase(
                    phase_number=2,
                    name="active_scan",
                    agent_name="recon",
                    objective=f"Active port/service scan on {objective}",
                    depends_on=["passive_recon"],
                ),
                MissionPhase(
                    phase_number=3,
                    name="vulnerability_analysis",
                    agent_name="recon",
                    objective=f"Vulnerability analysis for {objective}",
                    depends_on=["active_scan"],
                ),
                MissionPhase(
                    phase_number=4,
                    name="exploit_selection",
                    agent_name="exploit",
                    objective=f"Select exploit for {objective}",
                    depends_on=["vulnerability_analysis"],
                ),
                MissionPhase(
                    phase_number=5,
                    name="exploit_execution",
                    agent_name="exploit",
                    objective=f"Run exploit against {objective}",
                    depends_on=["exploit_selection"],
                ),
                MissionPhase(
                    phase_number=6,
                    name="post_exploit_verify",
                    agent_name="exploit",
                    objective=f"Verify exploitation on {objective}",
                    depends_on=["exploit_execution"],
                ),
            ],
            estimated_duration=600,
            risk_level=0.35,
        )

    # ── Dispatch ─────────────────────────────────────────────────────────

    async def dispatch(self, phase: str, agent_name: str, task: str) -> AgentResult:
        """Stub: dispatch a sub-task to a specialist agent.

        Phase 4 will route through actual inter-agent communication.
        """
        self._log.info("dispatch_stub", phase=phase, agent=agent_name, task=task)
        return AgentResult(
            agent_name=agent_name,
            personality=self.personality_mode,
            objective=task,
            success=True,
            output=f"Stub dispatch: {agent_name} → {task}",
            steps=[
                AgentStep(
                    step_number=1,
                    action="dispatch",
                    tool=agent_name,
                    result=f"phase={phase}, task={task}",
                )
            ],
        )

    async def _execute_plan(
        self,
        plan: MissionPlan,
        context: dict,
    ) -> dict[str, AgentResult]:
        """Execute all phases respecting dependency ordering."""
        persona = context.get("personality", self.personality.mode.value)
        results: dict[str, AgentResult] = {}
        phase_map = {p.name: p for p in plan.phases}

        if persona == "psychopathy":
            tasks = {
                p.name: asyncio.create_task(self.dispatch(p.name, p.agent_name, p.objective))
                for p in plan.phases
            }
            done = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for name, result in zip(tasks, done):
                if isinstance(result, BaseException):
                    results[name] = AgentResult(
                        agent_name=phase_map[name].agent_name,
                        personality=self.personality_mode,
                        objective=phase_map[name].objective,
                        success=False,
                        output=f"Exception: {result}",
                        steps=[],
                    )
                else:
                    results[name] = result
            return results

        executed: set[str] = set()
        remaining = list(plan.phases)

        while remaining:
            batch = [p for p in remaining if all(dep in executed for dep in p.depends_on)]
            if not batch:
                batch = [remaining[0]]
                self._log.warning(
                    "dependency_deadlock", phase=batch[0].name, waits=batch[0].depends_on
                )

            for phase in batch:
                remaining.remove(phase)

            if persona == "narcissism":
                for phase in batch:
                    result = await self.dispatch(phase.name, phase.agent_name, phase.objective)
                    results[phase.name] = result
                    executed.add(phase.name)
            else:
                tasks = {
                    p.name: asyncio.create_task(self.dispatch(p.name, p.agent_name, p.objective))
                    for p in batch
                }
                done = await asyncio.gather(*tasks.values(), return_exceptions=True)
                for name, result in zip(tasks, done):
                    if isinstance(result, BaseException):
                        results[name] = AgentResult(
                            agent_name=phase_map[name].agent_name,
                            personality=self.personality_mode,
                            objective=phase_map[name].objective,
                            success=False,
                            output=f"Exception: {result}",
                            steps=[],
                        )
                    else:
                        results[name] = result
                    executed.add(name)

        return results

    # ── Helpers ──────────────────────────────────────────────────────────

    def _aggregate(self, plan: MissionPlan, results: dict[str, AgentResult]) -> dict:
        total = len(plan.phases)
        succeeded = sum(1 for r in results.values() if r.success)
        return {
            "total_phases": total,
            "succeeded": succeeded,
            "failed": total - succeeded,
            "executed_phases": sorted(results.keys()),
            "summary": f"{succeeded}/{total} phases succeeded",
        }

    def _format_summary(self, plan: MissionPlan, results: dict[str, AgentResult]) -> str:
        lines = [f"Mission: {plan.objective} ({plan.risk_level:.2f} risk)"]
        for p in plan.phases:
            r = results.get(p.name)
            status = "✓" if r and r.success else "✗"
            lines.append(f"  {status} {p.name} ({p.agent_name})")
        return "\n".join(lines)

    def _build_result(
        self,
        steps: list[AgentStep],
        objective: str,
        data: dict | None = None,
        error: str | None = None,
    ) -> AgentResult:
        return AgentResult(
            agent_name=self.name,
            personality=self.personality_mode,
            objective=objective,
            success=error is None,
            output=error or f"Completed {len(steps)} steps",
            tools_used=self.select_tools(),
            steps=steps,
            duration_ms=sum(s.duration_ms for s in steps),
        )

    async def _analyse_objective(
        self,
        objective: str,
        context: dict,
    ) -> dict:
        try:
            result = await self.ai_router.generate(
                prompt=(
                    f"Analyse the following offensive security objective "
                    f"and extract: target, desired outcome, constraints, "
                    f"risk level (low/medium/high/critical).\n"
                    f"Personality: {self.personality_mode}\n"
                    f"Objective: {objective}"
                ),
                tier=ModelTier.LIGHT,
                json_mode=True,
            )
            import json

            return json.loads(result.text)
        except Exception as exc:
            self._log.warning("ai_router_fallback", error=str(exc))
            return {
                "target": objective.split()[0] if objective else "unknown",
                "desired_outcome": objective,
                "constraints": [],
                "risk_level": "medium",
            }
