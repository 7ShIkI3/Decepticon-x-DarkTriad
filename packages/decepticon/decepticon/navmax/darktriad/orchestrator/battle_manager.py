"""🜏 BattleManager — coordination temps-réel multi-agent.

Orchestre l'exécution d'un MissionPlan en respectant les dépendances,
la déconfliction entre agents, et une state machine par phase.
"""

from __future__ import annotations

import asyncio
import enum
import time
from dataclasses import dataclass, field

import structlog

from decepticon.navmax.darktriad.agents.base import BaseAgent
from decepticon.navmax.darktriad.agents.registry import AgentRegistry
from decepticon.navmax.darktriad.core.sandbox import SandboxManager
from decepticon.navmax.darktriad.orchestrator.shared import (
    MissionPhase,
    MissionPlan,
    PhaseResult,
    PhaseStatus,
)

logger = structlog.get_logger(__name__)

# ── Enums ─────────────────────────────────────────────────────────────────────


class ResolutionAction(enum.Enum):
    """Action de résolution d'un conflit entre agents."""

    WAIT = "wait"
    ABORT = "abort"
    REDIRECT = "redirect"
    QUEUE = "queue"
    FORCE = "force"


class RecoveryAction(enum.Enum):
    """Action de récupération après échec d'une phase."""

    RETRY = "retry"
    SKIP = "skip"
    ESCALATE = "escalate"
    ABORT_MISSION = "abort_mission"


# ── Dataclasses ───────────────────────────────────────────────────────────────


@dataclass
class ConflictReport:
    """Signalement d'un conflit entre deux agents sur une ressource."""

    agent_a: str
    agent_b: str
    resource: str
    conflict_type: str
    severity: str  # low | medium | high | critical


@dataclass
class BattleReport:
    """Rapport complet de bataille après exécution d'un plan."""

    mission_id: str
    phases_total: int
    phases_completed: int
    phases_failed: int
    phase_results: list[PhaseResult] = field(default_factory=list)
    conflicts: list[ConflictReport] = field(default_factory=list)
    total_duration_ms: float = 0.0
    success: bool = False
    recovery_actions: list[RecoveryAction] = field(default_factory=list)


# ── Deconfliction Engine ─────────────────────────────────────────────────────


class DeconflictionEngine:
    """Prévient les collisions entre agents sur les mêmes cibles/ressources.

    Utilise un locking distribué local pour garantir qu'un seul agent
    interagit avec une cible donnée à la fois.
    """

    def __init__(self) -> None:
        self._locks: dict[str, str] = {}  # target -> agent_name
        self._log = structlog.get_logger("tdt.orchestrator.deconfliction")

    # ── Public API ────────────────────────────────────────────────────────

    def check_conflict(self, agent_a: str, agent_b: str, target: str) -> ConflictReport:
        """Vérifie s'il y a conflit entre deux agents sur une même cible.

        Returns:
            ConflictReport avec détails du conflit (ou severity='none'
            s'il n'y a pas de conflit).
        """
        lock_holder_a = self._target_lock_holder(target)
        conflict_type = "target_contention"
        severity: str = "low"

        if lock_holder_a is None:
            return ConflictReport(
                agent_a=agent_a,
                agent_b=agent_b,
                resource=target,
                conflict_type="none",
                severity="none",
            )

        # Les deux agents veulent la même cible
        if lock_holder_a == agent_b or lock_holder_a == agent_a:
            # Déjà lockée par l'un des deux → conflit réel
            severity = "high" if self._is_aggressive(agent_a, agent_b) else "medium"
            return ConflictReport(
                agent_a=agent_a,
                agent_b=agent_b,
                resource=target,
                conflict_type=conflict_type,
                severity=severity,
            )

        # Lockée par un tiers
        return ConflictReport(
            agent_a=agent_a,
            agent_b=agent_b,
            resource=target,
            conflict_type="resource_owned",
            severity="medium",
        )

    def resolve_conflict(self, conflict: ConflictReport) -> ResolutionAction:
        """Décide de l'action à prendre face à un conflit.

        La décision dépend de la sévérité et du type de conflit.
        """
        if conflict.severity == "none" or conflict.conflict_type == "none":
            return ResolutionAction.QUEUE

        strategy: dict[str, ResolutionAction] = {
            "low": ResolutionAction.QUEUE,
            "medium": ResolutionAction.WAIT,
            "high": ResolutionAction.REDIRECT,
            "critical": ResolutionAction.ABORT,
        }
        action = strategy.get(conflict.severity, ResolutionAction.WAIT)

        self._log.info(
            "conflict_resolved",
            agents=f"{conflict.agent_a} vs {conflict.agent_b}",
            resource=conflict.resource,
            severity=conflict.severity,
            action=action.value,
        )
        return action

    def _target_lock(self, target: str, agent: str) -> bool:
        """Acquiert le lock sur une cible pour un agent.

        Returns:
            True si le lock a été acquis, False si déjà pris.
        """
        holder = self._locks.get(target)
        if holder is not None and holder != agent:
            return False
        self._locks[target] = agent
        self._log.debug("lock_acquired", target=target, agent=agent)
        return True

    def _target_unlock(self, target: str, agent: str) -> None:
        """Libère le lock sur une cible.

        L'agent doit être le détenteur actuel du lock.
        """
        current = self._locks.get(target)
        if current == agent:
            del self._locks[target]
            self._log.debug("lock_released", target=target, agent=agent)
        elif current is not None:
            self._log.warning(
                "unlock_mismatch",
                target=target,
                caller=agent,
                holder=current,
            )

    # ── Helpers ───────────────────────────────────────────────────────────

    def _target_lock_holder(self, target: str) -> str | None:
        """Retourne l'agent qui détient le lock sur une cible."""
        return self._locks.get(target)

    @staticmethod
    def _is_aggressive(agent_a: str, agent_b: str) -> bool:
        """Heuristique simple: noms contenant 'psycho' → agressif."""
        low_a = agent_a.lower()
        low_b = agent_b.lower()
        return "psycho" in low_a or "psycho" in low_b

    @property
    def active_locks(self) -> dict[str, str]:
        """Retourne une copie des locks actifs (lecture seule)."""
        return dict(self._locks)


# ── Battle Manager ────────────────────────────────────────────────────────────


class BattleManager:
    """Coordinateur temps-réel de bataille multi-agent.

    Orchestre l'exécution d'un MissionPlan complet:
    - State machine PENDING → IN_PROGRESS → COMPLETED|FAILED → SKIPPED
    - Déconfliction automatique entre agents
    - Exécution parallèle quand les dépendances le permettent
    - Gestion des erreurs et recovery
    """

    def __init__(
        self,
        agent_registry: AgentRegistry,
        sandbox: SandboxManager,
    ) -> None:
        self._registry = agent_registry
        self._sandbox = sandbox
        self._deconfliction = DeconflictionEngine()
        self._log = structlog.get_logger("tdt.orchestrator.battle_manager")

    # ── Public API ────────────────────────────────────────────────────────

    @property
    def deconfliction(self) -> DeconflictionEngine:
        """Accès à l'engine de déconfliction (lecture)."""
        return self._deconfliction

    async def execute_plan(self, plan: MissionPlan) -> BattleReport:
        """Exécute toutes les phases d'un MissionPlan.

        Processus:
        1. Initialise la state machine pour chaque phase
        2. Pour chaque phase prête (dépendances satisfaites):
           - Récupère l'agent via AgentRegistry
           - Injecte la personnalité appropriée
           - Lance l'exécution
           - Surveille le statut
        3. Gère les erreurs et les retries
        4. Met à jour le statut du plan

        Args:
            plan: Le plan de mission à exécuter.

        Returns:
            BattleReport complet avec résultats de toutes les phases.
        """
        start = time.monotonic()
        mission_id = f"mission-{int(start)}"
        self._log.info(
            "battle_started",
            mission_id=mission_id,
            phases=len(plan.phases),
            objective=plan.objective[:80],
        )

        # 1. Initialiser la state machine
        phase_states: dict[str, PhaseStatus] = {p.name: PhaseStatus.PENDING for p in plan.phases}
        phase_results: dict[str, PhaseResult] = {}
        conflicts: list[ConflictReport] = []
        recovery_actions: list[RecoveryAction] = []

        phase_map = {p.name: p for p in plan.phases}
        completed: set[str] = set()
        remaining = list(plan.phases)

        while remaining:
            # Phases dont les dépendances sont satisfaites
            ready = [p for p in remaining if self._check_dependencies(p, phase_results)]

            if not ready:
                # Deadlock: aucune phase n'est prête
                self._log.warning("dependency_deadlock", remaining=[p.name for p in remaining])
                for p in remaining:
                    phase_results[p.name] = PhaseResult(
                        phase_id=p.name,
                        agent_name=p.agent_name,
                        status=PhaseStatus.SKIPPED,
                        output=f"Deadlock: dependencies {p.depends_on} never satisfied",
                        duration_ms=(time.monotonic() - start) * 1000,
                    )
                    phase_states[p.name] = PhaseStatus.SKIPPED
                    completed.add(p.name)
                break

            for p in ready:
                remaining.remove(p)

            # Vérifier les conflits avant exécution
            deconflicted: list[MissionPhase] = []
            for p in ready:
                conflict_ok = True
                for other in ready:
                    if p.name == other.name:
                        continue
                    # Conflit si deux phases visent la même cible
                    conflict = self._deconfliction.check_conflict(
                        p.agent_name, other.agent_name, p.objective
                    )
                    if conflict.conflict_type != "none" and conflict.severity != "none":
                        conflicts.append(conflict)
                        action = self._deconfliction.resolve_conflict(conflict)
                        if action in (ResolutionAction.ABORT, ResolutionAction.FORCE):
                            recovery_actions.append(RecoveryAction.SKIP)
                            phase_results[p.name] = PhaseResult(
                                phase_id=p.name,
                                agent_name=p.agent_name,
                                status=PhaseStatus.SKIPPED,
                                output=(
                                    f"Blocked by conflict with {other.agent_name} on {p.objective}"
                                ),
                                duration_ms=(time.monotonic() - start) * 1000,
                            )
                            phase_states[p.name] = PhaseStatus.SKIPPED
                            completed.add(p.name)
                            conflict_ok = False
                            break
                        elif action == ResolutionAction.REDIRECT:
                            # Rediriger = locker et continuer
                            self._deconfliction._target_lock(p.objective, p.agent_name)
                            deconflicted.append(p)
                        elif action == ResolutionAction.WAIT:
                            # WAIT = ne pas exécuter maintenant (rester dans remaining)
                            conflict_ok = False
                            break
                        elif action == ResolutionAction.QUEUE:
                            deconflicted.append(p)

                if conflict_ok:
                    deconflicted.append(p)

            # Exécuter les phases déconflicted
            if deconflicted:
                results = await self._execute_parallel(deconflicted)
                for r in results:
                    phase_results[r.phase_id] = r
                    phase_states[r.phase_id] = r.status
                    completed.add(r.phase_id)
                    if r.status == PhaseStatus.FAILED:
                        recovery = self._handle_phase_failure(
                            phase_map[r.phase_id],
                            Exception(r.error) if r.error else RuntimeError("phase_failed"),
                        )
                        recovery_actions.append(recovery)
            else:
                # Deadlock dans la déconfliction
                self._log.warning("deconfliction_deadlock")
                break

        total_duration = (time.monotonic() - start) * 1000
        phases_total = len(plan.phases)
        phases_completed = sum(
            1 for r in phase_results.values() if r.status == PhaseStatus.COMPLETED
        )
        phases_failed = sum(1 for r in phase_results.values() if r.status == PhaseStatus.FAILED)

        report = BattleReport(
            mission_id=mission_id,
            phases_total=phases_total,
            phases_completed=phases_completed,
            phases_failed=phases_failed,
            phase_results=list(phase_results.values()),
            conflicts=conflicts,
            total_duration_ms=total_duration,
            success=phases_failed == 0 and phases_completed > 0,
            recovery_actions=recovery_actions,
        )

        self._log.info(
            "battle_completed",
            mission_id=mission_id,
            success=report.success,
            completed=f"{phases_completed}/{phases_total}",
            failed=phases_failed,
            duration_ms=round(total_duration, 1),
        )
        return report

    async def execute_phase(
        self,
        phase: MissionPhase,
        agent: BaseAgent,
    ) -> PhaseResult:
        """Exécute une phase individuelle via un agent.

        State machine: PENDING → IN_PROGRESS → COMPLETED | FAILED

        Args:
            phase: La phase à exécuter.
            agent: L'agent à utiliser.

        Returns:
            PhaseResult avec le statut final.
        """
        start = time.monotonic()
        self._log.info(
            "phase_started",
            phase=phase.name,
            agent=agent.name,
            persona=agent.personality_mode,
        )

        # Lock la cible
        self._deconfliction._target_lock(phase.objective, agent.name)

        try:
            result = await agent.execute(
                objective=phase.objective,
                context={
                    "phase": phase.name,
                    "phase_num": phase.phase_number,
                    "plan_objective": getattr(phase, "parent_objective", None),
                },
            )

            duration_ms = (time.monotonic() - start) * 1000
            status = PhaseStatus.COMPLETED if result.success else PhaseStatus.FAILED

            phase_result = PhaseResult(
                phase_id=phase.name,
                agent_name=agent.name,
                status=status,
                output=result.output,
                artifacts=[s.tool for s in result.steps if s.tool],
                duration_ms=duration_ms,
                error=None if result.success else result.output,
            )

            self._log.info(
                "phase_completed",
                phase=phase.name,
                status=status.value,
                duration_ms=round(duration_ms, 1),
            )
            return phase_result

        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000
            self._log.error(
                "phase_crashed",
                phase=phase.name,
                agent=agent.name,
                error=str(exc),
            )
            return PhaseResult(
                phase_id=phase.name,
                agent_name=agent.name,
                status=PhaseStatus.FAILED,
                output="",
                duration_ms=duration_ms,
                error=str(exc),
            )

        finally:
            self._deconfliction._target_unlock(phase.objective, agent.name)

    async def coordinate(
        self,
        active_phases: list[MissionPhase],
    ) -> list[PhaseResult]:
        """Coordonne l'exécution d'une liste de phases actives.

        Vérifie les conflits entre phases, applique la déconfliction,
        et exécute les phases non-confligées en parallèle.

        Args:
            active_phases: Phases à coordonner (déjà prêtes).

        Returns:
            Résultats des phases exécutées (confligées = ignorées).
        """
        # Filtrer par dépendances
        completed: dict[str, PhaseResult] = {}
        executables = [p for p in active_phases if self._check_dependencies(p, completed)]

        if not executables:
            return []

        # Déconfliction
        deconflicted: list[MissionPhase] = []
        for phase in executables:
            conflict = False
            for other in executables:
                if phase.name == other.name:
                    continue
                report = self._deconfliction.check_conflict(
                    phase.agent_name, other.agent_name, phase.objective
                )
                if report.conflict_type != "none":
                    action = self._deconfliction.resolve_conflict(report)
                    if action in (ResolutionAction.ABORT, ResolutionAction.WAIT):
                        conflict = True
                        break
            if not conflict:
                deconflicted.append(phase)

        # Exécution parallèle
        return await self._execute_parallel(deconflicted)

    # ── Internal ──────────────────────────────────────────────────────────

    def _check_dependencies(
        self,
        phase: MissionPhase,
        completed: dict[str, PhaseResult],
    ) -> bool:
        """Vérifie si toutes les dépendances d'une phase sont satisfaites.

        Une phase est prête si toutes ses phases dépendantes
        sont complétées avec succès (ou skipped).
        """
        if not phase.depends_on:
            return True

        for dep in phase.depends_on:
            result = completed.get(dep)
            if result is None:
                return False
            if result.status not in (PhaseStatus.COMPLETED, PhaseStatus.SKIPPED):
                return False

        return True

    def _handle_phase_failure(
        self,
        phase: MissionPhase,
        error: Exception,
    ) -> RecoveryAction:
        """Décide de l'action de recovery après l'échec d'une phase.

        Heuristique simple basée sur le type d'erreur.
        """
        error_str = str(error).lower()

        # Timeout → retry
        if "timeout" in error_str:
            self._log.info("recovery_retry", phase=phase.name)
            return RecoveryAction.RETRY

        # Sandbox/docker error → escalate
        if "sandbox" in error_str or "docker" in error_str:
            self._log.warning("recovery_escalate", phase=phase.name)
            return RecoveryAction.ESCALATE

        # Permission/infrastructure → skip
        if "permission" in error_str or "denied" in error_str:
            self._log.info("recovery_skip", phase=phase.name)
            return RecoveryAction.SKIP

        # Par défaut → escalate (safe side)
        self._log.warning("recovery_default_escalate", phase=phase.name, error=error_str[:80])
        return RecoveryAction.ESCALATE

    async def _execute_parallel(
        self,
        phases: list[MissionPhase],
    ) -> list[PhaseResult]:
        """Exécute plusieurs phases en parallèle via asyncio.gather.

        Chaque phase est exécutée via l'agent correspondant du registry.

        Args:
            phases: Phases à exécuter en parallèle.

        Returns:
            Résultats dans le même ordre que les phases d'entrée.
        """
        if not phases:
            return []

        async def _run(phase: MissionPhase) -> PhaseResult:
            agent = self._registry.get(phase.agent_name)
            if agent is None:
                self._log.error(
                    "agent_not_found",
                    agent=phase.agent_name,
                    phase=phase.name,
                )
                return PhaseResult(
                    phase_id=phase.name,
                    agent_name=phase.agent_name,
                    status=PhaseStatus.SKIPPED,
                    output=f"Agent '{phase.agent_name}' not found in registry",
                    error=f"AgentNotFound: {phase.agent_name}",
                )
            return await self.execute_phase(phase, agent)

        tasks = [asyncio.create_task(_run(p)) for p in phases]
        return await asyncio.gather(*tasks)
