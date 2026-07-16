"""Engagement Package Generator — Rules of Engagement, ConOps, OPPLAN.

Produces structured red‑team engagement documents driven by the AI Router
for content generation, with static fallback templates for offline/test use.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from decepticon.navmax.darktriad.agents.base import AgentResult, AgentStep
from decepticon.navmax.darktriad.agents.registry import AgentRegistry
from decepticon.navmax.darktriad.core.ai_router import AIRouter, ModelTier
from decepticon.navmax.darktriad.orchestrator.shared import MissionPhase, MissionPlan

logger = structlog.get_logger(__name__)

# ── Engagement Dataclasses ────────────────────────────────────────────────────


@dataclass
class OPPhase:
    """A phase within an Operations Plan (OPPLAN)."""

    phase_number: int
    name: str
    objective: str
    techniques: list[str] = field(default_factory=list)  # MITRE ATT&CK IDs
    agents_assigned: list[str] = field(default_factory=list)
    estimated_duration: str = "TBD"
    success_indicators: list[str] = field(default_factory=list)
    fallback: str = ""


@dataclass
class OperationsPlan:
    """Detailed Operations Plan (OPPLAN)."""

    engagement_id: str
    objective: str
    phases: list[OPPhase] = field(default_factory=list)
    mitre_mapping: dict[str, list[str]] = field(default_factory=dict)
    resources_required: list[str] = field(default_factory=list)
    timeline: dict[str, str] = field(default_factory=dict)
    contingency_plans: list[str] = field(default_factory=list)


@dataclass
class ConceptOfOperations:
    """Concept of Operations (ConOps) document."""

    engagement_id: str
    objective: str
    overview: str = ""
    phases_summary: list[str] = field(default_factory=list)
    key_assets: list[str] = field(default_factory=list)
    threat_model: str = ""
    success_criteria: list[str] = field(default_factory=list)
    exit_criteria: list[str] = field(default_factory=list)
    communication_plan: str = ""
    reporting_frequency: str = "daily"


@dataclass
class RulesOfEngagement:
    """Rules of Engagement (RoE) document."""

    engagement_id: str
    version: str = "1.0"
    authorized_targets: list[str] = field(default_factory=list)
    excluded_targets: list[str] = field(default_factory=list)
    authorized_techniques: list[str] = field(default_factory=list)
    prohibited_techniques: list[str] = field(default_factory=list)
    time_window: dict[str, str] = field(default_factory=dict)
    allowed_hours: list[str] = field(default_factory=list)
    data_handling: str = ""
    deconfliction_procedure: str = ""
    emergency_stop_procedure: str = ""
    points_of_contact: list[str] = field(default_factory=list)
    risk_acceptance: str = ""
    legal_basis: str = ""


@dataclass
class EngagementPackage:
    """Complete engagement package combining RoE, ConOps, and OPPLAN."""

    engagement_id: str
    objective: str
    personality: str
    roe: RulesOfEngagement
    conops: ConceptOfOperations
    opplan: OperationsPlan
    created_at: str = ""
    status: str = "draft"

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(UTC).isoformat()


# ── Conflict Detection ────────────────────────────────────────────────────────


@dataclass
class Conflict:
    """A detected conflict between phases or agents."""

    type: str  # e.g. "resource", "dependency", "timing"
    description: str
    phase_names: list[str] = field(default_factory=list)
    severity: str = "medium"  # low, medium, high, critical
    resolution: str | None = None


@dataclass
class ConflictResolution:
    """Resolution for a detected conflict."""

    conflict_type: str
    resolution: str
    adjusted_phases: list[str] = field(default_factory=list)
    notes: str = ""


# ── Template helpers ──────────────────────────────────────────────────────────

_MITRE_MAP: dict[str, list[str]] = {
    "passive_recon": ["T1590", "T1592", "T1595"],
    "active_scan": ["T1046", "T1595"],
    "vulnerability_analysis": ["T1580", "T1068"],
    "exploit_selection": ["T1210", "T1204"],
    "exploit_execution": ["T1203", "T1190"],
    "post_exploit_verify": ["T1082", "T1057"],
    "full_assault": ["T1190", "T1210", "T1203", "T1059"],
    "lateral_movement": ["T1021", "T1550", "T1570"],
    "privilege_escalation": ["T1068", "T1055", "T1548"],
    "persistence": ["T1098", "T1136", "T1505"],
    "defense_evasion": ["T1070", "T1562", "T1027"],
    "credential_access": ["T1003", "T1555", "T1056"],
    "discovery": ["T1082", "T1083", "T1046"],
    "collection": ["T1005", "T1074", "T1119"],
    "command_and_control": ["T1071", "T1573", "T1090"],
    "exfiltration": ["T1041", "T1567", "T1029"],
    "impact": ["T1485", "T1490", "T1486"],
}

_DEFAULT_ROE_TEMPLATE: dict[str, Any] = {
    "authorized_targets": [],
    "excluded_targets": [],
    "authorized_techniques": [
        "T1590",
        "T1592",
        "T1595",
        "T1046",
        "T1580",
        "T1210",
        "T1203",
        "T1190",
        "T1059",
    ],
    "prohibited_techniques": [
        "T1485",
        "T1490",
        "T1486",
        "T1561",
    ],
    "time_window": {"start": "2025-01-01T00:00:00Z", "end": "2025-01-14T23:59:59Z"},
    "allowed_hours": ["09:00-17:00"],
    "data_handling": "All data must be encrypted at rest and in transit. No exfiltration without explicit approval.",
    "deconfliction_procedure": "Check-in every 4 hours. Green = active, Yellow = caution, Red = stop immediate.",
    "emergency_stop_procedure": "Send STOP signal via out-of-band channel. All operations cease within 60 seconds.",
    "points_of_contact": ["red_team_lead@example.com", "blue_team_poc@example.com"],
    "risk_acceptance": "Signed by CISO. Maximum acceptable impact: denial of service on non-critical systems.",
    "legal_basis": "Authorized penetration test under written agreement with asset owner.",
}

_DEFAULT_CONOPS_TEMPLATE: dict[str, Any] = {
    "overview": "Simulated adversarial operation to assess detection and response capabilities.",
    "key_assets": ["domain_controllers", "file_servers", "web_applications"],
    "threat_model": "Advanced Persistent Threat (APT) with initial access via spearphishing.",
    "success_criteria": [
        "C2 beacon established",
        "Lateral movement to crown jewels",
        "Data exfiltration detected",
    ],
    "exit_criteria": [
        "All implants removed",
        "Persistence mechanisms cleaned",
        "No forensic traces left",
    ],
    "communication_plan": "Secure out-of-band channel. Daily sync at 0900 UTC.",
    "reporting_frequency": "daily",
}


# ── EngagementBuilder ─────────────────────────────────────────────────────────


class EngagementBuilder:
    """Generates a complete engagement package (RoE + ConOps + OPPLAN).

    Uses the AI Router for content generation with static fallback so it
    works both online and offline (e.g. test suites).
    """

    def __init__(self, ai_router: AIRouter) -> None:
        self.ai_router = ai_router
        self._log = logger.bind(component="EngagementBuilder")

    async def build(
        self,
        objective: str,
        scope: dict[str, Any],
        personality: str,
    ) -> EngagementPackage:
        """Build a complete engagement package for *objective*.

        Args:
            objective: High-level red-team objective.
            scope: Operational scope dict (targets, constraints, timeline…).
            personality: Personality mode string.

        Returns:
            A fully populated :class:`EngagementPackage`.
        """
        engagement_id = f"TDT-{uuid.uuid4().hex[:8].upper()}"
        constraints = scope.get("constraints", {})

        roe = await self.generate_roe(scope, constraints)
        roe.engagement_id = engagement_id

        # Build a plan from the objective / personality
        plan = MissionPlan(
            objective=objective,
            phases=self._default_phases_for_personality(personality, objective),
            estimated_duration=30,
            risk_level=0.5,
            created_at=datetime.now(UTC).isoformat(),
        )

        conops = await self.generate_conops(objective, plan)
        conops.engagement_id = engagement_id

        opplan = await self.generate_opplan(objective, plan.phases)
        opplan.engagement_id = engagement_id

        return EngagementPackage(
            engagement_id=engagement_id,
            objective=objective,
            personality=personality,
            roe=roe,
            conops=conops,
            opplan=opplan,
            status="draft",
        )

    async def generate_roe(
        self,
        scope: dict[str, Any],
        constraints: dict[str, Any],
    ) -> RulesOfEngagement:
        """Generate a Rules of Engagement document."""
        targets = scope.get("targets", [])
        try:
            result = await self.ai_router.generate(
                prompt=(
                    f"Generate Rules of Engagement for a red team assessment.\n"
                    f"Targets: {targets}\n"
                    f"Constraints: {json.dumps(constraints)}\n\n"
                    f"Return a JSON object with the following keys:\n"
                    f"authorized_targets, excluded_targets, authorized_techniques, "
                    f"prohibited_techniques, time_window, allowed_hours, data_handling, "
                    f"deconfliction_procedure, emergency_stop_procedure, points_of_contact, "
                    f"risk_acceptance, legal_basis"
                ),
                tier=ModelTier.LIGHT,
                json_mode=True,
            )
            data = json.loads(result.text)
        except Exception:
            self._log.warning("roe_ai_fallback", exc_info=True)
            data = dict(_DEFAULT_ROE_TEMPLATE)

        data.setdefault("authorized_targets", targets)
        # Merge excluded targets from constraints (overrides AI result)
        excluded = constraints.get("excluded", [])
        if excluded:
            data["excluded_targets"] = excluded
        data.setdefault("excluded_targets", [])
        data.setdefault("authorized_techniques", _DEFAULT_ROE_TEMPLATE["authorized_techniques"])
        data.setdefault("prohibited_techniques", _DEFAULT_ROE_TEMPLATE["prohibited_techniques"])
        data.setdefault("time_window", _DEFAULT_ROE_TEMPLATE["time_window"])
        data.setdefault("allowed_hours", _DEFAULT_ROE_TEMPLATE["allowed_hours"])
        data.setdefault("data_handling", _DEFAULT_ROE_TEMPLATE["data_handling"])
        data.setdefault("deconfliction_procedure", _DEFAULT_ROE_TEMPLATE["deconfliction_procedure"])
        data.setdefault(
            "emergency_stop_procedure", _DEFAULT_ROE_TEMPLATE["emergency_stop_procedure"]
        )
        data.setdefault("points_of_contact", _DEFAULT_ROE_TEMPLATE["points_of_contact"])
        data.setdefault("risk_acceptance", _DEFAULT_ROE_TEMPLATE["risk_acceptance"])
        data.setdefault("legal_basis", _DEFAULT_ROE_TEMPLATE["legal_basis"])

        return RulesOfEngagement(
            engagement_id="",
            version="1.0",
            authorized_targets=data["authorized_targets"],
            excluded_targets=data["excluded_targets"],
            authorized_techniques=data["authorized_techniques"],
            prohibited_techniques=data["prohibited_techniques"],
            time_window=data["time_window"],
            allowed_hours=data["allowed_hours"],
            data_handling=data["data_handling"],
            deconfliction_procedure=data["deconfliction_procedure"],
            emergency_stop_procedure=data["emergency_stop_procedure"],
            points_of_contact=data["points_of_contact"],
            risk_acceptance=data["risk_acceptance"],
            legal_basis=data["legal_basis"],
        )

    async def generate_conops(
        self,
        objective: str,
        plan: MissionPlan,
    ) -> ConceptOfOperations:
        """Generate a Concept of Operations document."""
        phase_names = [p.name for p in plan.phases]
        try:
            result = await self.ai_router.generate(
                prompt=(
                    f"Generate Concept of Operations for red team mission.\n"
                    f"Objective: {objective}\n"
                    f"Phases: {phase_names}\n"
                    f"Risk level: {plan.risk_level}\n\n"
                    f"Return a JSON object with keys:\n"
                    f"overview, phases_summary, key_assets, threat_model, "
                    f"success_criteria, exit_criteria, communication_plan, "
                    f"reporting_frequency"
                ),
                tier=ModelTier.LIGHT,
                json_mode=True,
            )
            data = json.loads(result.text)
        except Exception:
            self._log.warning("conops_ai_fallback", exc_info=True)
            data = dict(_DEFAULT_CONOPS_TEMPLATE)

        data.setdefault("overview", _DEFAULT_CONOPS_TEMPLATE["overview"])
        data["phases_summary"] = phase_names  # Always use actual plan phases
        data.setdefault("key_assets", _DEFAULT_CONOPS_TEMPLATE["key_assets"])
        data.setdefault("threat_model", _DEFAULT_CONOPS_TEMPLATE["threat_model"])
        data.setdefault("success_criteria", _DEFAULT_CONOPS_TEMPLATE["success_criteria"])
        data.setdefault("exit_criteria", _DEFAULT_CONOPS_TEMPLATE["exit_criteria"])
        data.setdefault("communication_plan", _DEFAULT_CONOPS_TEMPLATE["communication_plan"])
        data.setdefault("reporting_frequency", _DEFAULT_CONOPS_TEMPLATE["reporting_frequency"])

        return ConceptOfOperations(
            engagement_id="",
            objective=objective,
            overview=data["overview"],
            phases_summary=data["phases_summary"],
            key_assets=data["key_assets"],
            threat_model=data["threat_model"],
            success_criteria=data["success_criteria"],
            exit_criteria=data["exit_criteria"],
            communication_plan=data["communication_plan"],
            reporting_frequency=data["reporting_frequency"],
        )

    async def generate_opplan(
        self,
        objective: str,
        phases: list[MissionPhase],
    ) -> OperationsPlan:
        """Generate an Operations Plan from mission phases."""
        opp_phases = []
        for i, mp in enumerate(phases):
            technique_ids = _MITRE_MAP.get(mp.name, [f"T{1000 + i}"])
            opp_phases.append(
                OPPhase(
                    phase_number=mp.phase_number,
                    name=mp.name,
                    objective=mp.objective,
                    techniques=technique_ids,
                    agents_assigned=[mp.agent_name] if mp.agent_name else [],
                    estimated_duration="TBD",
                    success_indicators=[f"{mp.name}_completed"],
                    fallback=f"Skip {mp.name} and proceed to next phase",
                )
            )

        mitre_mapping = await self.map_to_mitre(phases)
        timeline = {p.name: "TBD" for p in phases}

        return OperationsPlan(
            engagement_id="",
            objective=objective,
            phases=opp_phases,
            mitre_mapping=mitre_mapping,
            resources_required=["C2 infrastructure", "Phishing platform", "Scanning tools"],
            timeline=timeline,
            contingency_plans=[f"Phase {p.name} failure: {p.fallback}" for p in opp_phases],
        )

    async def map_to_mitre(
        self,
        phases: list[MissionPhase],
    ) -> dict[str, list[str]]:
        """Map mission phases to MITRE ATT&CK techniques.

        Returns:
            Dict mapping phase names to lists of MITRE technique IDs.
        """
        mapping: dict[str, list[str]] = {}
        for p in phases:
            if p.name in _MITRE_MAP:
                mapping[p.name] = list(_MITRE_MAP[p.name])
            else:
                mapping[p.name] = [f"T{1000 + p.phase_number}"]
        return mapping

    # ── Internal helpers ──────────────────────────────────────────────────

    def _default_phases_for_personality(
        self,
        personality: str,
        objective: str,
    ) -> list[MissionPhase]:
        persona = personality.strip().lower()
        if persona == "narcissism":
            return [
                MissionPhase(
                    phase_number=1,
                    name="full_assault",
                    agent_name="narcissus",
                    objective=objective,
                    depends_on=[],
                ),
            ]
        elif persona == "psychopathy":
            return [
                MissionPhase(
                    phase_number=1,
                    name="active_scan",
                    agent_name="psychopath",
                    objective=f"Scan {objective}",
                    depends_on=[],
                ),
                MissionPhase(
                    phase_number=2,
                    name="exploit_execution",
                    agent_name="psychopath",
                    objective=f"Exploit {objective}",
                    depends_on=[],
                ),
                MissionPhase(
                    phase_number=3,
                    name="post_exploit_verify",
                    agent_name="psychopath",
                    objective=f"Verify {objective}",
                    depends_on=["exploit_execution"],
                ),
            ]
        else:
            return [
                MissionPhase(
                    phase_number=1,
                    name="passive_recon",
                    agent_name="machiavelli",
                    objective=f"Recon {objective}",
                    depends_on=[],
                ),
                MissionPhase(
                    phase_number=2,
                    name="active_scan",
                    agent_name="machiavelli",
                    objective=f"Scan {objective}",
                    depends_on=["passive_recon"],
                ),
                MissionPhase(
                    phase_number=3,
                    name="vulnerability_analysis",
                    agent_name="machiavelli",
                    objective=f"Analyze {objective}",
                    depends_on=["active_scan"],
                ),
                MissionPhase(
                    phase_number=4,
                    name="exploit_selection",
                    agent_name="machiavelli",
                    objective=f"Select exploit for {objective}",
                    depends_on=["vulnerability_analysis"],
                ),
                MissionPhase(
                    phase_number=5,
                    name="exploit_execution",
                    agent_name="machiavelli",
                    objective=f"Execute {objective}",
                    depends_on=["exploit_selection"],
                ),
            ]

    def _estimate_duration(self, personality: str) -> str:
        durations = {
            "narcissism": "<30s",
            "psychopathy": "<2min",
            "machiavellianism": "5-15min",
        }
        return durations.get(personality.strip().lower(), "TBD")

    def _estimate_risk(self, personality: str) -> str:
        risks = {
            "narcissism": "high",
            "psychopathy": "critical",
            "machiavellianism": "low",
        }
        return risks.get(personality.strip().lower(), "medium")


# ── MissionPlanner ────────────────────────────────────────────────────────────


class MissionPlanner:
    """Decomposes an objective into a personality-tailored mission plan.

    Wraps and extends OrchestratorAgent plan logic for standalone use.
    """

    def __init__(self, registry: AgentRegistry) -> None:
        self.registry = registry
        self._log = logger.bind(component="MissionPlanner")

    async def plan(
        self,
        objective: str,
        personality: str,
        context: dict[str, Any] | None = None,
    ) -> MissionPlan:
        """Decompose *objective* into a :class:`MissionPlan`.

        Args:
            objective: High-level objective.
            personality: One of ``narcissism|psychopathy|machiavellianism``.
            context: Optional execution context.

        Returns:
            A :class:`MissionPlan` with phases, duration, and risk.
        """
        phases = await self.decompose(objective, personality)
        assigned = await self.assign_agents(phases, personality)
        return MissionPlan(
            objective=objective,
            phases=assigned,
            estimated_duration=300,
            risk_level=0.5,
        )

    async def decompose(
        self,
        objective: str,
        personality: str,
    ) -> list[MissionPhase]:
        """Decompose objective into raw phases (agents unassigned)."""
        persona = personality.strip().lower()

        if persona == "narcissism":
            return [
                MissionPhase(
                    phase_number=1,
                    name="full_assault",
                    agent_name="",
                    objective=objective,
                    depends_on=[],
                ),
            ]
        elif persona == "psychopathy":
            return [
                MissionPhase(
                    phase_number=1,
                    name="active_scan",
                    agent_name="",
                    objective=f"Active scan of {objective}",
                    depends_on=[],
                ),
                MissionPhase(
                    phase_number=2,
                    name="vulnerability_analysis",
                    agent_name="",
                    objective=f"Vulnerability scan of {objective}",
                    depends_on=[],
                ),
                MissionPhase(
                    phase_number=3,
                    name="exploit_execution",
                    agent_name="",
                    objective=f"Rapid exploitation of {objective}",
                    depends_on=[],
                ),
                MissionPhase(
                    phase_number=4,
                    name="lateral_movement",
                    agent_name="",
                    objective=f"Pivot from {objective}",
                    depends_on=[],
                ),
            ]
        else:
            return [
                MissionPhase(
                    phase_number=1,
                    name="passive_recon",
                    agent_name="",
                    objective=f"Passive reconnaissance on {objective}",
                    depends_on=[],
                ),
                MissionPhase(
                    phase_number=2,
                    name="active_scan",
                    agent_name="",
                    objective=f"Active scanning of {objective}",
                    depends_on=["passive_recon"],
                ),
                MissionPhase(
                    phase_number=3,
                    name="vulnerability_analysis",
                    agent_name="",
                    objective=f"Vulnerability assessment of {objective}",
                    depends_on=["active_scan"],
                ),
                MissionPhase(
                    phase_number=4,
                    name="exploit_selection",
                    agent_name="",
                    objective=f"Select appropriate exploit for {objective}",
                    depends_on=["vulnerability_analysis"],
                ),
                MissionPhase(
                    phase_number=5,
                    name="exploit_execution",
                    agent_name="",
                    objective=f"Execute selected exploit against {objective}",
                    depends_on=["exploit_selection"],
                ),
                MissionPhase(
                    phase_number=6,
                    name="post_exploit_verify",
                    agent_name="",
                    objective=f"Verify access on {objective}",
                    depends_on=["exploit_execution"],
                ),
            ]

    async def assign_agents(
        self,
        phases: list[MissionPhase],
        personality: str,
    ) -> list[MissionPhase]:
        """Assign agent categories to phases based on phase name and personality."""
        agent_map: dict[str, str] = {
            "passive_recon": "recon",
            "active_scan": "recon",
            "vulnerability_analysis": "recon",
            "exploit_selection": "exploit",
            "exploit_execution": "exploit",
            "post_exploit_verify": "exploit",
            "full_assault": "narcissus",
            "lateral_movement": "lateral",
            "privilege_escalation": "privesc",
            "persistence": "persistence",
            "defense_evasion": "evasion",
            "credential_access": "credential",
            "discovery": "recon",
            "collection": "exfil",
            "command_and_control": "c2",
            "exfiltration": "exfil",
            "impact": "exploit",
        }

        assigned: list[MissionPhase] = []
        for p in phases:
            agent = agent_map.get(p.name, "general")
            if personality.strip().lower() == "narcissism":
                agent = "narcissus"
            assigned.append(
                MissionPhase(
                    phase_number=p.phase_number,
                    name=p.name,
                    agent_name=agent,
                    objective=p.objective,
                    depends_on=list(p.depends_on),
                )
            )
        return assigned

    def _estimate_duration(self, personality: str) -> str:
        d = {"narcissism": "<30s", "psychopathy": "<2min", "machiavellianism": "5-15min"}
        return d.get(personality.strip().lower(), "TBD")

    def _estimate_risk(self, personality: str) -> str:
        r = {"narcissism": "high", "psychopathy": "critical", "machiavellianism": "low"}
        return r.get(personality.strip().lower(), "medium")


# ── BattleManager ─────────────────────────────────────────────────────────────


class BattleManager:
    """Executes mission plans by dispatching phases to agents.

    Manages state transitions and aggregates phase results.
    """

    def __init__(self, registry: AgentRegistry) -> None:
        self.registry = registry
        self._state: dict[str, str] = {}  # phase_name -> state
        self._log = logger.bind(component="BattleManager")

    async def execute_plan(
        self,
        plan: MissionPlan,
        personality: str = "machiavellianism",
    ) -> dict[str, AgentResult]:
        """Execute all phases of a mission plan.

        Args:
            plan: The mission plan to execute.
            personality: Driving personality mode.

        Returns:
            Dict mapping phase names to their results.
        """
        self._state.clear()
        results: dict[str, AgentResult] = {}

        for phase in plan.phases:
            self._state[phase.name] = "PENDING"

        for phase in plan.phases:
            self._state[phase.name] = "IN_PROGRESS"
            result = await self.execute_phase(phase, personality)
            results[phase.name] = result
            self._state[phase.name] = "COMPLETED" if result.success else "FAILED"

        return results

    async def execute_phase(
        self,
        phase: MissionPhase,
        personality: str = "machiavellianism",
    ) -> AgentResult:
        """Execute a single phase by dispatching to the appropriate agent.

        Args:
            phase: The phase to execute.
            personality: Personality mode.

        Returns:
            Agent execution result.
        """
        agent = self.registry.get(phase.agent_name)
        if agent is None:
            return AgentResult(
                agent_name=phase.agent_name,
                personality=personality,
                objective=phase.objective,
                success=False,
                output=f"Agent '{phase.agent_name}' not found in registry",
                steps=[
                    AgentStep(
                        step_number=1,
                        action="dispatch",
                        tool=phase.agent_name,
                        result="Agent unavailable",
                    ),
                ],
                duration_ms=0.0,
            )

        try:
            result = await agent.execute(
                phase.objective, {"phase": phase.name, "personality": personality}
            )
            return result
        except Exception as exc:
            return AgentResult(
                agent_name=phase.agent_name,
                personality=personality,
                objective=phase.objective,
                success=False,
                output=f"Phase execution failed: {exc}",
                steps=[],
                duration_ms=0.0,
            )

    def get_state(self, phase_name: str) -> str | None:
        """Get the current state of a phase."""
        return self._state.get(phase_name)

    def get_all_states(self) -> dict[str, str]:
        """Get states for all phases."""
        return dict(self._state)


# ── DeconflictionEngine ───────────────────────────────────────────────────────


class DeconflictionEngine:
    """Detects and resolves conflicts between mission phases.

    Checks for circular dependencies, resource contention, and
    dependency ordering violations.
    """

    def __init__(self) -> None:
        self._log = logger.bind(component="DeconflictionEngine")

    async def check_conflict(self, phases: list[MissionPhase]) -> list[Conflict]:
        """Scan phases for potential conflicts.

        Args:
            phases: List of mission phases to check.

        Returns:
            List of detected conflicts (empty if none found).
        """
        conflicts: list[Conflict] = []

        # Check for circular dependencies
        circular = self._find_circular_dependencies(phases)
        for cycle in circular:
            conflicts.append(
                Conflict(
                    type="circular_dependency",
                    description=f"Circular dependency detected: {' → '.join(cycle)}",
                    phase_names=cycle,
                    severity="critical",
                )
            )

        # Check for missing dependency targets
        phase_names = {p.name for p in phases}
        for p in phases:
            for dep in p.depends_on:
                if dep not in phase_names:
                    conflicts.append(
                        Conflict(
                            type="missing_dependency",
                            description=f"Phase '{p.name}' depends on '{dep}' which does not exist",
                            phase_names=[p.name, dep],
                            severity="high",
                        )
                    )

        # Check for duplicate phase numbers
        seen_numbers: set[int] = set()
        for p in phases:
            if p.phase_number in seen_numbers:
                conflicts.append(
                    Conflict(
                        type="duplicate_phase_number",
                        description=f"Duplicate phase number {p.phase_number}",
                        phase_names=[p.name],
                        severity="low",
                    )
                )
            seen_numbers.add(p.phase_number)

        return conflicts

    async def resolve_conflict(self, conflict: Conflict) -> ConflictResolution:
        """Resolve a single conflict.

        Args:
            conflict: The conflict to resolve.

        Returns:
            A :class:`ConflictResolution` describing how to resolve.
        """
        if conflict.type == "circular_dependency":
            # Break the cycle by removing the last dependency
            resolution = ConflictResolution(
                conflict_type="circular_dependency",
                resolution="Remove circular dependency edges",
                adjusted_phases=conflict.phase_names,
                notes=f"Broken cycle involving phases: {', '.join(conflict.phase_names)}",
            )
        elif conflict.type == "missing_dependency":
            resolution = ConflictResolution(
                conflict_type="missing_dependency",
                resolution="Add missing phase or remove dependency reference",
                adjusted_phases=[conflict.phase_names[0]] if conflict.phase_names else [],
                notes=f"Phase '{conflict.phase_names[0] if conflict.phase_names else '?'}' "
                f"references non-existent dependency. Remove dependency or create phase.",
            )
        elif conflict.type == "duplicate_phase_number":
            resolution = ConflictResolution(
                conflict_type="duplicate_phase_number",
                resolution="Renumber phases sequentially",
                adjusted_phases=conflict.phase_names,
                notes="Reassign phase numbers to be unique and sequential.",
            )
        else:
            resolution = ConflictResolution(
                conflict_type=conflict.type,
                resolution="Manual review required",
                adjusted_phases=conflict.phase_names,
                notes="No automatic resolution available for this conflict type.",
            )

        return resolution

    def _find_circular_dependencies(
        self,
        phases: list[MissionPhase],
    ) -> list[list[str]]:
        """Detect circular dependency chains using DFS."""
        adj: dict[str, list[str]] = {p.name: list(p.depends_on) for p in phases}
        cycles: list[list[str]] = []
        visited: set[str] = set()
        rec_stack: set[str] = set()
        path: list[str] = []

        def dfs(node: str) -> None:
            if node in rec_stack:
                # Found a cycle — extract it from the current path
                idx = path.index(node)
                cycles.append(list(path[idx:]))
                return
            if node in visited:
                return
            if node not in adj:
                return

            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbour in adj.get(node, []):
                dfs(neighbour)

            path.pop()
            rec_stack.discard(node)

        for node in adj:
            dfs(node)

        return cycles
