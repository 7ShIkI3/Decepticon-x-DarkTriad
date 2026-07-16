"""The Dark Triad — Mission Planner.

Decomposes natural-language objectives into executable mission phases,
assigns specialist agents via AgentRegistry, builds dependency graphs
with NetworkX, and estimates duration/risk per personality mode.

Personality-driven planning strategies:
  - NARCISSISM:   1–2 phases, sequential, no dependencies, high risk
  - PSYCHOPATHY:  ≤3 phases, all parallel, no skip, critical risk
  - MACHIAVELLIANISM:  ≥5 phases, complex dependency graph, exit conditions
"""

from __future__ import annotations

import json
from typing import Any

import networkx as nx  # type: ignore[import-untyped]
import structlog

from decepticon.navmax.darktriad.agents.registry import AgentRegistry
from decepticon.navmax.darktriad.core.ai_router import AIRouter, ModelTier
from decepticon.navmax.darktriad.core.personality import PersonalityMode
from decepticon.navmax.darktriad.core.sandbox import SandboxManager
from decepticon.navmax.darktriad.orchestrator.shared import (
    MissionPhase,
    MissionPlan,
    PhaseStatus,
)

logger = structlog.get_logger(__name__)


# ── Personality strategy constants ────────────────────────────────────────────

_PERSONALITY_STRATEGIES: dict[str, dict[str, Any]] = {
    PersonalityMode.NARCISSISM.value: {
        "min_phases": 1,
        "max_phases": 2,
        "parallelism": "sequential",
        "allow_skip": False,
        "default_risk": 0.85,
    },
    PersonalityMode.PSYCHOPATHY.value: {
        "min_phases": 1,
        "max_phases": 3,
        "parallelism": "parallel",
        "allow_skip": False,
        "default_risk": 0.95,
    },
    PersonalityMode.MACHIAVELLIANISM.value: {
        "min_phases": 5,
        "max_phases": 12,
        "parallelism": "dag",
        "allow_skip": True,
        "default_risk": 0.35,
    },
}

# Default phase templates keyed by phase name — used by Machiavelli strategies
_PHASE_TEMPLATES: dict[str, dict[str, Any]] = {
    "passive_recon": {
        "description": "Passive intelligence gathering (OSINT, DNS, WHOIS, Shodan)",
        "agent_category": "recon",
        "tools": ["whois", "dnsrecon", "shodan", "theHarvester"],
        "estimated_duration": 120,
        "risk_level": 0.1,
        "exit_conditions": ["target_ip_resolved", "domain_info_collected"],
        "success_criteria": ["at_least_one_open_port_found", "domain_tech_stack_identified"],
    },
    "active_scan": {
        "description": "Active network scanning (port scan, service fingerprint, Nmap)",
        "agent_category": "recon",
        "tools": ["nmap", "masscan", "rustscan"],
        "estimated_duration": 180,
        "risk_level": 0.3,
        "exit_conditions": ["top_1000_ports_scanned"],
        "success_criteria": ["open_ports_identified", "service_versions_extracted"],
    },
    "vulnerability_analysis": {
        "description": "Vulnerability detection and CVE matching against discovered services",
        "agent_category": "recon",
        "tools": ["nmap_scripts", "searchsploit", " nuclei"],
        "estimated_duration": 240,
        "risk_level": 0.2,
        "exit_conditions": ["no_critical_cves_missed"],
        "success_criteria": ["exploitable_cves_identified", "attack_vector_ranked"],
    },
    "exploit_selection": {
        "description": "Select and prepare best exploit for each identified vulnerability",
        "agent_category": "exploit",
        "tools": ["metasploit", "searchsploit", "custom_exploit"],
        "estimated_duration": 120,
        "risk_level": 0.4,
        "exit_conditions": ["payload_compatible_with_target"],
        "success_criteria": ["working_exploit_selected", "payload_generated"],
    },
    "exploit_execution": {
        "description": "Run selected exploit payload against the target",
        "agent_category": "exploit",
        "tools": ["metasploit", "custom_exploit", "payload_delivery"],
        "estimated_duration": 300,
        "risk_level": 0.7,
        "exit_conditions": ["shell_or_beacon_established"],
        "success_criteria": ["foothold_achieved", "persistence_ready"],
    },
    "post_exploit_verify": {
        "description": "Verify exploitation success and collect system information",
        "agent_category": "post_exploit",
        "tools": ["system_info", "whoami", "enumeration_scripts"],
        "estimated_duration": 90,
        "risk_level": 0.5,
        "exit_conditions": ["system_compromised_confirmed"],
        "success_criteria": ["privilege_level_determined", "sensitive_data_located"],
    },
    "privilege_escalation": {
        "description": "Escalate privileges to highest level on compromised host",
        "agent_category": "exploit",
        "tools": ["linpeas", "winpeas", "kernel_exploit_checker"],
        "estimated_duration": 300,
        "risk_level": 0.6,
        "exit_conditions": ["root_or_system_obtained"],
        "success_criteria": ["highest_privilege_achieved"],
    },
    "lateral_movement": {
        "description": "Move laterally across the network to adjacent targets",
        "agent_category": "lateral",
        "tools": ["crackmapexec", "wmiexec", "psexec", "ssh_pivot"],
        "estimated_duration": 360,
        "risk_level": 0.7,
        "exit_conditions": ["new_target_compromised"],
        "success_criteria": ["pivot_established", "credential_material_extracted"],
    },
    "credential_dump": {
        "description": "Dump credentials and password hashes from compromised systems",
        "agent_category": "credential",
        "tools": ["mimikatz", "sam_dump", "lsass_dump", "hashcat"],
        "estimated_duration": 180,
        "risk_level": 0.8,
        "exit_conditions": ["hashes_or_passwords_extracted"],
        "success_criteria": ["credential_material_obtained", "crackable_hashes_identified"],
    },
    "persistence": {
        "description": "Install persistence mechanisms for long-term access",
        "agent_category": "persistence",
        "tools": ["scheduled_tasks", "service_install", "ssh_key_backdoor"],
        "estimated_duration": 120,
        "risk_level": 0.4,
        "exit_conditions": ["persistence_confirmed"],
        "success_criteria": ["at_least_one_persistence_method_active"],
    },
    "data_exfiltration": {
        "description": "Exfiltrate target data through covert channels",
        "agent_category": "exfil",
        "tools": ["rsync", "dns_exfil", "icmp_exfil", "encrypted_tunnel"],
        "estimated_duration": 600,
        "risk_level": 0.9,
        "exit_conditions": ["data_transferred_or_abort"],
        "success_criteria": ["intel_recovered", "forensic_artifacts_minimised"],
    },
    "cover_tracks": {
        "description": "Erase forensic traces and remove persistence markers",
        "agent_category": "evasion",
        "tools": ["log_cleaner", "timestomp", "artifact_remover"],
        "estimated_duration": 60,
        "risk_level": 0.3,
        "exit_conditions": ["all_accessible_logs_cleared"],
        "success_criteria": ["forensic_footprint_below_threshold"],
    },
}

# Dependency mapping for the default Machiavelli plan
_PHASE_DEPENDENCIES: dict[str, list[str]] = {
    "passive_recon": [],
    "active_scan": ["passive_recon"],
    "vulnerability_analysis": ["active_scan"],
    "exploit_selection": ["vulnerability_analysis"],
    "exploit_execution": ["exploit_selection"],
    "post_exploit_verify": ["exploit_execution"],
    "privilege_escalation": ["post_exploit_verify"],
    "lateral_movement": ["privilege_escalation"],
    "credential_dump": ["post_exploit_verify"],
    "persistence": ["post_exploit_verify"],
    "data_exfiltration": ["credential_dump", "persistence"],
    "cover_tracks": ["data_exfiltration"],
}


# ── Prompt templates ──────────────────────────────────────────────────────────

_DECOMPOSE_PROMPT = """You are a military-grade mission planner. Decompose the following
objective into discrete, executable phases for an autonomous offensive security agent.

PERSONALITY: {personality}
OBJECTIVE: {objective}
CONSTRAINTS: {constraints}

For each phase, return a JSON object with exactly these fields:
- "name": short unique name (snake_case, e.g. "port_scan")
- "description": one-line description of what this phase does
- "agent_category": one of: recon, exploit, post_exploit, persistence, lateral, exfil, evasion, credential, privesc, c2, deception, ad, cloud, social
- "tools": list of tool names needed
- "depends_on": list of phase names this phase depends on (empty list for root phases)
- "estimated_duration": estimated seconds for this phase (integer)
- "risk_level": float 0.0 (safe) to 1.0 (suicide)
- "exit_conditions": list of conditions that must be met to consider this phase done
- "success_criteria": list of measurable success criteria

Personality-specific planning rules:
- NARCISSISM: ONLY 1-2 phases, no dependencies, aggressive direct approach
- PSYCHOPATHY: AT MOST 3 phases, all run in parallel with zero dependencies
- MACHIAVELLIANISM: AT LEAST 5 phases, detailed dependency graph, stealth prioritised

Return a JSON array of phase objects ONLY — no explanatory text.
"""


# ── Main Planner ──────────────────────────────────────────────────────────────


class MissionPlanner:
    """Decomposes NL objectives → mission phases → agent assignments → ordered plan.

    Uses the AI router for natural-language decomposition, the agent registry
    for capability-based agent selection, NetworkX for dependency graph
    analysis, and personality-specific strategies for plan structure.

    Args:
        ai_router: Multi-provider AI router for NL→phase decomposition.
        agent_registry: Registered agent catalogue for capability lookups.
        sandbox: Sandbox manager (used to validate execution feasibility).
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
        self._log = logger.bind(component="MissionPlanner")

    # ── Public API ─────────────────────────────────────────────────────────

    async def plan(
        self,
        objective: str,
        personality: str = PersonalityMode.MACHIAVELLIANISM.value,
        constraints: dict | None = None,
    ) -> MissionPlan:
        """Full planning pipeline: analyse → decompose → assign → schedule.

        Args:
            objective: Natural-language mission objective.
            personality: One of ``"narcissism"``, ``"psychopathy"``,
                         or ``"machiavellianism"``.
            constraints: Optional dict of constraints (airgap, target_type, etc.).

        Returns:
            A complete :class:`MissionPlan` with assigned, ordered phases.
        """
        constraints = constraints or {}
        self._log.info(
            "planning_mission",
            objective=objective,
            personality=personality,
            constraints=constraints,
        )

        # 1. Analyse the objective via AI Router
        analysis = await self._analyse_objective(objective, personality)

        # 2. Decompose into raw phases
        raw_phases = await self.decompose(objective, personality, analysis)

        # 3. Assign agents to each phase
        phases = await self.assign_agents(raw_phases)

        # 4. Build the dependency graph & order
        dag = self._build_dependency_graph(phases)
        ordered = self._topological_sort(phases, dag, personality)

        # 5. Estimate duration and risk
        estimated_duration = self._estimate_duration(ordered)
        risk_level = self._estimate_risk(ordered, constraints)

        plan = MissionPlan(
            objective=objective,
            personality=personality,
            phases=ordered,
            constraints=constraints,
            estimated_duration=estimated_duration,
            risk_level=risk_level,
            status="planned",
        )

        self._log.info(
            "mission_planned",
            mission_id=plan.mission_id,
            total_phases=plan.total_phases,
            duration=plan.estimated_duration,
            risk=plan.risk_level,
        )
        return plan

    # ── Step 1: Analyse ───────────────────────────────────────────────────

    async def _analyse_objective(
        self,
        objective: str,
        personality: str,
    ) -> dict[str, Any]:
        """Send the objective to the AI router for initial analysis.

        Returns a dict with target, outcome, constraints, and risk hints.
        """
        try:
            result = await self._ai_router.generate(
                prompt=(
                    f"Analyse the following offensive security objective. "
                    f"Extract: target, desired_outcome, constraints (list), "
                    f"estimated_complexity (1-10), risk_hints (list).\n"
                    f"Personality: {personality}\n"
                    f"Objective: {objective}"
                ),
                tier=ModelTier.LIGHT,
                json_mode=True,
            )
            return json.loads(result.text)
        except Exception as exc:
            self._log.warning("analysis_fallback", error=str(exc))
            return {
                "target": objective.split()[0] if objective else "unknown",
                "desired_outcome": objective,
                "constraints": [],
                "estimated_complexity": 5,
                "risk_hints": ["unknown"],
            }

    # ── Step 2: Decompose ─────────────────────────────────────────────────

    async def decompose(
        self,
        objective: str,
        personality: str = PersonalityMode.MACHIAVELLIANISM.value,
        analysis: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Decompose a natural-language objective into raw phase dicts.

        Uses the AI router for NL→phase decomposition with personality-
        aware prompts. Falls back to template-based decomposition when
        the AI router is unavailable or returns invalid output.

        Args:
            objective: The mission objective.
            personality: Personality mode for planning strategy.
            analysis: Optional pre-computed objective analysis.

        Returns:
            A list of phase dicts (each containing name, description,
            agent_category, tools, depends_on, etc.).
        """
        strategy = _PERSONALITY_STRATEGIES.get(
            personality, _PERSONALITY_STRATEGIES[PersonalityMode.MACHIAVELLIANISM.value]
        )
        constraints_str = json.dumps(analysis or {}, indent=2)

        try:
            result = await self._ai_router.generate(
                prompt=_DECOMPOSE_PROMPT.format(
                    personality=personality.upper(),
                    objective=objective,
                    constraints=constraints_str,
                ),
                tier=ModelTier.LIGHT,
                json_mode=True,
            )

            raw = json.loads(result.text)

            # Accept either a list directly or a dict with a 'phases' key
            if isinstance(raw, dict):
                raw = raw.get("phases", raw.get("phases", []))
            if not isinstance(raw, list):
                self._log.warning("unexpected_decompose_format", received=type(raw).__name__)
                raw = []

            # Enforce personality min/max phase limits
            min_p = strategy["min_phases"]
            max_p = strategy["max_phases"]
            if len(raw) < min_p:
                self._log.warning(
                    "too_few_phases_from_ai",
                    count=len(raw),
                    minimum=min_p,
                )
                # Extend with templates if AI returned too few
                raw = self._extend_with_templates(raw, min_p, objective)
            if len(raw) > max_p:
                self._log.info("truncating_phases", count=len(raw), maximum=max_p)
                raw = raw[:max_p]

            return raw

        except Exception as exc:
            self._log.warning("ai_decompose_fallback", error=str(exc))
            return self._template_fallback(objective, personality)

    def _extend_with_templates(
        self,
        existing: list[dict[str, Any]],
        minimum: int,
        objective: str,
    ) -> list[dict[str, Any]]:
        """Pad a short phase list with template phases to meet *minimum*."""
        used_names = {p.get("name") for p in existing if p.get("name")}
        for tpl_name in _PHASE_TEMPLATES:
            if len(existing) >= minimum:
                break
            if tpl_name in used_names:
                continue
            tpl = dict(_PHASE_TEMPLATES[tpl_name])
            tpl["name"] = tpl_name
            tpl["description"] = tpl["description"].replace("target", objective)
            existing.append(tpl)
        return existing

    def _template_fallback(
        self,
        objective: str,
        personality: str,
    ) -> list[dict[str, Any]]:
        """Generate a hard-coded phase list when the AI router is unavailable."""
        strategy = _PERSONALITY_STRATEGIES.get(
            personality, _PERSONALITY_STRATEGIES[PersonalityMode.MACHIAVELLIANISM.value]
        )

        if personality == PersonalityMode.NARCISSISM.value:
            return [
                {
                    "name": "full_assault",
                    "description": f"Direct full-spectrum assault on {objective}",
                    "agent_category": "exploit",
                    "tools": ["all"],
                    "depends_on": [],
                    "estimated_duration": 60,
                    "risk_level": 0.85,
                    "exit_conditions": ["target_compromised"],
                    "success_criteria": ["foothold_achieved"],
                },
            ]

        if personality == PersonalityMode.PSYCHOPATHY.value:
            return [
                {
                    "name": "recon_and_exploit",
                    "description": f"Simultaneous recon and exploitation of {objective}",
                    "agent_category": "exploit",
                    "tools": ["nmap", "metasploit", "all"],
                    "depends_on": [],
                    "estimated_duration": 120,
                    "risk_level": 0.95,
                    "exit_conditions": ["any_foothold"],
                    "success_criteria": ["access_obtained"],
                },
            ]

        # Machiavelli default — full pipeline
        phases: list[dict[str, Any]] = []
        for tpl_name, tpl in _PHASE_TEMPLATES.items():
            if len(phases) >= strategy["max_phases"]:
                break
            phase = dict(tpl)
            phase["name"] = tpl_name
            phase["depends_on"] = _PHASE_DEPENDENCIES.get(tpl_name, [])
            phases.append(phase)
        return phases

    # ── Step 3: Assign agents ─────────────────────────────────────────────

    async def assign_agents(
        self,
        phases: list[dict[str, Any]],
    ) -> list[MissionPhase]:
        """Map each raw phase dict to a concrete agent via AgentRegistry.

        For each phase, queries the registry by category and selects the
        best-matching agent. If no agent matches the category, assigns
        a fallback agent.

        Args:
            phases: Raw phase dicts from :meth:`decompose`.

        Returns:
            A list of :class:`MissionPhase` instances with resolved agents.
        """
        assigned: list[MissionPhase] = []

        for i, raw in enumerate(phases):
            category = raw.get("agent_category", "recon")
            candidates = self._agent_registry.list_by_category(category)

            if candidates:
                agent = candidates[0]
                agent_name = agent.name
                personality_override = getattr(agent, "personality_mode", None)
            else:
                # Fallback: grab any registered agent
                all_agents = self._agent_registry.list_all()
                if all_agents:
                    agent = all_agents[0]
                    agent_name = agent.name
                    personality_override = getattr(agent, "personality_mode", None)
                    self._log.warning(
                        "category_fallback",
                        phase=raw.get("name"),
                        requested_category=category,
                        assigned_agent=agent_name,
                    )
                else:
                    # No agents at all — placeholder
                    agent_name = "unassigned"
                    personality_override = None
                    self._log.error(
                        "no_agents_registered",
                        phase=raw.get("name"),
                    )

            phase = MissionPhase(
                id=raw.get("name", f"phase_{i + 1}"),
                phase_number=i + 1,
                name=raw.get("name", f"phase_{i + 1}"),
                description=raw.get("description", ""),
                agent_name=agent_name,
                agent_category=category,
                personality_override=personality_override,
                objective=raw.get("description", ""),
                tools=raw.get("tools", []),
                commands=raw.get("commands", []),
                depends_on=raw.get("depends_on", []),
                estimated_duration=int(raw.get("estimated_duration", 30)),
                risk_level=float(raw.get("risk_level", 0.5)),
                exit_conditions=raw.get("exit_conditions", []),
                success_criteria=raw.get("success_criteria", []),
                status=PhaseStatus.PENDING,
            )
            assigned.append(phase)
            self._log.debug(
                "phase_assigned",
                phase=phase.name,
                agent=phase.agent_name,
                category=phase.agent_category,
            )

        return assigned

    # ── Step 4: Dependency graph & ordering ───────────────────────────────

    def _build_dependency_graph(
        self,
        phases: list[MissionPhase],
    ) -> nx.DiGraph:
        """Build a NetworkX directed graph from phase dependency declarations.

        Each phase is a node; each ``depends_on`` entry becomes an edge
        from the dependency to the dependent phase.

        Args:
            phases: Fully assigned mission phases.

        Returns:
            A :class:`nx.DiGraph` with phase IDs as node keys and phase
            objects stored in the ``"phase"`` node attribute.
        """
        dag = nx.DiGraph()
        phase_map = {p.id: p for p in phases}

        for p in phases:
            dag.add_node(p.id, phase=p)

        for p in phases:
            for dep_id in p.depends_on:
                if dep_id in phase_map:
                    dag.add_edge(dep_id, p.id)
                else:
                    self._log.warning(
                        "unknown_dependency",
                        phase=p.id,
                        depends_on=dep_id,
                    )

        self._log.debug(
            "dependency_graph_built",
            nodes=dag.number_of_nodes(),
            edges=dag.number_of_edges(),
        )
        return dag

    def _topological_sort(
        self,
        phases: list[MissionPhase],
        dag: nx.DiGraph,
        personality: str,
    ) -> list[MissionPhase]:
        """Order phases respecting the dependency graph and personality.

        Personality rules:
        - NARCISSISM: Sequential, single-phase ordering, no parallelism.
        - PSYCHOPATHY: All phases run in parallel — remove all dependencies.
        - MACHIAVELLIANISM: Full topological ordering by dependency DAG.

        Args:
            phases: Assigned mission phases.
            dag: Dependency graph built from phase declarations.
            personality: Personality mode string.

        Returns:
            Re-ordered list of :class:`MissionPhase` instances.
        """
        if personality == PersonalityMode.PSYCHOPATHY.value:
            # Strip all dependencies — parallel execution
            for p in phases:
                p.depends_on = []
            return phases

        if personality == PersonalityMode.NARCISSISM.value:
            # Sequential — chain phases linearly
            for i, phase in enumerate(phases):
                if i > 0:
                    phase.depends_on = [phases[i - 1].id]
                else:
                    phase.depends_on = []
            return phases

        # Machiavelli: topological sort
        try:
            ordered_ids: list[str] = list(nx.topological_sort(dag))
        except nx.NetworkXUnfeasible:
            self._log.warning("dependency_cycle_detected", falling_back="insertion_order")
            # Fall back to insertion order if the graph has cycles
            return phases

        phase_map = {p.id: p for p in phases}
        ordered = [phase_map[pid] for pid in ordered_ids if pid in phase_map]

        # Re-number phases in their new order
        for i, p in enumerate(ordered):
            p.phase_number = i + 1

        return ordered

    # ── Step 5: Estimate ──────────────────────────────────────────────────

    def _estimate_duration(self, phases: list[MissionPhase]) -> int:
        """Estimate total mission duration in seconds.

        For sequential phases, sum individual durations.
        For parallel-scheduled phases, use the max of concurrent groups.

        Uses a simple greedy analysis: phases with no inter-dependencies
        can run in parallel.

        Args:
            phases: Ordered mission phases.

        Returns:
            Total estimated duration in seconds.
        """
        if not phases:
            return 0

        # Build a simple dependency map
        deps_of: dict[str, list[str]] = {p.id: list(p.depends_on) for p in phases}

        executed: set[str] = set()
        total = 0

        remaining = list(phases)
        while remaining:
            # Batch: phases whose dependencies are all met
            batch = [p for p in remaining if all(d in executed for d in deps_of[p.id])]
            if not batch:
                batch = [remaining[0]]

            for p in batch:
                remaining.remove(p)

            # Duration of this batch = max of its members
            batch_duration = max(p.estimated_duration for p in batch)
            total += batch_duration

            for p in batch:
                executed.add(p.id)

        return total

    def _estimate_risk(
        self,
        phases: list[MissionPhase],
        target_context: dict[str, Any],
    ) -> float:
        """Calculate aggregate mission risk score (0.0 → 1.0).

        Factors:
        1. Mean risk of all phases.
        2. Number of phases (more phases → more exposure).
        3. Target context hints (e.g. "high_value_target" increases risk).
        4. Estimated duration (longer missions → higher risk).

        Args:
            phases: Ordered mission phases.
            target_context: Dict with optional keys like ``risk_hints``,
                            ``estimated_complexity``, ``target``.

        Returns:
            Float risk score between 0.0 and 1.0.
        """
        if not phases:
            return 0.0

        # Base: average phase risk
        base_risk = sum(p.risk_level for p in phases) / len(phases)

        # Phase count penalty (more phases = more to go wrong)
        n = len(phases)
        count_factor = min(0.15, n * 0.02)

        # Duration penalty (longer = riskier)
        total_duration = self._estimate_duration(phases)
        duration_factor = min(0.15, total_duration / 3600 * 0.05)  # per hour

        # Context penalties
        context_factor = 0.0
        risk_hints = target_context.get("risk_hints", [])
        if isinstance(risk_hints, list):
            context_factor = min(0.2, len(risk_hints) * 0.05)

        complexity = target_context.get("estimated_complexity", 1)
        if isinstance(complexity, (int, float)):
            context_factor += min(0.3, complexity * 0.03)

        raw = base_risk + count_factor + duration_factor + context_factor
        return round(min(1.0, max(0.0, raw)), 4)
