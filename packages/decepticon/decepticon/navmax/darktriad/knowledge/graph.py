"""The Dark Triad — Knowledge Graph Backend.

AttackGraph (NetworkX by default, Neo4j optional), PatternLearner,
and MITRE ATT&CK mapping for autonomous offensive operations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean
from typing import Any

import networkx as nx

# ── Dataclasses ──────────────────────────────────────────────────────────────


@dataclass
class TargetNode:
    """A target host / network asset discovered during recon."""

    id: str
    hostname: str
    ip: str
    os: str
    criticality: float  # 0.0 → 1.0
    tags: list[str] = field(default_factory=list)


@dataclass
class FindingNode:
    """A vulnerability, weakness, or exposure found on a target."""

    id: str
    target_id: str
    type: str  # vulnerability / weakness / exposure
    severity: str  # critical / high / medium / low
    cve: str | None = None
    description: str = ""
    cvss_score: float | None = None
    mitre_technique: str | None = None


@dataclass
class ExploitNode:
    """A recorded exploit attempt against a finding."""

    id: str
    finding_id: str
    success: bool
    method: str
    timestamp: str
    personality: str = ""
    output: str = ""


@dataclass
class AttackPath:
    """A complete attack chain from entry to target."""

    id: str
    steps: list[str]  # node IDs along the path
    total_risk: float  # aggregated risk score
    techniques: list[str] = field(default_factory=list)  # MITRE ATT&CK
    personality_used: str = ""


@dataclass
class GraphStats:
    """Aggregate statistics for the knowledge graph."""

    targets: int = 0
    findings: int = 0
    exploits: int = 0
    attack_paths: int = 0
    critical_paths: int = 0
    unique_techniques: int = 0


@dataclass
class LearnedPattern:
    """A reusable attack pattern extracted from past engagements."""

    pattern: str
    technique_chain: list[str] = field(default_factory=list)
    success_rate: float = 0.0
    best_personality: str = ""
    target_profile: str = ""


# ── Node / Edge type constants ───────────────────────────────────────────────

_NODE_TARGET = "target"
_NODE_FINDING = "finding"
_NODE_EXPLOIT = "exploit"

_EDGE_FOUND_ON = "found_on"  # finding → target
_EDGE_EXPLOITS = "exploits"  # exploit → finding
_EDGE_CHAIN = "chain"  # directional attack-step link
_EDGE_TECHNIQUE = "technique"  # node → MITRE technique label

# Default criticality threshold for "critical path" classification
_CRITICAL_THRESHOLD = 0.8


# ── AttackGraph (NetworkX backend) ──────────────────────────────────────────


class AttackGraph:
    """Knowledge graph for offensive operations.

    NetworkX DiGraph as the primary backend.  Neo4j is **optional** —
    when *use_neo4j=True* and the connection fails, the class falls
    back to NetworkX transparently.
    """

    def __init__(self, use_neo4j: bool = False) -> None:
        self.use_neo4j = use_neo4j
        self._graph: nx.DiGraph = nx.DiGraph()
        self._neo4j_driver: Any = None
        self._neo4j_available = False

        if use_neo4j:
            self._try_connect_neo4j()

    # ------------------------------------------------------------------
    # Neo4j bootstrap (optional)
    # ------------------------------------------------------------------

    def _try_connect_neo4j(self) -> None:
        """Attempt to connect to a local Neo4j instance.

        If anything fails the graph stays in NetworkX mode.
        """
        try:
            # Respect standard env vars or fall back to defaults
            import os

            from neo4j import GraphDatabase

            uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
            user = os.environ.get("NEO4J_USER", "neo4j")
            pwd = os.environ.get("NEO4J_PASSWORD", "password")

            self._neo4j_driver = GraphDatabase.driver(uri, auth=(user, pwd))
            # Verify connectivity
            self._neo4j_driver.verify_connectivity()
            self._neo4j_available = True
        except Exception:
            self._neo4j_available = False
            self._neo4j_driver = None
            # Transparent fallback — no warning noise

    # ------------------------------------------------------------------
    # Core mutation helpers
    # ------------------------------------------------------------------

    def _add_node(self, node_id: str, kind: str, **attrs: Any) -> None:
        """Internal: add a typed node to the NetworkX graph."""
        attrs["kind"] = kind
        self._graph.add_node(node_id, **attrs)

    def _ensure_node(self, node_id: str) -> bool:
        """Return True if the node exists."""
        return self._graph.has_node(node_id)

    # ------------------------------------------------------------------
    # Public mutation API  (all async for consistent interface)
    # ------------------------------------------------------------------

    async def add_target(self, target: TargetNode) -> str:
        """Store a target node and return its id."""
        self._add_node(
            target.id,
            _NODE_TARGET,
            hostname=target.hostname,
            ip=target.ip,
            os=target.os,
            criticality=target.criticality,
            tags=list(target.tags),
        )
        return target.id

    async def add_finding(self, finding: FindingNode) -> str:
        """Store a finding and link it to its target."""
        self._add_node(
            finding.id,
            _NODE_FINDING,
            target_id=finding.target_id,
            type=finding.type,
            severity=finding.severity,
            cve=finding.cve,
            description=finding.description,
            cvss_score=finding.cvss_score,
            mitre_technique=finding.mitre_technique,
        )
        if self._ensure_node(finding.target_id):
            self._graph.add_edge(finding.id, finding.target_id, relation=_EDGE_FOUND_ON)
        if finding.mitre_technique:
            self._graph.add_edge(finding.id, finding.mitre_technique, relation=_EDGE_TECHNIQUE)
        return finding.id

    async def add_exploit(self, exploit: ExploitNode) -> str:
        """Store an exploit and link it to its finding."""
        self._add_node(
            exploit.id,
            _NODE_EXPLOIT,
            finding_id=exploit.finding_id,
            success=exploit.success,
            method=exploit.method,
            timestamp=exploit.timestamp,
            personality=exploit.personality,
            output=exploit.output,
        )
        if self._ensure_node(exploit.finding_id):
            self._graph.add_edge(exploit.id, exploit.finding_id, relation=_EDGE_EXPLOITS)
        return exploit.id

    async def add_attack_path(self, path: AttackPath) -> str:
        """Record a full attack chain.

        Each consecutive pair of *path.steps* gets a ``chain`` edge.
        """
        self._add_node(
            path.id,
            "attack_path",
            steps=list(path.steps),
            total_risk=path.total_risk,
            techniques=list(path.techniques),
            personality_used=path.personality_used,
        )
        for i in range(len(path.steps) - 1):
            self._graph.add_edge(path.steps[i], path.steps[i + 1], relation=_EDGE_CHAIN)
        return path.id

    async def link(self, source_id: str, target_id: str, relation: str) -> None:
        """Add an arbitrary typed edge between two existing nodes."""
        if not (self._ensure_node(source_id) and self._ensure_node(target_id)):
            msg = f"Cannot link {source_id!r} → {target_id!r}: node(s) missing"
            raise ValueError(msg)
        self._graph.add_edge(source_id, target_id, relation=relation)

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    async def query_attack_paths(self, target: str) -> list[AttackPath]:
        """Return every recorded attack path containing *target*."""
        results: list[AttackPath] = []
        for nid, data in self._graph.nodes(data=True):
            if data.get("kind") != "attack_path":
                continue
            steps: list[str] = data.get("steps", [])
            if target in steps:
                results.append(
                    AttackPath(
                        id=nid,
                        steps=steps,
                        total_risk=data.get("total_risk", 0.0),
                        techniques=list(data.get("techniques", [])),
                        personality_used=data.get("personality_used", ""),
                    )
                )
        return results

    async def find_critical_paths(self) -> list[AttackPath]:
        """Shortest paths (by step count) toward high-criticality targets.

        Only considers targets whose ``criticality >= 0.8``.
        """
        critical_targets = [
            nid
            for nid, data in self._graph.nodes(data=True)
            if (
                data.get("kind") == _NODE_TARGET
                and data.get("criticality", 0.0) >= _CRITICAL_THRESHOLD
            )
        ]
        # Collect all attack-path nodes
        path_nodes = [
            (nid, data)
            for nid, data in self._graph.nodes(data=True)
            if data.get("kind") == "attack_path"
        ]
        results: list[AttackPath] = []
        for nid, data in path_nodes:
            steps: list[str] = data.get("steps", [])
            for ct in critical_targets:
                if ct in steps:
                    results.append(
                        AttackPath(
                            id=nid,
                            steps=steps,
                            total_risk=data.get("total_risk", 0.0),
                            techniques=list(data.get("techniques", [])),
                            personality_used=data.get("personality_used", ""),
                        )
                    )
                    break
        # Sort by step count ascending (shortest critical paths first)
        results.sort(key=lambda p: len(p.steps))
        return results

    async def export_mitre_mapping(self) -> dict[str, list[str]]:
        """Map every MITRE ATT&CK technique to the findings that use it.

        Returns ``{technique_id: [finding_id, …]}``.
        """
        mapping: dict[str, list[str]] = {}
        for nid, data in self._graph.nodes(data=True):
            if data.get("kind") != _NODE_FINDING:
                continue
            technique = data.get("mitre_technique")
            if technique:
                mapping.setdefault(technique, []).append(nid)
        return mapping

    async def get_statistics(self) -> GraphStats:
        """Compute aggregate graph statistics."""
        targets = sum(1 for _, d in self._graph.nodes(data=True) if d.get("kind") == _NODE_TARGET)
        findings = sum(1 for _, d in self._graph.nodes(data=True) if d.get("kind") == _NODE_FINDING)
        exploits = sum(1 for _, d in self._graph.nodes(data=True) if d.get("kind") == _NODE_EXPLOIT)
        paths = sum(1 for _, d in self._graph.nodes(data=True) if d.get("kind") == "attack_path")

        techniques: set[str] = set()
        for _, d in self._graph.nodes(data=True):
            t = d.get("mitre_technique")
            if t:
                techniques.add(t)
            for t2 in d.get("techniques", []):
                techniques.add(t2)

        critical_paths_pct = 0.0
        if paths > 0:
            cps = await self.find_critical_paths()
            critical_paths_pct = len(cps)

        return GraphStats(
            targets=targets,
            findings=findings,
            exploits=exploits,
            attack_paths=paths,
            critical_paths=int(critical_paths_pct),
            unique_techniques=len(techniques),
        )

    # ------------------------------------------------------------------
    # Low-level accessors (for PatternLearner and testing)
    # ------------------------------------------------------------------

    @property
    def graph(self) -> nx.DiGraph:
        """Expose the underlying NetworkX graph for advanced queries."""
        return self._graph


# ── PatternLearner ───────────────────────────────────────────────────────────


class PatternLearner:
    """Learns reusable attack patterns from historical graph data.

    Extracts technique chains, correlates them with personality profiles
    and target characteristics, and surfaces the most effective approaches.
    """

    # MITRE technique → applicable target OS / service profile hints
    _OS_HINT: dict[str, str] = {
        "T1190": "web_server",  # Exploit Public-Facing Application
        "T1133": "vpn_or_rdp",
        "T1566": "user_endpoint",  # Phishing
        "T1078": "any_with_creds",  # Valid Accounts
        "T1203": "client_software",  # Exploitation for Client Execution
        "T1543": "server_os",  # Create or Modify System Process
        "T1059": "any",  # Command and Scripting Interpreter
        "T1053": "server_os",  # Scheduled Task / Job
        "T1003": "domain_controller",  # OS Credential Dumping
        "T1482": "domain_controller",  # Domain Trust Discovery
        "T1558": "domain_controller",  # Steal or Forge Kerberos Tickets
        "T1550": "any",  # Use Alternate Authentication Material
        "T1021": "any",  # Remote Services
        "T1570": "server_os",  # Lateral Tool Transfer
        "T1048": "any",  # Exfiltration Over Alternative Protocol
    }

    # Personality → success-weight bonus
    _PERSONALITY_WEIGHTS: dict[str, float] = {
        "psychopathy": 1.0,
        "narcissism": 0.7,
        "mach": 0.9,
    }

    def __init__(self) -> None:
        self._patterns: dict[str, LearnedPattern] = {}

    # ------------------------------------------------------------------
    # Learning
    # ------------------------------------------------------------------

    async def learn_from_engagement(self, graph: AttackGraph) -> list[LearnedPattern]:
        """Analyse the graph and extract attack patterns.

        Returns a list of *LearnedPattern* instances sorted by
        success rate (descending).
        """
        raw: dict[str, dict[str, Any]] = {}

        for _, data in graph.graph.nodes(data=True):
            if data.get("kind") != _NODE_EXPLOIT:
                continue
            success = data.get("success", False)
            method = data.get("method", "unknown")
            personality = data.get("personality", "")
            finding_id = data.get("finding_id", "")

            if not finding_id:
                continue

            # Resolve the finding node to get the technique chain
            finding_data = graph.graph.nodes.get(finding_id)
            if not finding_data:
                continue

            technique = finding_data.get("mitre_technique") or "unknown"

            # Build a coarse target profile from the technique hint
            target_profile = self._OS_HINT.get(technique, "unknown")

            key = f"{technique}::{method}"

            if key not in raw:
                raw[key] = {
                    "technique_chain": [technique],
                    "success_count": 0,
                    "total_count": 0,
                    "best_personality": personality,
                    "personality_scores": {},
                    "target_profile": target_profile,
                    "pattern": f"{technique} → {method}",
                }

            entry = raw[key]
            entry["total_count"] += 1
            if success:
                entry["success_count"] += 1
            entry["personality_scores"][personality] = entry["personality_scores"].get(
                personality, 0
            ) + (1 if success else 0)
            # Track best personality by raw success count
            best_p = max(entry["personality_scores"], key=lambda p: entry["personality_scores"][p])
            entry["best_personality"] = best_p

        # Convert raw dicts to LearnedPattern
        patterns: list[LearnedPattern] = []
        for key, entry in raw.items():
            total = entry["total_count"]
            success_rate = entry["success_count"] / total if total > 0 else 0.0
            patterns.append(
                LearnedPattern(
                    pattern=entry["pattern"],
                    technique_chain=entry["technique_chain"],
                    success_rate=round(success_rate, 4),
                    best_personality=entry["best_personality"],
                    target_profile=entry["target_profile"],
                )
            )

        patterns.sort(key=lambda p: p.success_rate, reverse=True)
        self._patterns = {p.pattern: p for p in patterns}
        return patterns

    async def suggest_techniques(self, target_profile: TargetNode) -> list[str]:
        """Recommend MITRE techniques based on target profile + learned patterns.

        Uses coarse OS-profile matching when few or no patterns exist yet.
        """
        if not self._patterns:
            return self._default_techniques(target_profile)

        # Score each pattern by relevance to the target
        scored: list[tuple[str, float]] = []
        for pattern in self._patterns.values():
            relevance = self._profile_match(pattern.target_profile, target_profile)
            score = pattern.success_rate * relevance
            # Bonus for best personality alignment
            if pattern.best_personality:
                w = self._PERSONALITY_WEIGHTS.get(pattern.best_personality, 0.5)
                score *= w
            scored.append((pattern.technique_chain[0], score))

        scored.sort(key=lambda x: x[1], reverse=True)
        # Deduplicate while preserving order
        seen: set[str] = set()
        result: list[str] = []
        for technique, _ in scored:
            if technique not in seen:
                seen.add(technique)
                result.append(technique)
                if len(result) >= 10:
                    break

        return result if result else self._default_techniques(target_profile)

    async def evaluate_personality_effectiveness(self, personality: str) -> float:
        """Return the average success rate across all patterns for *personality*.

        Returns 0.0 if no patterns exist or the personality was never used.
        """
        rates: list[float] = []
        for pattern in self._patterns.values():
            if pattern.best_personality == personality:
                rates.append(pattern.success_rate)
        return round(mean(rates), 4) if rates else 0.0

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _profile_match(pattern_profile: str, target: TargetNode) -> float:
        """Score how well a pattern's target profile matches a real target (0-1)."""
        # Simple heuristic — expand with actual OS fingerprinting later
        os_normalised = target.os.lower()
        hint_normalised = pattern_profile.lower()

        exact_matches = {
            "web_server": ["linux", "windows server", "nginx", "apache"],
            "vpn_or_rdp": ["windows", "linux"],
            "domain_controller": ["windows server", "windows"],
            "any": [],  # always matches
        }

        if hint_normalised == "any" or not hint_normalised:
            return 1.0
        if hint_normalised == "unknown":
            return 0.3

        candidates = exact_matches.get(hint_normalised, [])
        if not candidates:
            return 0.5
        for c in candidates:
            if c in os_normalised:
                return 0.9
        return 0.3

    @staticmethod
    def _default_techniques(target: TargetNode) -> list[str]:
        """Fallback technique suggestions when no learned patterns exist."""
        os_lower = target.os.lower()
        techniques: list[str] = ["T1078"]  # Valid Accounts — universal

        if "web" in os_lower or "nginx" in os_lower or "apache" in os_lower:
            techniques.extend(["T1190", "T1203"])
        elif "windows" in os_lower:
            techniques.extend(["T1003", "T1558", "T1133"])
        elif "linux" in os_lower:
            techniques.extend(["T1543", "T1059", "T1053"])
        else:
            techniques.append("T1566")

        return techniques


@dataclass
class _NodeRef:
    """Lightweight helper for building AttackPath step lists.

    Not exported — internal convenience only.
    """

    node_id: str
    kind: str
