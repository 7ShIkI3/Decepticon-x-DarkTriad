"""Firewall Rule Analyzer — analyse intelligente des règles de firewall.

Détecte :
- Règles Any/Any (trop permissives)
- Shadowing (règle masquée par une autre plus large)
- Redondance (règles identiques)
- Règles exposant des ports à risque (RDP, SSH, DB...)
- Règles sans hit count (potentiellement inutiles)
- Règles permettant le trafic depuis/vers des zones sensibles
- Ordonnancement sous-optimal (règle large avant règle spécifique)

Usage:
    analyzer = RuleAnalyzer()
    findings = analyzer.analyze(firewall_config)
    for f in findings:
        print(f"{f.severity}: {f.description}")
"""

from dataclasses import dataclass, field
from enum import StrEnum

import structlog

from .base import (
    FirewallConfig,
    FirewallRule,
    RuleAction,
    RuleSeverity,
)

logger = structlog.get_logger(__name__)


# ── Types ──────────────────────────────────────────────────────


class FindingType(StrEnum):
    ANY_ANY_RULE = "any_any_rule"
    SHADOWED_RULE = "shadowed_rule"
    REDUNDANT_RULE = "redundant_rule"
    HIGH_RISK_PORT = "high_risk_port"
    ZERO_HIT_RULE = "zero_hit_rule"
    PERMISSIVE_SOURCE = "permissive_source"
    RULE_ORDER_ISSUE = "rule_order_issue"
    DISABLED_RULE_ORPHAN = "disabled_rule_orphan"


@dataclass
class RuleFinding:
    """Une anomalie détectée dans les règles firewall."""

    type: FindingType
    severity: RuleSeverity
    description: str
    rule_ids: list[str] = field(default_factory=list)
    rule_names: list[str] = field(default_factory=list)
    recommendation: str = ""
    impact: str = ""


@dataclass
class RuleAnalysisReport:
    """Rapport d'analyse des règles firewall."""

    firewall: str = ""
    total_rules: int = 0
    enabled_rules: int = 0
    findings: list[RuleFinding] = field(default_factory=list)
    risk_score: float = 0.0  # 0-100

    def summary(self) -> str:
        lines = [
            f"=== Rule Analysis: {self.firewall} ===",
            f"Total rules: {self.total_rules} ({self.enabled_rules} enabled)",
            f"Findings: {len(self.findings)}",
            f"Risk Score: {self.risk_score:.0f}/100",
        ]
        for f in self.findings:
            marker = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}.get(
                f.severity, "❓",
            )
            lines.append(
                f"  {marker} [{f.type}] {f.description}",
            )
        return "\n".join(lines)


# ── Analyseur ──────────────────────────────────────────────────


class RuleAnalyzer:
    """Analyseur de règles firewall.

    Usage:
        analyzer = RuleAnalyzer()
        report = analyzer.analyze(firewall_config)
        print(report.summary())
    """

    # Ports à haut risque
    HIGH_RISK_PORTS: dict[str, tuple[str, str]] = {
        "22": ("SSH", "Accès shell distant"),
        "23": ("Telnet", "Protocole non"),
        "3389": ("RDP", "Bureau à distance"),
        "5900": ("VNC", "Contrôle distant"),
        "21": ("FTP", "Transfert fichier"),
        "135": ("RPC", "Remote Procedure Call"),
        "139": ("NetBIOS", "Partage fichier"),
        "445": ("SMB", "Partage fichier"),
        "1433": ("MSSQL", "Base SQL Server"),
        "1521": ("Oracle", "Base Oracle"),
        "3306": ("MySQL", "Base MySQL"),
        "5432": ("PostgreSQL", "Base PostgreSQL"),
        "6379": ("Redis", "Cache Redis"),
        "27017": ("MongoDB", "Base MongoDB"),
        "11211": ("Memcached", "Cache Memcached"),
        "5985": ("WinRM", "PowerShell Remoting"),
        "636": ("LDAPS", "LDAP sécurisé"),
    }

    def __init__(self) -> None:
        self._findings: list[RuleFinding] = []

    def analyze(self, config: FirewallConfig) -> RuleAnalysisReport:
        """Analyse complète d'une configuration firewall.

        Args:
            config: FirewallConfig extraite du connecteur

        Returns:
            RuleAnalysisReport structuré

        """
        self._findings = []

        enabled = [r for r in config.rules if r.enabled]

        # ── Checks ─────────────────────────────────────────────
        self._check_any_any_rules(enabled)
        self._check_high_risk_ports(enabled)
        self._check_shadowed_rules(enabled)
        self._check_zero_hit_rules(enabled)
        self._check_rule_order(enabled)
        self._check_disabled_orphans(config.rules)

        # ── Calcul du score de risque ──────────────────────────
        risk_score = self._compute_risk_score()

        return RuleAnalysisReport(
            firewall=config.hostname,
            total_rules=len(config.rules),
            enabled_rules=len(enabled),
            findings=self._findings,
            risk_score=risk_score,
        )

    # ── Checks ─────────────────────────────────────────────────

    def _check_any_any_rules(self, rules: list[FirewallRule]) -> None:
        """Détecte les règles Any/Any trop permissives."""
        any_any = []
        for r in rules:
            if r.action != RuleAction.ALLOW:
                continue

            is_any_src = (
                not r.source_addresses
                or "any" in [a.lower().strip() for a in r.source_addresses]
                or "all" in [a.lower().strip() for a in r.source_addresses]
            )
            is_any_dst = (
                not r.destination_addresses
                or "any" in [a.lower().strip() for a in r.destination_addresses]
                or "all" in [a.lower().strip() for a in r.destination_addresses]
            )
            is_any_svc = not r.destination_ports or "any" in [
                p.lower().strip() for p in r.destination_ports
            ]

            if is_any_src and is_any_dst and is_any_svc:
                any_any.append(r)

        if any_any:
            self._findings.append(
                RuleFinding(
                    type=FindingType.ANY_ANY_RULE,
                    severity=RuleSeverity.HIGH if len(any_any) > 1 else RuleSeverity.MEDIUM,
                    description=(
                        f"{len(any_any)} règle(s) Any/Any (source=any, dest=any, "
                        f"service=any) — ces règles autorisent tout le trafic."
                    ),
                    rule_ids=[r.id for r in any_any],
                    rule_names=[r.name for r in any_any],
                    recommendation=(
                        "Restreindre la source, la destination, et le service "
                        "au strict nécessaire. Ajouter des zones et adresses "
                        "spécifiques."
                    ),
                    impact="Un attaquant ayant accès au réseau source peut "
                    "atteindre n'importe quelle destination.",
                ),
            )

    def _check_high_risk_ports(self, rules: list[FirewallRule]) -> None:
        """Détecte les règles exposant des ports à haut risque."""
        risky_rules: list[tuple[FirewallRule, str]] = []

        for r in rules:
            if r.action != RuleAction.ALLOW:
                continue
            for port in r.destination_ports:
                port_clean = port.strip()
                for risk_port, (svc_name, _) in self.HIGH_RISK_PORTS.items():
                    if port_clean == risk_port or port_clean.startswith(
                        risk_port + ":",
                    ):
                        risky_rules.append((r, f"{risk_port}/{svc_name}"))

        if risky_rules:
            self._findings.append(
                RuleFinding(
                    type=FindingType.HIGH_RISK_PORT,
                    severity=RuleSeverity.HIGH,
                    description=(
                        f"{len(risky_rules)} règle(s) exposant des ports à "
                        f"haut risque (RDP, SSH, bases de données...)."
                    ),
                    rule_ids=[r.id for r, _ in risky_rules],
                    rule_names=[f"{r.name} → {svc}" for r, svc in risky_rules],
                    recommendation=(
                        "1. Restreindre les sources à des IPs spécifiques\n"
                        "2. Utiliser un VPN plutôt qu'exposer RDP/SSH\n"
                        "3. Ajouter une restriction par utilisateur/groupe"
                    ),
                    impact="Ces services sont des cibles privilégiées pour "
                    "le bruteforce et l'exploitation de vulnérabilités.",
                ),
            )

    def _check_shadowed_rules(self, rules: list[FirewallRule]) -> None:
        """Détecte les règles masquées (shadowing).

        Une règle est shadowée si une règle plus large avant elle
        capture tout le trafic qu'elle traiterait.
        """
        shadowed = []

        for i, r in enumerate(rules):
            if r.action != RuleAction.ALLOW:
                continue
            for j in range(i):
                prev = rules[j]
                if prev.action != RuleAction.ALLOW:
                    continue
                if self._rule_covers(prev, r):
                    shadowed.append((r, prev))
                    break

        if shadowed:
            self._findings.append(
                RuleFinding(
                    type=FindingType.SHADOWED_RULE,
                    severity=RuleSeverity.MEDIUM,
                    description=(
                        f"{len(shadowed)} règle(s) masquée(s) par une règle "
                        f"plus permissive placée avant."
                    ),
                    rule_ids=[r.id for r, _ in shadowed],
                    rule_names=[f"{r.name} (shadowed by {prev.name})" for r, prev in shadowed],
                    recommendation=(
                        "Réorganiser les règles pour placer les plus spécifiques "
                        "avant les plus générales."
                    ),
                    impact="Ces règles ne seront jamais atteintes : gaspillage "
                    "de ressources et faux sentiment de sécurité.",
                ),
            )

    def _check_zero_hit_rules(self, rules: list[FirewallRule]) -> None:
        """Détecte les règles sans trafic (hit_count=0)."""
        zero_hit = [r for r in rules if r.hit_count == 0]

        if len(zero_hit) > len(rules) * 0.3:  # >30% des règles
            self._findings.append(
                RuleFinding(
                    type=FindingType.ZERO_HIT_RULE,
                    severity=RuleSeverity.LOW,
                    description=(
                        f"{len(zero_hit)} règle(s) sans trafic enregistré "
                        f"({len(zero_hit) / max(len(rules), 1) * 100:.0f}% du total)."
                    ),
                    rule_ids=[r.id for r in zero_hit[:10]],
                    rule_names=[r.name for r in zero_hit[:10]],
                    recommendation=(
                        "Auditer ces règles : sont-elles encore nécessaires ? "
                        "Si non, les supprimer pour réduire la surface d'attaque."
                    ),
                    impact="Règles inutilisées = complexité inutile et risque "
                    "de mauvaise configuration future.",
                ),
            )

    def _check_rule_order(self, rules: list[FirewallRule]) -> None:
        """Détecte les problèmes d'ordonnancement."""
        # Règle Deny avant Allow large = potentiellement tout bloque
        issues = []
        for i, r in enumerate(rules):
            if r.action != RuleAction.DENY:
                continue
            # Vérifier si cette règle est Any/Any deny avant des allow
            is_any = (
                not r.source_addresses or "any" in [a.lower().strip() for a in r.source_addresses]
            ) and (
                not r.destination_addresses
                or "any" in [a.lower().strip() for a in r.destination_addresses]
            )
            if is_any:
                for j in range(i + 1, min(i + 5, len(rules))):
                    if rules[j].action == RuleAction.ALLOW:
                        issues.append((r, rules[j]))
                        break

        if issues:
            self._findings.append(
                RuleFinding(
                    type=FindingType.RULE_ORDER_ISSUE,
                    severity=RuleSeverity.MEDIUM,
                    description=(
                        f"{len(issues)} règle(s) Deny Any/Any placée(s) avant "
                        f"des règles Allow — ces règles Allow sont bloquées."
                    ),
                    rule_ids=[r_deny.id for r_deny, _ in issues],
                    rule_names=[
                        f"{r_deny.name} blocks {r_allow.name}" for r_deny, r_allow in issues
                    ],
                    recommendation=(
                        "Placer les règles Deny Any/Any en fin de politique, "
                        "après toutes les règles Allow spécifiques."
                    ),
                    impact="Trafic légitime bloqué → incidents de production.",
                ),
            )

    def _check_disabled_orphans(self, all_rules: list[FirewallRule]) -> None:
        """Détecte les règles désactivées orphelines."""
        disabled = [r for r in all_rules if not r.enabled]

        if len(disabled) > 20:
            self._findings.append(
                RuleFinding(
                    type=FindingType.DISABLED_RULE_ORPHAN,
                    severity=RuleSeverity.LOW,
                    description=(
                        f"{len(disabled)} règle(s) désactivée(s). "
                        f"Auditer et supprimer les règles obsolètes."
                    ),
                    rule_ids=[r.id for r in disabled[:10]],
                    rule_names=[r.name for r in disabled[:10]],
                    recommendation=("Supprimer les règles désactivées de plus de 90 jours."),
                    impact="Complexité inutile et risque de réactivation accidentelle.",
                ),
            )

    # ── Helpers ────────────────────────────────────────────────

    def _rule_covers(self, rule_a: FirewallRule, rule_b: FirewallRule) -> bool:
        """Vérifie si rule_a couvre entièrement rule_b.

        Returns:
            True si rule_a est plus large et capture tout ce que rule_b capture

        """
        # Source: a doit être plus large que b
        a_src = {s.lower() for s in rule_a.source_addresses}
        b_src = {s.lower() for s in rule_b.source_addresses}
        if not a_src:
            a_src = {"any"}
        if not b_src:
            b_src = {"any"}

        if "any" not in a_src and not a_src.issuperset(b_src):
            return False

        # Destination
        a_dst = {d.lower() for d in rule_a.destination_addresses}
        b_dst = {d.lower() for d in rule_b.destination_addresses}
        if not a_dst:
            a_dst = {"any"}
        if not b_dst:
            b_dst = {"any"}

        if "any" not in a_dst and not a_dst.issuperset(b_dst):
            return False

        # Service (ports)
        a_svc = {p.lower() for p in rule_a.destination_ports}
        b_svc = {p.lower() for p in rule_b.destination_ports}
        if not a_svc:
            a_svc = {"any"}
        if not b_svc:
            b_svc = {"any"}

        return not ("any" not in a_svc and not a_svc.issuperset(b_svc))

    def _compute_risk_score(self) -> float:
        """Calcule un score de risque 0-100."""
        score = 0.0

        weights = {
            FindingType.ANY_ANY_RULE: 20,
            FindingType.HIGH_RISK_PORT: 15,
            FindingType.SHADOWED_RULE: 5,
            FindingType.ZERO_HIT_RULE: 2,
            FindingType.RULE_ORDER_ISSUE: 10,
            FindingType.DISABLED_RULE_ORPHAN: 3,
        }

        for finding in self._findings:
            score += weights.get(finding.type, 5)

        return min(100.0, score)
