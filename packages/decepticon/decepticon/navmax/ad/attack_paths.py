"""AD Attack Paths — analyse IA des chemins d'attaque et rapports d'impact.

Utilise l'AIEngine pour transformer les données brutes du graphe d'attaque
en rapports compréhensibles avec :
- Identification des chemins critiques
- Score de risque et priorisation
- Impact business
- Suggestions de remédiation

Usage:
    analyzer = AttackPathAnalyzer(ai_engine)
    analysis = await analyzer.analyze(trust_graph)
    print(analysis.report)
"""

import json
from dataclasses import dataclass, field

import structlog

from decepticon.navmax.ai.providers.base import ModelTier

logger = structlog.get_logger(__name__)

# ── System Prompts ─────────────────────────────────────────────

ATTACK_PATH_SYSTEM = """You are a senior Active Directory security analyst specialized in attack path analysis.
You analyze BloodHound-style attack graphs and produce actionable intelligence.

CAPABILITIES:
- Identify critical attack paths from low-privilege users to Domain Admins
- Detect Kerberoasting, AS-REP Roasting, delegation abuse opportunities
- Assess cross-domain trust exploitation risks
- Prioritize findings by risk and business impact
- Suggest precise remediation steps

OUTPUT FORMAT: Valid JSON only, no markdown wrapping.
{
  "critical_paths": [
    {
      "name": "Path name",
      "source": "lowpriv_user",
      "target": "Domain Admins",
      "steps": ["Step 1", "Step 2"],
      "technique": "Kerberoasting + Group Nesting",
      "risk_score": 95,
      "business_impact": "Full domain compromise, access to financial data",
      "remediation": "Remove SPN from svc_account, review group membership"
    }
  ],
  "top_risks": [
    {"finding": "...", "severity": "critical", "affected_assets": 150}
  ],
  "exposed_users_count": 12,
  "kerberoastable_accounts_leading_to_da": 3,
  "cross_domain_risks": 1,
  "overall_risk_level": "CRITICAL",
  "executive_summary": "2-3 sentence summary for CISO"
}

RULES:
1. Be SPECIFIC — name actual accounts, groups, and hosts
2. Risk score 0-100: >80 = CRITICAL, 60-80 = HIGH, 40-60 = MEDIUM, <40 = LOW
3. Business impact must mention concrete assets (financial data, PII, IP...)
4. Remediation must be actionable (exact account names, exact GPOs)
5. NEVER recommend "monitor" as the only remediation — always suggest a config change"""


# ── Data Models ────────────────────────────────────────────────


@dataclass
class CriticalPath:
    """Un chemin d'attaque critique identifié par l'IA."""

    name: str = ""
    source: str = ""
    target: str = ""
    steps: list[str] = field(default_factory=list)
    technique: str = ""
    risk_score: float = 0.0
    business_impact: str = ""
    remediation: str = ""


@dataclass
class RiskFinding:
    """Un risque identifié."""

    finding: str = ""
    severity: str = "medium"  # critical, high, medium, low
    affected_assets: int = 0
    category: str = ""  # kerberoasting, delegation, trust, acl...


@dataclass
class AttackPathAnalysis:
    """Analyse complète des chemins d'attaque."""

    critical_paths: list[CriticalPath] = field(default_factory=list)
    top_risks: list[RiskFinding] = field(default_factory=list)
    exposed_users_count: int = 0
    kerberoastable_accounts_leading_to_da: int = 0
    cross_domain_risks: int = 0
    overall_risk_level: str = "UNKNOWN"
    executive_summary: str = ""
    raw_report: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def report(self) -> str:
        """Rapport textuel formaté."""
        lines = [
            "=" * 60,
            "  NAVMAX — ACTIVE DIRECTORY ATTACK PATH ANALYSIS",
            "=" * 60,
            "",
            f"  Overall Risk Level: {self.overall_risk_level}",
            f"  Exposed Users: {self.exposed_users_count}",
            f"  Kerberoastable → DA paths: {self.kerberoastable_accounts_leading_to_da}",
            f"  Cross-Domain Risks: {self.cross_domain_risks}",
            "",
            "  Executive Summary:",
            f"  {self.executive_summary}",
            "",
        ]

        if self.critical_paths:
            lines.append("-" * 60)
            lines.append("  CRITICAL ATTACK PATHS")
            lines.append("-" * 60)
            for i, path in enumerate(self.critical_paths, 1):
                lines.append(f"  [{i}] {path.name} (Score: {path.risk_score:.0f}/100)")
                lines.append(f"      {path.source} → {path.target}")
                lines.append(f"      Technique: {path.technique}")
                for j, step in enumerate(path.steps, 1):
                    lines.append(f"        Step {j}: {step}")
                lines.append(f"      Business Impact: {path.business_impact}")
                lines.append(f"      Remediation: {path.remediation}")
                lines.append("")

        if self.top_risks:
            lines.append("-" * 60)
            lines.append("  TOP RISKS")
            lines.append("-" * 60)
            for risk in self.top_risks:
                severity_marker = {
                    "critical": "🔴 CRITICAL",
                    "high": "🟠 HIGH",
                    "medium": "🟡 MEDIUM",
                    "low": "🟢 LOW",
                }.get(risk.severity, risk.severity.upper())
                lines.append(f"  {severity_marker}: {risk.finding}")
                if risk.affected_assets:
                    lines.append(f"    Affected assets: {risk.affected_assets}")
                lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)


# ── Analyseur ──────────────────────────────────────────────────


class AttackPathAnalyzer:
    """Analyseur IA des chemins d'attaque AD.

    Prend un ADTrustGraph, interroge l'IA pour produire une analyse
    structurée avec priorités et remédiations.

    Usage:
        analyzer = AttackPathAnalyzer(ai_engine)
        analysis = await analyzer.analyze(trust_graph)
        print(analysis.report)
    """

    def __init__(self, ai_engine=None) -> None:
        """Args:
        ai_engine: AIEngine instance (optionnel — mode dégradé sans IA).

        """
        self.ai = ai_engine

    async def analyze(self, trust_graph) -> AttackPathAnalysis:
        """Analyse complète d'un graphe d'attaque AD.

        Args:
            trust_graph: ADTrustGraph déjà construit

        Returns:
            AttackPathAnalysis avec le rapport structuré

        """
        # ── Collecte des données brutes ─────────────────────────
        context = self._build_analysis_context(trust_graph)

        # ── Analyse IA (ou fallback) ────────────────────────────
        if self.ai:
            try:
                result = await self.ai.generate(
                    prompt=self._build_prompt(context),
                    tier=ModelTier.MEDIUM,
                    system=ATTACK_PATH_SYSTEM,
                    temperature=0.2,
                    max_tokens=4096,
                    json_mode=True,
                )
                return self._parse_ai_response(result.text, context)
            except Exception as e:
                logger.exception("ai_analysis_failed", error=str(e))
                return self._fallback_analysis(trust_graph, context, str(e))

        return self._fallback_analysis(trust_graph, context)

    # ── Collecte de contexte ────────────────────────────────────

    def _build_analysis_context(self, trust_graph) -> dict:
        """Construit le dictionnaire de contexte pour l'analyse."""
        context = {
            "domain": trust_graph._domain,
            "node_count": trust_graph.node_count,
            "edge_count": trust_graph.edge_count,
        }

        # Domain Admins effectifs
        da_list = trust_graph.get_effective_domain_admins()
        context["effective_domain_admins"] = da_list[:20]
        context["effective_domain_admins_count"] = len(da_list)

        # Chemins Kerberoastable
        kerb_paths = trust_graph.find_kerberoastable_paths()
        context["kerberoastable_paths"] = []
        for p in kerb_paths[:10]:
            context["kerberoastable_paths"].append(
                {
                    "path_labels": p.path_labels,
                    "length": p.length,
                    "risk_score": p.risk_score,
                },
            )
        context["kerberoastable_paths_count"] = len(kerb_paths)

        # Utilisateurs les plus exposés
        exposed = trust_graph.find_most_exposed_users(top_n=10)
        context["most_exposed_users"] = exposed

        # Cibles haute valeur
        hv_targets = trust_graph.get_high_value_targets()
        context["high_value_targets"] = [
            {"name": t.name, "type": t.type, "domain": t.domain} for t in hv_targets[:20]
        ]
        context["high_value_targets_count"] = len(hv_targets)

        # Users AS-REP roastable
        asrep_targets = trust_graph.find_asrep_roastable_targets()
        context["asrep_roastable_count"] = len(asrep_targets)
        context["asrep_roastable_sample"] = asrep_targets[:10]

        # Délégation non contrainte
        unconstrained = trust_graph.find_unconstrained_delegation_hosts()
        context["unconstrained_delegation_count"] = len(unconstrained)
        context["unconstrained_delegation_sample"] = unconstrained[:10]

        # Chemins cross-domain
        cross_paths = trust_graph.find_cross_domain_attack_paths()
        context["cross_domain_paths_count"] = len(cross_paths)

        # Résumé
        context["summary"] = trust_graph.summary()

        return context

    def _build_prompt(self, context: dict) -> str:
        """Construit le prompt pour l'IA."""
        return f"""Analyze this Active Directory attack graph and produce a structured JSON report.

DOMAIN: {context.get("domain", "Unknown")}

GRAPH STATS:
- Nodes: {context.get("node_count", 0)}
- Edges: {context.get("edge_count", 0)}
- Effective Domain Admins: {context.get("effective_domain_admins_count", 0)}
- Kerberoastable attack paths: {context.get("kerberoastable_paths_count", 0)}
- AS-REP Roastable accounts: {context.get("asrep_roastable_count", 0)}
- Unconstrained delegation hosts: {context.get("unconstrained_delegation_count", 0)}
- Cross-domain attack paths: {context.get("cross_domain_paths_count", 0)}
- High-value targets: {context.get("high_value_targets_count", 0)}

EFFECTIVE DOMAIN ADMINS (top 20):
{json.dumps(context.get("effective_domain_admins", []), indent=2)}

KERBEROASTABLE PATHS TO DA (top 10):
{json.dumps(context.get("kerberoastable_paths", []), indent=2)}

MOST EXPOSED USERS (ranked by path count to DA):
{json.dumps(context.get("most_exposed_users", []), indent=2)}

HIGH-VALUE TARGETS:
{json.dumps(context.get("high_value_targets", []), indent=2)}

UNCONSTRAINED DELEGATION HOSTS:
{json.dumps(context.get("unconstrained_delegation_sample", []), indent=2)}

AS-REP ROASTABLE ACCOUNTS:
{json.dumps(context.get("asrep_roastable_sample", []), indent=2)}

Based on this data, identify the most critical attack paths, prioritize risks,
and suggest concrete remediation steps. Output only valid JSON."""

    # ── Parsing de la réponse IA ────────────────────────────────

    def _parse_ai_response(
        self,
        response: str,
        context: dict,
    ) -> AttackPathAnalysis:
        """Parse la réponse JSON de l'IA en AttackPathAnalysis."""
        json_str = self._extract_json(response)

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            logger.warning("ai_response_parse_failed", error=str(e))
            return self._fallback_analysis(None, context, f"JSON parse error: {e}")

        critical_paths = []
        for cp in data.get("critical_paths", []):
            critical_paths.append(
                CriticalPath(
                    name=cp.get("name", "Unnamed path"),
                    source=cp.get("source", "?"),
                    target=cp.get("target", "?"),
                    steps=cp.get("steps", []),
                    technique=cp.get("technique", "Unknown"),
                    risk_score=float(cp.get("risk_score", 0)),
                    business_impact=cp.get("business_impact", ""),
                    remediation=cp.get("remediation", ""),
                ),
            )

        risks = []
        for r in data.get("top_risks", []):
            risks.append(
                RiskFinding(
                    finding=r.get("finding", ""),
                    severity=r.get("severity", "medium"),
                    affected_assets=int(r.get("affected_assets", 0)),
                    category=r.get("category", ""),
                ),
            )

        return AttackPathAnalysis(
            critical_paths=critical_paths,
            top_risks=risks,
            exposed_users_count=int(
                data.get("exposed_users_count", len(context.get("most_exposed_users", []))),
            ),
            kerberoastable_accounts_leading_to_da=int(
                data.get(
                    "kerberoastable_accounts_leading_to_da",
                    context.get("kerberoastable_paths_count", 0),
                ),
            ),
            cross_domain_risks=int(
                data.get("cross_domain_risks", context.get("cross_domain_paths_count", 0)),
            ),
            overall_risk_level=data.get("overall_risk_level", "UNKNOWN"),
            executive_summary=data.get("executive_summary", "No summary available."),
            raw_report=response,
        )

    # ── Fallback (sans IA) ──────────────────────────────────────

    def _fallback_analysis(
        self,
        trust_graph,
        context: dict | None = None,
        error: str = "",
    ) -> AttackPathAnalysis:
        """Analyse dégradée sans IA — purement algorithmique."""
        ctx = context or {}

        errors = [error] if error else []

        # Niveau de risque global
        kerb_count = ctx.get("kerberoastable_paths_count", 0)
        exposed_count = len(ctx.get("most_exposed_users", []))
        cross_count = ctx.get("cross_domain_paths_count", 0)
        unconstrained_count = ctx.get("unconstrained_delegation_count", 0)
        asrep_count = ctx.get("asrep_roastable_count", 0)

        if kerb_count >= 3 or cross_count >= 2:
            risk_level = "CRITICAL"
        elif kerb_count >= 1 or cross_count >= 1 or unconstrained_count >= 3:
            risk_level = "HIGH"
        elif exposed_count >= 5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Chemins critiques (algorithmiques)
        critical_paths = []
        if trust_graph:
            for p in trust_graph.find_kerberoastable_paths()[:3]:
                critical_paths.append(
                    CriticalPath(
                        name=f"Kerberoasting path via {p.path_labels[0]}",
                        source=p.path_labels[0],
                        target=p.path_labels[-1],
                        steps=[
                            f"{p.path_labels[i]} → {p.path_labels[i + 1]}"
                            for i in range(len(p.path_labels) - 1)
                        ],
                        technique="Kerberoasting + Group Nesting",
                        risk_score=p.risk_score,
                        business_impact=(
                            "Compromission complète du domaine possible via "
                            "cassage du hash Kerberos du compte de service"
                        ),
                        remediation=(
                            f"Supprimer les SPNs de {p.path_labels[0]} ou "
                            f"renforcer son mot de passe (30+ caractères)"
                        ),
                    ),
                )

            for p in trust_graph.find_cross_domain_attack_paths()[:2]:
                critical_paths.append(
                    CriticalPath(
                        name=f"Cross-domain path via {p.path_labels[0]}",
                        source=p.path_labels[0],
                        target=p.path_labels[-1],
                        steps=[
                            f"{p.path_labels[i]} → {p.path_labels[i + 1]}"
                            for i in range(len(p.path_labels) - 1)
                        ],
                        technique="Cross-Domain Trust Exploitation",
                        risk_score=p.risk_score,
                        business_impact=(
                            "Escalade inter-domaine possible via la relation de confiance"
                        ),
                        remediation=(
                            "Activer le SID filtering sur la relation de confiance, "
                            "réduire les privilèges cross-domaine"
                        ),
                    ),
                )

        # Risques
        risks = []
        if kerb_count > 0:
            risks.append(
                RiskFinding(
                    finding=f"{kerb_count} comptes Kerberoastable mènent aux Domain Admins",
                    severity="critical",
                    affected_assets=kerb_count,
                    category="kerberoasting",
                ),
            )
        if asrep_count > 0:
            risks.append(
                RiskFinding(
                    finding=f"{asrep_count} comptes vulnérables à l'AS-REP Roasting",
                    severity="high" if asrep_count > 1 else "medium",
                    affected_assets=asrep_count,
                    category="asrep_roasting",
                ),
            )
        if unconstrained_count > 0:
            risks.append(
                RiskFinding(
                    finding=f"{unconstrained_count} machines avec délégation non contrainte",
                    severity="high",
                    affected_assets=unconstrained_count,
                    category="delegation",
                ),
            )
        if cross_count > 0:
            risks.append(
                RiskFinding(
                    finding=f"{cross_count} chemins d'attaque inter-domaines identifiés",
                    severity="critical" if cross_count >= 2 else "high",
                    affected_assets=cross_count + 1,
                    category="cross_domain",
                ),
            )

        # Résumé exécutif
        if risk_level == "CRITICAL":
            exec_summary = (
                f"Domaine {ctx.get('domain', 'inconnu')} en état CRITIQUE. "
                f"{kerb_count} chemins Kerberoasting directs vers Domain Admins "
                f"et {cross_count} risques inter-domaines nécessitent une "
                f"remédiation immédiate."
            )
        elif risk_level == "HIGH":
            exec_summary = (
                f"Domaine {ctx.get('domain', 'inconnu')} présente des risques "
                f"élevés. {exposed_count} utilisateurs ont un chemin vers "
                f"Domain Admins, dont {kerb_count} via Kerberoasting."
            )
        else:
            exec_summary = (
                f"Domaine {ctx.get('domain', 'inconnu')} en état {risk_level}. "
                f"Pas de chemin d'attaque critique immédiat détecté."
            )

        return AttackPathAnalysis(
            critical_paths=critical_paths,
            top_risks=risks,
            exposed_users_count=exposed_count,
            kerberoastable_accounts_leading_to_da=kerb_count,
            cross_domain_risks=cross_count,
            overall_risk_level=risk_level,
            executive_summary=exec_summary,
            errors=errors,
        )

    def _extract_json(self, text: str) -> str:
        """Extrait le JSON d'une réponse formatée (markdown ou autre)."""
        text = text.strip()

        if "```json" in text:
            parts = text.split("```json", 1)[1].split("```", 1)
            return parts[0].strip()
        if "```" in text:
            parts = text.split("```", 1)[1].split("```", 1)
            return parts[0].strip()

        first_brace = text.find("{")
        if first_brace >= 0:
            text = text[first_brace:]
            depth = 0
            for i, c in enumerate(text):
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        return text[: i + 1]

        return text


# ── Fonction utilitaire ────────────────────────────────────────


async def quick_analysis(
    trust_graph,
    ai_engine=None,
) -> AttackPathAnalysis:
    """Analyse rapide en une ligne.

    Usage:
        graph = ADTrustGraph()
        graph.build(domain_map)
        analysis = await quick_analysis(graph)
        print(analysis.report)
    """
    analyzer = AttackPathAnalyzer(ai_engine)
    return await analyzer.analyze(trust_graph)
