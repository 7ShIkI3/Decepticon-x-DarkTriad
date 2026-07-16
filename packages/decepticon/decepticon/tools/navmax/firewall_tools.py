"""LangChain ``@tool`` wrappers for ``decepticon.navmax.firewall``.

Each tool follows the Decepticon convention: returns a JSON string so the
agent can parse it deterministically.

Tools
-----
- **fortigate_connect** / **fortigate_get_config** / **fortigate_analyze**
- **stormshield_connect** / **stormshield_get_config** / **stormshield_analyze**
- **firewall_rule_analyzer** — analyse générique de règles
- **firewall_compare_configs** — comparaison deux configurations
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from decepticon.navmax.firewall.fortigate import FortiGateConnector
from decepticon.navmax.firewall.stormshield import StormShieldConnector
from decepticon.navmax.firewall.rule_analyzer import RuleAnalyzer, RuleAnalysisReport

# ── Helpers ──────────────────────────────────────────────────────────────────


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)


def _findings_to_dict(report: RuleAnalysisReport) -> dict:
    """Sérialise un RuleAnalysisReport."""
    return {
        "firewall": report.firewall,
        "total_rules": report.total_rules,
        "enabled_rules": report.enabled_rules,
        "risk_score": report.risk_score,
        "findings": [
            {
                "type": f.type.value,
                "severity": f.severity.value,
                "description": f.description,
                "rule_ids": f.rule_ids,
                "rule_names": f.rule_names,
                "recommendation": f.recommendation,
                "impact": f.impact,
            }
            for f in report.findings
        ],
    }


async def _build_fortigate(
    host: str,
    api_key: str = "",
    username: str = "",
    password: str = "",
    verify_ssl: bool = False,
    timeout: float = 30.0,
) -> tuple[FortiGateConnector | None, str]:
    """Construit et connecte un FortiGateConnector."""
    fgt = FortiGateConnector(
        host=host,
        api_key=api_key,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        timeout=timeout,
    )
    ok = await fgt.connect()
    if not ok:
        return None, f"Échec de connexion à FortiGate {host}"
    return fgt, ""


async def _build_stormshield(
    host: str,
    api_key: str = "",
    username: str = "",
    password: str = "",
    verify_ssl: bool = False,
    timeout: float = 30.0,
) -> tuple[StormShieldConnector | None, str]:
    """Construit et connecte un StormShieldConnector."""
    sns = StormShieldConnector(
        host=host,
        api_key=api_key,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        timeout=timeout,
    )
    ok = await sns.connect()
    if not ok:
        return None, f"Échec de connexion à StormShield {host}"
    return sns, ""


# ── Input schemas ────────────────────────────────────────────────────────────


class FirewallAuthInput(BaseModel):
    """Authentification à un firewall."""

    host: str = Field(..., description="Adresse IP ou nom d'hôte du firewall")
    api_key: str = Field("", description="Clé API (prioritaire sur username/password)")
    username: str = Field("", description="Nom d'utilisateur")
    password: str = Field("", description="Mot de passe")
    verify_ssl: bool = Field(False, description="Vérifier le certificat SSL")
    timeout: float = Field(30.0, description="Timeout de connexion (secondes)", ge=5)


class FirewallConfigInput(FirewallAuthInput):
    """Paramètres pour l'extraction de configuration firewall."""


class FirewallAnalyzeInput(FirewallConfigInput):
    """Paramètres pour l'analyse de règles firewall."""


class RuleAnalyzerInput(BaseModel):
    """Analyse générique de règles firewall (sans connexion)."""

    rules_json: str = Field(
        ...,
        description=(
            "Liste JSON de règles avec les champs : "
            "id, name, action (allow/deny), source_addresses, "
            "destination_addresses, destination_ports, enabled, position"
        ),
    )
    firewall_name: str = Field("unknown", description="Nom du firewall pour le rapport")


class CompareConfigsInput(BaseModel):
    """Comparaison de deux configurations firewall."""

    config_a_json: str = Field(
        ..., description="Première configuration firewall (JSON)",
    )
    config_b_json: str = Field(
        ..., description="Seconde configuration firewall (JSON)",
    )


# ── Tools: FortiGate ─────────────────────────────────────────────────────────


@tool(args_schema=FirewallAuthInput)
async def fortigate_connect(
    host: str,
    api_key: str = "",
    username: str = "",
    password: str = "",
    verify_ssl: bool = False,
    timeout: float = 30.0,
) -> str:
    """Tester la connexion à un firewall FortiGate via l'API REST FortiOS.

    Établit une connexion de test, vérifie l'authentification et
    retourne les informations système (hostname, modèle, version).

    Args:
        host: Adresse IP du FortiGate
        api_key: Clé API FortiOS (Bearer)
        username: Nom d'utilisateur (si pas d'api_key)
        password: Mot de passe (si pas d'api_key)
        verify_ssl: Vérifier le certificat SSL
        timeout: Timeout de connexion (secondes)
    """
    fgt, err = await _build_fortigate(
        host=host,
        api_key=api_key,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        timeout=timeout,
    )
    if err:
        return _json({"error": err})

    info = await fgt.get_system_info()
    await fgt.close()
    return _json({"connected": True, "system_info": info})


@tool(args_schema=FirewallConfigInput)
async def fortigate_get_config(
    host: str,
    api_key: str = "",
    username: str = "",
    password: str = "",
    verify_ssl: bool = False,
    timeout: float = 30.0,
) -> str:
    """Extraire la configuration complète d'un FortiGate.

    Récupère les règles firewall, interfaces, objets adresse,
    utilisateurs administrateurs, et vérifie les CVEs connues
    (CVE-2026-35616, CVE-2022-40684, CVE-2024-21762, etc.).

    Args:
        host: Adresse IP du FortiGate
        api_key: Clé API FortiOS
        username: Utilisateur admin
        password: Mot de passe admin
        verify_ssl: Vérifier le certificat
        timeout: Timeout de connexion
    """
    fgt, err = await _build_fortigate(
        host=host,
        api_key=api_key,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        timeout=timeout,
    )
    if err:
        return _json({"error": err})

    try:
        config = await fgt.get_full_config()
        return _json({
            "hostname": config.hostname,
            "vendor": config.vendor.value,
            "model": config.model,
            "version": config.version,
            "serial": config.serial,
            "rules": [
                {
                    "id": r.id,
                    "name": r.name,
                    "action": r.action.value,
                    "source_zones": r.source_zones,
                    "source_addresses": r.source_addresses,
                    "destination_zones": r.destination_zones,
                    "destination_addresses": r.destination_addresses,
                    "destination_ports": r.destination_ports,
                    "enabled": r.enabled,
                    "position": r.position,
                    "description": r.description,
                }
                for r in config.rules
            ],
            "interfaces": [
                {
                    "name": i.name,
                    "ip": i.ip_address,
                    "zone": i.zone,
                    "enabled": i.enabled,
                    "type": i.type,
                }
                for i in config.interfaces
            ],
            "addresses": [
                {"name": a.name, "value": a.value, "type": a.type}
                for a in config.addresses
            ],
            "users": [
                {"name": u.name, "profile": u.profile, "type": u.type}
                for u in config.users
            ],
            "cve_checks": [
                {
                    "cve_id": c.cve_id,
                    "title": c.title,
                    "severity": c.severity,
                    "vulnerable": c.vulnerable,
                    "remediation": c.remediation,
                }
                for c in config.cve_checks
            ],
            "summary": config.summary(),
        })
    finally:
        await fgt.close()


@tool(args_schema=FirewallAnalyzeInput)
async def fortigate_analyze(
    host: str,
    api_key: str = "",
    username: str = "",
    password: str = "",
    verify_ssl: bool = False,
    timeout: float = 30.0,
) -> str:
    """Analyser les règles d'un FortiGate pour détecter les anomalies.

    Détecte : règles Any/Any, shadowing, ports à risque,
    règles inutilisées, problèmes d'ordonnancement.

    Args:
        host: Adresse IP du FortiGate
        api_key: Clé API FortiOS
        username: Utilisateur admin
        password: Mot de passe admin
        verify_ssl: Vérifier le certificat
        timeout: Timeout de connexion
    """
    fgt, err = await _build_fortigate(
        host=host,
        api_key=api_key,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        timeout=timeout,
    )
    if err:
        return _json({"error": err})

    try:
        config = await fgt.get_full_config()
        analyzer = RuleAnalyzer()
        report = analyzer.analyze(config)
        return _json(_findings_to_dict(report))
    finally:
        await fgt.close()


# ── Tools: StormShield ───────────────────────────────────────────────────────


@tool(args_schema=FirewallAuthInput)
async def stormshield_connect(
    host: str,
    api_key: str = "",
    username: str = "",
    password: str = "",
    verify_ssl: bool = False,
    timeout: float = 30.0,
) -> str:
    """Tester la connexion à un firewall StormShield SNS via l'API CONF.

    Établit une connexion de test à l'API StormShield SNS et
    retourne les informations système (version, hostname).

    Args:
        host: Adresse IP du StormShield
        api_key: Clé API SNS (X-API-Key)
        username: Nom d'utilisateur (si pas d'api_key)
        password: Mot de passe (si pas d'api_key)
        verify_ssl: Vérifier le certificat SSL
        timeout: Timeout de connexion (secondes)
    """
    sns, err = await _build_stormshield(
        host=host,
        api_key=api_key,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        timeout=timeout,
    )
    if err:
        return _json({"error": err})

    info = await sns.get_system_info()
    await sns.close()
    return _json({"connected": True, "system_info": info})


@tool(args_schema=FirewallConfigInput)
async def stormshield_get_config(
    host: str,
    api_key: str = "",
    username: str = "",
    password: str = "",
    verify_ssl: bool = False,
    timeout: float = 30.0,
) -> str:
    """Extraire la configuration complète d'un StormShield SNS.

    Récupère les règles de filtrage, interfaces, objets réseau,
    administrateurs, et vérifie les CVEs connues StormShield.

    Args:
        host: Adresse IP du StormShield
        api_key: Clé API SNS
        username: Utilisateur admin
        password: Mot de passe admin
        verify_ssl: Vérifier le certificat
        timeout: Timeout de connexion
    """
    sns, err = await _build_stormshield(
        host=host,
        api_key=api_key,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        timeout=timeout,
    )
    if err:
        return _json({"error": err})

    try:
        config = await sns.get_full_config()
        return _json({
            "hostname": config.hostname,
            "vendor": config.vendor.value,
            "model": config.model,
            "version": config.version,
            "serial": config.serial,
            "rules": [
                {
                    "id": r.id,
                    "name": r.name,
                    "action": r.action.value,
                    "source_zones": r.source_zones,
                    "source_addresses": r.source_addresses,
                    "destination_zones": r.destination_zones,
                    "destination_addresses": r.destination_addresses,
                    "destination_ports": r.destination_ports,
                    "enabled": r.enabled,
                    "position": r.position,
                    "description": r.description,
                }
                for r in config.rules
            ],
            "interfaces": [
                {
                    "name": i.name,
                    "ip": i.ip_address,
                    "zone": i.zone,
                    "enabled": i.enabled,
                    "type": i.type,
                }
                for i in config.interfaces
            ],
            "addresses": [
                {"name": a.name, "value": a.value, "type": a.type}
                for a in config.addresses
            ],
            "users": [
                {"name": u.name, "profile": u.profile, "type": u.type}
                for u in config.users
            ],
            "cve_checks": [
                {
                    "cve_id": c.cve_id,
                    "title": c.title,
                    "severity": c.severity,
                    "vulnerable": c.vulnerable,
                    "remediation": c.remediation,
                }
                for c in config.cve_checks
            ],
            "summary": config.summary(),
        })
    finally:
        await sns.close()


@tool(args_schema=FirewallAnalyzeInput)
async def stormshield_analyze(
    host: str,
    api_key: str = "",
    username: str = "",
    password: str = "",
    verify_ssl: bool = False,
    timeout: float = 30.0,
) -> str:
    """Analyser les règles d'un StormShield SNS pour détecter les anomalies.

    Détecte : règles Any/Any, shadowing, ports à risque,
    règles inutilisées, problèmes d'ordonnancement.

    Args:
        host: Adresse IP du StormShield
        api_key: Clé API SNS
        username: Utilisateur admin
        password: Mot de passe admin
        verify_ssl: Vérifier le certificat
        timeout: Timeout de connexion
    """
    sns, err = await _build_stormshield(
        host=host,
        api_key=api_key,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        timeout=timeout,
    )
    if err:
        return _json({"error": err})

    try:
        config = await sns.get_full_config()
        analyzer = RuleAnalyzer()
        report = analyzer.analyze(config)
        return _json(_findings_to_dict(report))
    finally:
        await sns.close()


# ── Tools: Analyse générique ───────────────────────────────────────────────


@tool(args_schema=RuleAnalyzerInput)
def firewall_rule_analyzer(rules_json: str, firewall_name: str = "unknown") -> str:
    """Analyser une liste de règles firewall sans connexion directe.

    Prend une liste JSON de règles et applique les mêmes détections
    que les analyseurs vendor-spécifiques : Any/Any, ports à risque,
    shadowing, règles inutilisées, problèmes d'ordre.

    Args:
        rules_json: Liste JSON de règles
        firewall_name: Nom du firewall (pour le rapport)
    """
    try:
        rules_data = json.loads(rules_json)
    except (json.JSONDecodeError, ValueError) as exc:
        return _json({"error": f"JSON invalide : {exc}"})

    if not isinstance(rules_data, list):
        rules_data = [rules_data] if isinstance(rules_data, dict) else []

    # Construire une FirewallConfig minimaliste à partir des données
    from decepticon.navmax.firewall.base import (
        FirewallAddress,
        FirewallConfig,
        FirewallInterface,
        FirewallRule,
        FirewallUser,
        FirewallVendor,
        RuleAction,
    )

    rules: list[FirewallRule] = []
    for i, r in enumerate(rules_data):
        action_str = r.get("action", "deny")
        rules.append(
            FirewallRule(
                id=str(r.get("id", i)),
                name=r.get("name", f"rule-{i}"),
                action=RuleAction.ALLOW if action_str.lower() in ("allow", "accept", "pass") else RuleAction.DENY,
                source_zones=r.get("source_zones", []),
                source_addresses=r.get("source_addresses", []),
                destination_zones=r.get("destination_zones", []),
                destination_addresses=r.get("destination_addresses", []),
                destination_ports=r.get("destination_ports", []),
                enabled=r.get("enabled", True),
                position=r.get("position", i),
                hit_count=r.get("hit_count", 0),
                description=r.get("description", ""),
            ),
        )

    config = FirewallConfig(
        vendor=FirewallVendor.GENERIC,
        hostname=firewall_name,
        rules=rules,
    )

    analyzer = RuleAnalyzer()
    report = analyzer.analyze(config)
    return _json(_findings_to_dict(report))


@tool(args_schema=CompareConfigsInput)
def firewall_compare_configs(config_a_json: str, config_b_json: str) -> str:
    """Comparer deux configurations firewall et identifier les différences.

    Détecte : règles ajoutées/supprimées, changements d'action,
    différences de ports, de sources, de destinations.

    Args:
        config_a_json: Première configuration (JSON)
        config_b_json: Seconde configuration (JSON)
    """
    try:
        cfg_a = json.loads(config_a_json)
        cfg_b = json.loads(config_b_json)
    except (json.JSONDecodeError, ValueError) as exc:
        return _json({"error": f"JSON invalide : {exc}"})

    rules_a = cfg_a if isinstance(cfg_a, list) else cfg_a.get("rules", [])
    rules_b = cfg_b if isinstance(cfg_b, list) else cfg_b.get("rules", [])

    def _rule_key(r: dict) -> str:
        return r.get("id", "") or r.get("name", "")

    map_a = {_rule_key(r): r for r in rules_a}
    map_b = {_rule_key(r): r for r in rules_b}

    added: list[dict] = []
    removed: list[dict] = []
    modified: list[dict] = []

    keys_a = set(map_a)
    keys_b = set(map_b)

    for k in keys_b - keys_a:
        added.append(map_b[k])

    for k in keys_a - keys_b:
        removed.append(map_a[k])

    for k in keys_a & keys_b:
        ra = map_a[k]
        rb = map_b[k]
        diffs: dict[str, tuple[Any, Any]] = {}
        for field in ("action", "source_addresses", "destination_addresses", "destination_ports", "enabled"):
            va = ra.get(field)
            vb = rb.get(field)
            if va != vb:
                diffs[field] = (va, vb)
        if diffs:
            modified.append({"id": k, "name": rb.get("name", k), "differences": diffs})

    changes = {
        "added": {"count": len(added), "rules": [{"id": r.get("id"), "name": r.get("name")} for r in added[:20]]},
        "removed": {"count": len(removed), "rules": [{"id": r.get("id"), "name": r.get("name")} for r in removed[:20]]},
        "modified": {"count": len(modified), "rules": modified[:20]},
    }

    total_a = len(rules_a)
    total_b = len(rules_b)

    return _json({
        "summary": {
            "config_a_rules": total_a,
            "config_b_rules": total_b,
            "added": len(added),
            "removed": len(removed),
            "modified": len(modified),
        },
        "changes": changes,
    })


# ── Registre ─────────────────────────────────────────────────────────────────

FIREWALL_TOOLS = [
    fortigate_connect,
    fortigate_get_config,
    fortigate_analyze,
    stormshield_connect,
    stormshield_get_config,
    stormshield_analyze,
    firewall_rule_analyzer,
    firewall_compare_configs,
]
