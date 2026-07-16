"""Module Firewall — connecteurs API pour équipements réseau.

Fonctionnalités :
- Connecteurs FortiGate (REST API) avec vérification CVE
- Connecteurs StormShield SNS (CONF API)
- Analyse intelligente des règles (shadowing, Any/Any, ports à risque)
- Corrélation AD × règles firewall (vue unifiée infrastructure)
"""

from .base import (
    CVECheck,
    FirewallAddress,
    FirewallConfig,
    FirewallConnector,
    FirewallInterface,
    FirewallRule,
    FirewallUser,
    FirewallVendor,
    Protocol,
    RuleAction,
    RuleSeverity,
)
from .correlation import ADCorrelator, CorrelationFinding, CorrelationReport, CorrelationSeverity
from .fortigate import FortiGateConnector
from .rule_analyzer import FindingType, RuleAnalysisReport, RuleAnalyzer, RuleFinding
from .stormshield import StormShieldConnector

__all__ = [
    # Correlation
    "ADCorrelator",
    "CVECheck",
    "CorrelationFinding",
    "CorrelationReport",
    "CorrelationSeverity",
    "FindingType",
    "FirewallAddress",
    "FirewallConfig",
    # Base
    "FirewallConnector",
    "FirewallInterface",
    "FirewallRule",
    "FirewallUser",
    "FirewallVendor",
    # Connectors
    "FortiGateConnector",
    "Protocol",
    "RuleAction",
    "RuleAnalysisReport",
    # Analysis
    "RuleAnalyzer",
    "RuleFinding",
    "RuleSeverity",
    "StormShieldConnector",
]
