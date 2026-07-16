---
name: navmax-firewall
description: NavMAX Firewall — connecteurs FortiGate & StormShield, analyse de règles (shadowing, Any/Any), corrélation AD × firewall.
metadata:
  subdomain: firewall
  when_to_use: "navmax firewall fortigate stormshield rule analysis shadowing correlation ad firewall infrastructure"
  navmax_module: decepticon.navmax.firewall
  mitre_attack:
    - T1046
    - T1069.002
---

# NavMAX Firewall Wrapper

## Module : `decepticon.navmax.firewall`

Connecteurs API pour équipements réseau FortiGate et StormShield,
analyse de règles de pare-feu, et corrélation AD × infrastructure.

## Classes & utilitaires exposés

| Classe / Fonction | Rôle |
|---|---|
| `FirewallConnector` (base) | Classe de base pour connecteurs firewall |
| `FortiGateConnector` | Connecteur FortiGate (REST API) — vérification CVE, règles, interfaces |
| `StormShieldConnector` | Connecteur StormShield SNS (CONF API) |
| `RuleAnalyzer` | Analyse de règles — shadowing, redondance, Any/Any, ports à risque |
| `ADCorrelator` | Corrélation AD × règles firewall (vue unifiée infrastructure) |
| `RuleFinding` | Résultat d'analyse de règle (type, sévérité) |
| `CorrelationFinding` | Résultat de corrélation AD × firewall |
| `RuleAnalysisReport` | Rapport complet d'analyse de règles |

## Workflow typique

```python
from decepticon.navmax.firewall import FortiGateConnector, RuleAnalyzer

# 1. Connexion FortiGate
fg = FortiGateConnector(host="192.168.1.1", api_token="***")
fg.connect()

# 2. Récupération des règles
rules = fg.get_firewall_rules()

# 3. Analyse des règles
analyzer = RuleAnalyzer(rules)
report = analyzer.analyze()
for finding in report.findings:
    print(finding.severity, finding.finding_type, finding.description)

# 4. Shadowing detection
shadowed = analyzer.find_shadowed_rules()

# 5. Corrélation AD × firewall
from decepticon.navmax.firewall import ADCorrelator
corr = ADCorrelator(ad_connector=ad_conn, fw_connector=fg)
corr_report = corr.correlate()
```

## Dépendances

- `requests` pour API REST FortiGate
- `paramiko` (optionnel) pour accès SSH StormShield
- Connexion AD (via `navmax-ad` ou Decepticon AD tools)
