---
name: navmax-ad
description: NavMAX AD — Active Directory connector, enumerator, trust graph, attack paths, ADCS scanner, BloodHound export, password spray, SMB scanner, Certipy & Responder wrappers.
metadata:
  subdomain: active-directory
  when_to_use: "navmax ad active directory domain enum enumeration trust attack path adcs bloodhound certipy password spray smb responder"
  navmax_module: decepticon.navmax.ad
  mitre_attack:
    - T1078.002
    - T1558.003
    - T1558.004
    - T1003.006
    - T1649
    - T1087.002
    - T1069.002
    - T1482
---

# NavMAX AD Wrapper

## Module : `decepticon.navmax.ad`

Wrapper complet des modules Active Directory NavMAX dans Decepticon.

## Classes & utilitaires exposés

| Classe / Fonction | Rôle |
|---|---|
| `ADConnector` | Connecteur LDAP/SMB — auth, domain info, users, groups, computers, GPO, OU, trusts |
| `ADEnumerator` | Énumération complète d'un domaine (users, groups, computers, DC…) |
| `ADTrustGraph` | Graphe des relations de confiance inter-domaines/forêts |
| `AttackPathAnalyzer` | Analyse de chemins d'attaque depuis un nœud source vers cible |
| `ADCSSCanner` | Scan des Certificate Templates vulnérables (ESC1-ESC8) |
| `BloodHoundExporter` | Export JSON/CSV compatible BloodHound CE |
| `PasswordSprayer` | Password spraying avec wordlists saisonnières, lockout detection |
| `ADVulnScanner` | Scan de vulnérabilités AD (SMB signing, LDAP signing, Kerberoastable…) |
| `ADSMSScanner` | Scan SMB (signing, shares, OS version) par sous-réseau |
| `CertipyWrapper` | Interface certipy (ESC1-ESC4, trouver des templates vulnérables) |
| `ResponderWrapper` | Wrapper Responder — capture NTLM hashes |
| `quick_enumeration` | Énumération rapide (wrapper one-shot) |
| `quick_vuln_scan` | Scan vulnérabilités rapide |
| `quick_adcs_scan` | Scan ADCS rapide |
| `quick_smb_scan` | Scan SMB rapide |

## Workflow typique

```python
from decepticon.navmax.ad import ADConnector, ADEnumerator, quick_enumeration

# 1. Connexion
conn = ADConnector(domain="corp.local", user="DOMAIN\\user", password="***")
conn.connect()

# 2. Énumération
enum = ADEnumerator(conn)
report = enum.enumerate_all()
print(report.domain, report.users_count, report.computers_count)

# 3. One-shot rapide
quick = quick_enumeration(domain="corp.local", username="user", password="***")

# 4. Trust graph
from decepticon.navmax.ad import ADTrustGraph
g = ADTrustGraph(conn)
paths = g.find_attack_paths(source="CORP\\user", target="CORP\\Domain Admins")

# 5. Password spray
from decepticon.navmax.ad import PasswordSprayer
sprayer = PasswordSprayer(domain="corp.local")
results = sprayer.spray(users=["user1", "user2"], password="Passw0rd!")
```

## Dépendances

- `ldap3` pour connexion LDAP
- `impacket` pour opérations SMB
- `bloodhound` (python) pour export BH
- `certipy` (optionnel) pour ADCS
- `responder` (optionnel, outil système)
