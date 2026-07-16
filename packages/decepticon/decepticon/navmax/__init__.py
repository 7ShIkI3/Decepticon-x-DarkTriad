"""NavMAX — Modules de cybersécurité intégrés dans Decepticon.

Package miroir des modules NavMAX (7ShIkI3) copiés pour utilisation
native dans l'écosystème Decepticon (PurpleAILAB).

Modules disponibles :
  - ad         : Active Directory (connector, enumerator, attack_paths, ADCS, BloodHound…)
  - ai         : Moteur IA, sélecteur de modèles, react_agent, providers
  - cloud      : Scanner cloud (AWS/Azure/GCP)
  - core       : Configuration, logging, exceptions, HTTP client, plugins
  - cracking   : Wrappers hashcat, john, hydra + wordlists
  - db         : Base de données SQLAlchemy (engine, models)
  - exploit    : Framework d'exploitation (Metasploit-like) + modules intégrés
  - firewall   : Connecteurs FortiGate, StormShield + analyse de règles
  - osint      : OSINT (DNS, WHOIS, SSL, Shodan, Censys) + graphe d'entités
  - proxy      : Proxy MITM, interceptor, fuzzer, intruder, crawler
  - scanner    : Scanner TCP, Nmap, Nuclei, contextual, fingerprint
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Sous-modules — importation paresseuse (lazy) via strings pour éviter
# les dépendances circulaires et les ralentissements au démarrage.
# ---------------------------------------------------------------------------

# AD
from decepticon.navmax import ad as _ad  # noqa: F401

# AI
from decepticon.navmax import ai as _ai  # noqa: F401

# Cloud
from decepticon.navmax import cloud as _cloud  # noqa: F401

# Core
from decepticon.navmax import core as _core  # noqa: F401

# Cracking
from decepticon.navmax import cracking as _cracking  # noqa: F401

# DB
from decepticon.navmax import db as _db  # noqa: F401

# Exploit
from decepticon.navmax import exploit as _exploit  # noqa: F401

# Firewall
from decepticon.navmax import firewall as _firewall  # noqa: F401

# OSINT
from decepticon.navmax import osint as _osint  # noqa: F401

# Proxy
from decepticon.navmax import proxy as _proxy  # noqa: F401

# Scanner
from decepticon.navmax import scanner as _scanner  # noqa: F401

__all__ = [
    "ad",
    "ai",
    "cloud",
    "core",
    "cracking",
    "db",
    "exploit",
    "firewall",
    "osint",
    "proxy",
    "scanner",
]
