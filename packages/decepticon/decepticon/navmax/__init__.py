"""NavMAX — Modules de cybersécurité intégrés dans Decepticon.

Package miroir des modules NavMAX (7ShIkI3) copiés pour utilisation
native dans l'écosystème Decepticon (PurpleAILAB).

Les imports sont lazy — importer `decepticon.navmax` ne charge
pas les sous-modules lourds (aiohttp, impacket, ldap3, python-nmap).
Pour utiliser un module, importez-le directement :
    from decepticon.navmax.ad import ADConnector
    from decepticon.navmax.personality import NARCISSUS
"""

from __future__ import annotations

# Lazy submodule access — defers imports until attribute access.
# Adding a new module: add it to __getattr__ below + __dir__.


def __getattr__(name: str):
    _LAZY = {
        "ad": "decepticon.navmax.ad",
        "ai": "decepticon.navmax.ai",
        "cloud": "decepticon.navmax.cloud",
        "core": "decepticon.navmax.core",
        "cracking": "decepticon.navmax.cracking",
        "darktriad": "decepticon.navmax.darktriad",
        "db": "decepticon.navmax.db",
        "exploit": "decepticon.navmax.exploit",
        "firewall": "decepticon.navmax.firewall",
        "osint": "decepticon.navmax.osint",
        "personality": "decepticon.navmax.personality",
        "proxy": "decepticon.navmax.proxy",
        "scanner": "decepticon.navmax.scanner",
    }
    if name in _LAZY:
        import importlib

        mod = importlib.import_module(_LAZY[name])
        globals()[name] = mod
        return mod
    raise AttributeError(f"module 'decepticon.navmax' has no attribute '{name}'")


def __dir__() -> list[str]:
    return [
        "ad",
        "ai",
        "cloud",
        "core",
        "cracking",
        "darktriad",
        "db",
        "exploit",
        "firewall",
        "osint",
        "personality",
        "proxy",
        "scanner",
    ]
