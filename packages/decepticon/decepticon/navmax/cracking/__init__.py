"""Module Cracking — wrappers hashcat, john, hydra avec pattern NavMAX.

Fonctionnalités :
- Base abstraite pour les outils de cracking
- Wrapper hashcat (NTLM, WPA2, bcrypt, MD5, SHA256)
- Wrapper John the Ripper (SSH, ZIP, RAR, PDF, Kerberos)
- Wrapper Hydra (brute force services réseau)
- Bibliothèque de ressources (wordlists, règles, masques)
- Données intégrées (rules/, wordlists/, masks/)
"""

from .base import (
    BaseCracker,
    CrackResult,
    CrackStatus,
    HashInfo,
    HashType,
)
from .hashcat_wrapper import HashcatWrapper
from .john_wrapper import JohnWrapper
from .hydra_wrapper import HydraWrapper
from .library import (
    CrackingLibrary,
    MaskInfo,
    RuleInfo,
    WordlistInfo,
)

__all__ = [
    "BaseCracker",
    "CrackResult",
    "CrackStatus",
    "HashInfo",
    "HashType",
    "HashcatWrapper",
    "JohnWrapper",
    "HydraWrapper",
    "CrackingLibrary",
    "MaskInfo",
    "RuleInfo",
    "WordlistInfo",
]
