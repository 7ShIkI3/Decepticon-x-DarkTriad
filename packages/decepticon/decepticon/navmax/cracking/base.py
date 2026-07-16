"""BaseCracker — classe abstraite pour les wrappers d'outils de cracking.

Définit l'interface commune (check_installation, get_version, crack)
et les dataclasses Pydantic pour les résultats.
"""

from __future__ import annotations

import shutil
from abc import ABCMeta, abstractmethod
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


# ══════════════════════════════════════════════════════════════════════════════
# Enums & Models
# ══════════════════════════════════════════════════════════════════════════════


class CrackStatus(StrEnum):
    """Statut d'une tentative de cracking."""

    SUCCESS = "success"
    FAILED = "failed"
    ERROR = "error"
    RUNNING = "running"
    CANCELLED = "cancelled"


class HashType(StrEnum):
    """Types de hash supportés (principaux)."""

    NTLM = "ntlm"
    WPA2 = "wpa2"
    BCRYPT = "bcrypt"
    MD5 = "md5"
    SHA256 = "sha256"
    SHA512 = "sha512"
    SHA1 = "sha1"
    LM = "lm"
    MSCHAPV2 = "mschapv2"
    KERBEROS_TGT = "kerberos_tgt"
    SSH = "ssh"
    ZIP = "zip"
    RAR = "rar"
    PDF = "pdf"
    UNKNOWN = "unknown"


class HashInfo(BaseModel):
    """Informations sur un hash à cracker.

    Attributes:
        hash_type: Type de hash détecté (NTLM, MD5, …).
        hashcat_mode: Mode hashcat correspondant (ex: 1000 pour NTLM).
        format_john: Format John the Ripper (ex: "nt" pour NTLM).
        original_hash: Le hash brut tel que fourni.
        hash_file: Chemin du fichier contenant le hash (optionnel).
        username: Nom d'utilisateur associé (optionnel).
    """

    hash_type: HashType = HashType.UNKNOWN
    hashcat_mode: int = 0
    format_john: str = ""
    original_hash: str = ""
    hash_file: str = ""
    username: str = ""


class CrackResult(BaseModel):
    """Résultat d'une opération de cracking.

    Attributes:
        status: Statut final (success/failed/error).
        cracked_password: Mot de passe trouvé (si succès).
        hash_type: Type de hash traité.
        hash_value: Hash original (tronqué pour affichage).
        duration_seconds: Temps d'exécution en secondes.
        speed: Vitesse de cracking (hashes/sec) estimée.
        command: Commande exécutée.
        stdout: Sortie standard brute de l'outil.
        stderr: Sortie d'erreur brute de l'outil.
        error: Message d'erreur si échec.
    """

    status: CrackStatus = CrackStatus.FAILED
    cracked_password: str = ""
    hash_type: HashType = HashType.UNKNOWN
    hash_value: str = Field(default="", description="Hash original (tronqué)")
    duration_seconds: float = 0.0
    speed: float = 0.0
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    error: str = ""


# ══════════════════════════════════════════════════════════════════════════════
# Hashcat mode lookup
# ══════════════════════════════════════════════════════════════════════════════

HASHCAT_MODES: dict[HashType, int] = {
    HashType.NTLM: 1000,
    HashType.WPA2: 22000,
    HashType.BCRYPT: 3200,
    HashType.MD5: 0,
    HashType.SHA256: 1400,
    HashType.SHA512: 1700,
    HashType.SHA1: 100,
    HashType.LM: 3000,
    HashType.MSCHAPV2: 5500,
    HashType.KERBEROS_TGT: 13100,
}

JOHN_FORMATS: dict[HashType, str] = {
    HashType.NTLM: "nt",
    HashType.WPA2: "wpapsk",
    HashType.BCRYPT: "bcrypt",
    HashType.MD5: "raw-md5",
    HashType.SHA256: "raw-sha256",
    HashType.SHA512: "raw-sha512",
    HashType.SHA1: "raw-sha1",
    HashType.LM: "lm",
    HashType.KERBEROS_TGT: "krb5tgs",
    HashType.SSH: "ssh",
    HashType.ZIP: "zip",
    HashType.RAR: "rar",
    HashType.PDF: "pdf",
}

# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════


def detect_hash_type(hash_string: str) -> HashInfo:
    """Détecte le type d'un hash à partir de sa structure.

    Args:
        hash_string: Le hash brut à analyser.

    Returns:
        HashInfo avec le type détecté et les modes associés.
    """
    original = hash_string.strip()

    # NTLM (32 hex, format avec séparateur deux-points: user:rid:lmhash:nthash)
    if ":" in original:
        parts = original.split(":")
        nt_hash = parts[-1] if len(parts) >= 2 else parts[0]
        if len(nt_hash) == 32 and all(c in "0123456789abcdefABCDEF" for c in nt_hash):
            return HashInfo(
                hash_type=HashType.NTLM,
                hashcat_mode=1000,
                format_john="nt",
                original_hash=original,
            )
        # LM:HASH (format LM:NT)
        if len(parts) >= 2 and len(parts[0]) == 32 and len(parts[-1]) == 32:
            return HashInfo(
                hash_type=HashType.NTLM,
                hashcat_mode=1000,
                format_john="nt",
                original_hash=original,
            )

    # MD5 (32 hex, hash seul)
    if len(original) == 32 and all(c in "0123456789abcdefABCDEF" for c in original):
        return HashInfo(
            hash_type=HashType.MD5,
            hashcat_mode=0,
            format_john="raw-md5",
            original_hash=original,
        )

    # LM (32 hex, mais sans séparateur — ambigu avec MD5)
    if len(original) == 32:
        return HashInfo(
            hash_type=HashType.MD5,
            hashcat_mode=0,
            format_john="raw-md5",
            original_hash=original,
        )

    # SHA1 (40 hex)
    if len(original) == 40 and all(c in "0123456789abcdefABCDEF" for c in original):
        return HashInfo(
            hash_type=HashType.SHA1,
            hashcat_mode=100,
            format_john="raw-sha1",
            original_hash=original,
        )

    # SHA256 (64 hex)
    if len(original) == 64 and all(c in "0123456789abcdefABCDEF" for c in original):
        return HashInfo(
            hash_type=HashType.SHA256,
            hashcat_mode=1400,
            format_john="raw-sha256",
            original_hash=original,
        )

    # SHA512 (128 hex)
    if len(original) == 128 and all(c in "0123456789abcdefABCDEF" for c in original):
        return HashInfo(
            hash_type=HashType.SHA512,
            hashcat_mode=1700,
            format_john="raw-sha512",
            original_hash=original,
        )

    # WPA2 (format: 22000 handshake)
    if "*" in original and original.startswith("WPA"):
        return HashInfo(
            hash_type=HashType.WPA2,
            hashcat_mode=22000,
            format_john="wpapsk",
            original_hash=original,
        )

    # bcrypt ($2a$,$2b$,$2y$)
    if original.startswith(("$2a$", "$2b$", "$2y$", "$2x$")):
        return HashInfo(
            hash_type=HashType.BCRYPT,
            hashcat_mode=3200,
            format_john="bcrypt",
            original_hash=original,
        )

    return HashInfo(hash_type=HashType.UNKNOWN, original_hash=original)


# ══════════════════════════════════════════════════════════════════════════════
# Base abstraite
# ══════════════════════════════════════════════════════════════════════════════


class BaseCracker(metaclass=ABCMeta):
    """Classe de base abstraite pour les wrappers d'outils de cracking.

    Toutes les sous-classes doivent implémenter check_installation,
    get_version et crack().
    """

    _binary_name: str = ""  # Surchargé par la sous-classe

    def __init__(self) -> None:
        self._available: bool | None = None
        self._version: str = ""

    @property
    def binary_name(self) -> str:
        return self._binary_name

    @property
    def available(self) -> bool:
        """Vérifie si le binaire est disponible dans le PATH."""
        if self._available is not None:
            return self._available
        self._available = shutil.which(self._binary_name) is not None
        return self._available

    def check_installation(self) -> str:
        """Vérifie si l'outil est installé et retourne un message clair.

        Returns:
            Chaîne décrivant l'état de l'installation.
        """
        binary = shutil.which(self._binary_name)
        if binary:
            version = self.get_version()
            return f"{self._binary_name} est installé : {binary} (version: {version})"
        return (
            f"{self._binary_name} n'est pas installé sur le système.\n"
            f"  - Linux   : apt install {self._binary_name} (ou brew)\n"
            f"  - macOS   : brew install {self._binary_name}\n"
            f"  - Windows : téléchargez depuis le site officiel"
        )

    @abstractmethod
    def get_version(self) -> str:
        """Retourne la version de l'outil installé.

        Returns:
            Chaîne de version (ex: "6.2.6") ou chaîne vide si non trouvé.
        """
        ...

    @abstractmethod
    async def crack(
        self,
        hash_file: str,
        wordlist: str,
        **options: Any,
    ) -> CrackResult:
        """Lance une opération de cracking.

        Args:
            hash_file: Chemin vers le fichier contenant le(s) hash(es).
            wordlist: Chemin vers la wordlist.
            **options: Options spécifiques à l'outil.

        Returns:
            CrackResult avec le résultat de l'opération.
        """
        ...
