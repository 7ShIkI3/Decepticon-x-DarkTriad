"""Données de cracking — règles hashcat, wordlists et masques intégrés.

Ce package contient des ressources de cracking prêtes à l'emploi :
- Règles hashcat (.rule) dans data/rules/
- Wordlists compactes (.txt) dans data/wordlists/
- Masques hashcat (.hcmask) dans data/masks/

Les fichiers volumineux (rockyou.txt, d3ad0ne.rule complet, etc.)
sont disponibles via téléchargement — voir CrackingLibrary.install_rockyou()
et les URLs de référence dans chaque fichier.
"""

from __future__ import annotations

from pathlib import Path

# ── Chemins ──────────────────────────────────────────────────────────────────

DATA_DIR = Path(__file__).parent
RULES_DIR = DATA_DIR / "rules"
WORDLISTS_DIR = DATA_DIR / "wordlists"
MASKS_DIR = DATA_DIR / "masks"

# ── Listes de ressources disponibles ─────────────────────────────────────────

# Règles hashcat embarquées
BUILTIN_RULES: list[dict[str, str | int]] = [
    {
        "name": "best64",
        "filename": "best64.rule",
        "description": "Les 64 meilleures règles (standard hashcat)",
        "rule_count": 96,
        "size_bytes": 626,
    },
    {
        "name": "d3ad0ne",
        "filename": "d3ad0ne.rule",
        "description": "Règles agressives (~250 règles, version complète: 35k+)",
        "rule_count": 250,
        "size_bytes": 3099,
        "external_url": "https://github.com/hashcat/hashcat/raw/master/rules/d3ad0ne.rule",
    },
    {
        "name": "T0XlC",
        "filename": "T0XlC.rule",
        "description": "Règles optimisées pour la vitesse",
        "rule_count": 120,
        "size_bytes": 1187,
        "external_url": "https://github.com/hashcat/hashcat/raw/master/rules/T0XlC.rule",
    },
    {
        "name": "InsidePro-PasswordsPro",
        "filename": "InsidePro-PasswordsPro.rule",
        "description": "Règles classiques PasswordsPro/Cain",
        "rule_count": 150,
        "size_bytes": 1723,
        "external_url": "https://github.com/hashcat/hashcat/raw/master/rules/InsidePro-PasswordsPro.rule",
    },
    {
        "name": "generated2",
        "filename": "generated2.rule",
        "description": "Règles générées automatiquement",
        "rule_count": 160,
        "size_bytes": 2019,
        "external_url": "https://github.com/hashcat/hashcat/raw/master/rules/generated2.rule",
    },
    {
        "name": "leetspeak",
        "filename": "leetspeak.rule",
        "description": "Substitutions l33t (e→3, a→@, etc.)",
        "rule_count": 219,
        "size_bytes": 1735,
    },
    {
        "name": "append-years",
        "filename": "append-years.rule",
        "description": "Ajoute les années 1980-2026 (format long et court)",
        "rule_count": 198,
        "size_bytes": 882,
    },
    {
        "name": "prepend-special",
        "filename": "prepend-special.rule",
        "description": "Préfixe !@#$%^&* et combinaisons avec capitalisation",
        "rule_count": 170,
        "size_bytes": 1013,
    },
]

# Wordlists embarquées
BUILTIN_WORDLISTS: list[dict[str, str | int]] = [
    {
        "name": "common-1000",
        "filename": "common-1000.txt",
        "description": "1000 mots de passe les plus courants (rockyou top 1000)",
        "word_count": 1000,
        "size_bytes": 3796,
    },
    {
        "name": "french-common",
        "filename": "french-common.txt",
        "description": "Mots de passe français courants",
        "word_count": 521,
        "size_bytes": 1876,
    },
    {
        "name": "seasonal",
        "filename": "seasonal.txt",
        "description": "Variations saisonnières (Summer2024!, Noel2024, etc.)",
        "word_count": 303,
        "size_bytes": 1307,
    },
    {
        "name": "keyboard-walks",
        "filename": "keyboard-walks.txt",
        "description": "Patterns clavier (qwerty, azerty, 1qaz2wsx, etc.)",
        "word_count": 255,
        "size_bytes": 588,
    },
    {
        "name": "default-creds",
        "filename": "default-creds.txt",
        "description": "Credentials par défaut (admin/admin, root/toor, etc.)",
        "word_count": 338,
        "size_bytes": 1626,
    },
]

# Masques embarqués
BUILTIN_MASKS: list[dict[str, str | int]] = [
    {
        "name": "common",
        "filename": "common.hcmask",
        "description": "Masques courants classés par probabilité de succès",
        "mask_count": 114,
        "size_bytes": 1886,
    },
]

# ── Fonctions d'accès ───────────────────────────────────────────────────────


def get_rule_path(name: str) -> Path:
    """Retourne le chemin absolu d'un fichier de règle par son nom."""
    for rule in BUILTIN_RULES:
        if rule["name"] == name:
            return RULES_DIR / rule["filename"]  # type: ignore[arg-type]
    msg = f"Règle '{name}' introuvable. Disponibles : {[r['name'] for r in BUILTIN_RULES]}"
    raise KeyError(msg)


def get_wordlist_path(name: str) -> Path:
    """Retourne le chemin absolu d'une wordlist par son nom."""
    for wl in BUILTIN_WORDLISTS:
        if wl["name"] == name:
            return WORDLISTS_DIR / wl["filename"]  # type: ignore[arg-type]
    msg = f"Wordlist '{name}' introuvable. Disponibles : {[w['name'] for w in BUILTIN_WORDLISTS]}"
    raise KeyError(msg)


def get_mask_path(name: str) -> Path:
    """Retourne le chemin absolu d'un masque par son nom."""
    for m in BUILTIN_MASKS:
        if m["name"] == name:
            return MASKS_DIR / m["filename"]  # type: ignore[arg-type]
    msg = f"Masque '{name}' introuvable. Disponibles : {[m['name'] for m in BUILTIN_MASKS]}"
    raise KeyError(msg)


__all__ = [
    "DATA_DIR",
    "RULES_DIR",
    "WORDLISTS_DIR",
    "MASKS_DIR",
    "BUILTIN_RULES",
    "BUILTIN_WORDLISTS",
    "BUILTIN_MASKS",
    "get_rule_path",
    "get_wordlist_path",
    "get_mask_path",
]
