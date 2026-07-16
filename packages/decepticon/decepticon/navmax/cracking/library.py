"""
Gestionnaire de bibliothèque de cracking NavMAX.

CrackingLibrary gère les wordlists, règles hashcat et masques.
Permet de lister, rechercher, générer et télécharger des ressources.
"""

from __future__ import annotations

import hashlib
import logging
import re
import shutil
import urllib.request
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .data import (
    BUILTIN_MASKS,
    BUILTIN_RULES,
    BUILTIN_WORDLISTS,
    MASKS_DIR,
    RULES_DIR,
    WORDLISTS_DIR,
    get_mask_path,
    get_rule_path,
    get_wordlist_path,
)

logger = logging.getLogger("navmax.cracking.library")

# ── Modèles Pydantic ─────────────────────────────────────────────────────────


class WordlistInfo(BaseModel):
    """Informations sur une wordlist de cracking."""

    name: str = Field(description="Nom court de la wordlist")
    filename: str = Field(description="Nom du fichier sur disque")
    path: str = Field(description="Chemin absolu du fichier")
    description: str = Field(description="Description de la wordlist")
    word_count: int = Field(default=0, description="Nombre estimé de mots")
    size_bytes: int = Field(default=0, description="Taille du fichier en octets")
    exists: bool = Field(default=False, description="Le fichier existe sur disque")
    installed: bool = Field(default=True, description="Disponible localement")


class RuleInfo(BaseModel):
    """Informations sur un fichier de règles hashcat."""

    name: str = Field(description="Nom court de la règle")
    filename: str = Field(description="Nom du fichier .rule")
    path: str = Field(description="Chemin absolu du fichier")
    description: str = Field(description="Description des règles")
    rule_count: int = Field(default=0, description="Nombre de règles dans le fichier")
    size_bytes: int = Field(default=0, description="Taille du fichier en octets")
    exists: bool = Field(default=False, description="Le fichier existe sur disque")
    installed: bool = Field(default=True, description="Disponible localement")
    external_url: str | None = Field(
        default=None, description="URL de téléchargement pour la version complète"
    )


class MaskInfo(BaseModel):
    """Informations sur un masque hashcat."""

    name: str = Field(description="Nom court du masque")
    filename: str = Field(description="Nom du fichier .hcmask")
    path: str = Field(description="Chemin absolu du fichier")
    description: str = Field(description="Description du masque")
    mask_count: int = Field(default=0, description="Nombre de masques")
    size_bytes: int = Field(default=0, description="Taille du fichier en octets")
    exists: bool = Field(default=False, description="Le fichier existe sur disque")
    installed: bool = Field(default=True, description="Disponible localement")


# ── Gestionnaire de bibliothèque ─────────────────────────────────────────────


class CrackingLibrary:
    """
    Gère les wordlists, règles hashcat et masques de cracking.

    Fonctionnalités :
      - Lister les ressources disponibles (wordlists, rules, masks)
      - Obtenir les chemins des fichiers
      - Rechercher des wordlists par motif
      - Générer des wordlists à partir de templates
      - Télécharger des ressources externes (rockyou)
    """

    # ── Wordlists ─────────────────────────────────────────────────────────

    @staticmethod
    def list_wordlists() -> list[WordlistInfo]:
        """Liste toutes les wordlists disponibles (embarquées + externes si installées)."""
        results: list[WordlistInfo] = []
        for wl in BUILTIN_WORDLISTS:
            path = WORDLISTS_DIR / str(wl["filename"])
            results.append(
                WordlistInfo(
                    name=str(wl["name"]),
                    filename=str(wl["filename"]),
                    path=str(path.resolve()),
                    description=str(wl["description"]),
                    word_count=int(wl.get("word_count", 0)),
                    size_bytes=int(wl.get("size_bytes", 0)),
                    exists=path.exists(),
                    installed=path.exists(),
                )
            )
        # Vérifier rockyou si installé
        rockyou = CrackingLibrary._find_rockyou()
        if rockyou:
            results.append(
                WordlistInfo(
                    name="rockyou",
                    filename=rockyou.name,
                    path=str(rockyou.resolve()),
                    description="RockYou 2009 wordlist (14M+ mots de passe)",
                    word_count=14_000_000,
                    size_bytes=rockyou.stat().st_size,
                    exists=True,
                    installed=True,
                )
            )
        return results

    @staticmethod
    def get_wordlist_path(name: str) -> Path:
        """Retourne le chemin absolu d'une wordlist.

        Args:
            name: Nom de la wordlist ('common-1000', 'rockyou', 'french-common', etc.)

        Returns:
            Path vers le fichier de la wordlist.

        Raises:
            FileNotFoundError: Si la wordlist n'existe pas sur le système.
        """
        # Chercher dans les wordlists embarquées
        try:
            return get_wordlist_path(name)
        except KeyError:
            pass

        # Chercher rockyou
        if name == "rockyou":
            rk = CrackingLibrary._find_rockyou()
            if rk:
                return rk
            raise FileNotFoundError(
                "rockyou.txt n'est pas installé. Utilisez install_rockyou() pour le télécharger."
            )

        raise FileNotFoundError(
            f"Wordlist '{name}' introuvable. "
            f"Disponibles : {[w.name for w in CrackingLibrary.list_wordlists()]}"
        )

    @staticmethod
    def _find_rockyou() -> Path | None:
        """Cherche rockyou.txt dans les emplacements standards."""
        candidates = [
            Path("/usr/share/wordlists/rockyou.txt"),
            Path("/usr/share/wordlists/rockyou.txt.gz"),
            Path.home() / ".navmax" / "wordlists" / "rockyou.txt",
            Path.home() / ".navmax" / "wordlists" / "rockyou.txt.gz",
            WORDLISTS_DIR / "rockyou.txt",
            WORDLISTS_DIR / "rockyou.txt.gz",
            Path("/usr/share/wordlists/rockyou/rockyou.txt"),
        ]
        for c in candidates:
            if c.exists():
                return c
        return None

    @staticmethod
    def search_wordlists(pattern: str) -> list[WordlistInfo]:
        """Recherche des wordlists par motif (nom, description).

        Args:
            pattern: Motif de recherche (insensible à la casse).

        Returns:
            Liste des wordlists correspondant au motif.
        """
        pattern_lower = pattern.lower()
        results = CrackingLibrary.list_wordlists()
        return [
            w
            for w in results
            if pattern_lower in w.name.lower()
            or pattern_lower in w.description.lower()
            or pattern_lower in w.filename.lower()
        ]

    @staticmethod
    def generate_wordlist(template: str, output: Path) -> Path:
        """Génère une wordlist à partir d'un template de motifs.

        Le template supporte les motifs suivants :
          - {year:YYYY}  → 2024, 2023, 2022...
          - {year:YY}    → 24, 23, 22...
          - {num:N}      → 0, 1, 2... N
          - {season}      → summer, winter, spring, autumn
          - {special}     → !, @, #, $
          - {leet:e}      → e → 3, a → @, etc.

        Exemple :
          "MotDePasse{year:YYYY}{special}" → MotDePasse2024!, MotDePasse2023!, ...

        Args:
            template: Template avec motifs à générer.
            output: Chemin du fichier de sortie.

        Returns:
            Path vers le fichier généré.
        """
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)

        passwords: set[str] = set()
        years_long = [str(y) for y in range(1980, 2027)]
        years_short = [str(y)[-2:] for y in range(1980, 2027)]
        seasons = ["summer", "winter", "spring", "autumn", "été", "hiver", "printemps", "automne"]
        specials = ["!", "@", "#", "$", "%", "^", "&", "*"]

        # Génération par motifs
        _generate_from_template(template, years_long, years_short, seasons, specials, passwords)

        # Si aucun remplacement, ajouter telle quelle
        if not passwords:
            passwords.add(template)

        # Écrire
        output.write_text("\n".join(sorted(passwords)) + "\n", encoding="utf-8")
        logger.info("Wordlist générée : %s (%d mots)", output, len(passwords))
        return output

    # ── Règles ────────────────────────────────────────────────────────────

    @staticmethod
    def list_rules() -> list[RuleInfo]:
        """Liste tous les fichiers de règles hashcat disponibles."""
        results: list[RuleInfo] = []
        for rule in BUILTIN_RULES:
            path = RULES_DIR / str(rule["filename"])
            results.append(
                RuleInfo(
                    name=str(rule["name"]),
                    filename=str(rule["filename"]),
                    path=str(path.resolve()),
                    description=str(rule["description"]),
                    rule_count=int(rule.get("rule_count", 0)),
                    size_bytes=int(rule.get("size_bytes", 0)),
                    exists=path.exists(),
                    installed=path.exists(),
                    external_url=str(rule["external_url"]) if rule.get("external_url") else None,
                )
            )
        return results

    @staticmethod
    def get_rule_path(name: str) -> Path:
        """Retourne le chemin absolu d'un fichier de règles hashcat.

        Args:
            name: Nom de la règle ('best64', 'leetspeak', etc.).

        Returns:
            Path vers le fichier .rule.

        Raises:
            FileNotFoundError: Si la règle n'existe pas.
        """
        try:
            return get_rule_path(name)
        except KeyError as e:
            raise FileNotFoundError(
                f"Règle '{name}' introuvable. "
                f"Disponibles : {[r.name for r in CrackingLibrary.list_rules()]}"
            ) from e

    # ── Masques ───────────────────────────────────────────────────────────

    @staticmethod
    def list_masks() -> list[MaskInfo]:
        """Liste tous les fichiers de masques hashcat disponibles."""
        results: list[MaskInfo] = []
        for mask in BUILTIN_MASKS:
            path = MASKS_DIR / str(mask["filename"])
            results.append(
                MaskInfo(
                    name=str(mask["name"]),
                    filename=str(mask["filename"]),
                    path=str(path.resolve()),
                    description=str(mask["description"]),
                    mask_count=int(mask.get("mask_count", 0)),
                    size_bytes=int(mask.get("size_bytes", 0)),
                    exists=path.exists(),
                    installed=path.exists(),
                )
            )
        return results

    @staticmethod
    def get_mask_path(name: str) -> Path:
        """Retourne le chemin absolu d'un fichier de masques hashcat.

        Args:
            name: Nom du masque ('common', etc.).

        Returns:
            Path vers le fichier .hcmask.

        Raises:
            FileNotFoundError: Si le masque n'existe pas.
        """
        try:
            return get_mask_path(name)
        except KeyError as e:
            raise FileNotFoundError(
                f"Masque '{name}' introuvable. "
                f"Disponibles : {[m.name for m in CrackingLibrary.list_masks()]}"
            ) from e

    # ── Installation rockyou ──────────────────────────────────────────────

    @staticmethod
    def install_rockyou(target_dir: str | Path | None = None) -> bool:
        """Télécharge et installe la wordlist rockyou.txt.

        La version complète fait ~140 Mo décompressée.
        Source : https://github.com/brannondorsey/naive-hashcat/releases

        Args:
            target_dir: Répertoire de destination (défaut : ~/.navmax/wordlists/).

        Returns:
            True si l'installation a réussi, False sinon.
        """
        if target_dir is None:
            target_dir = Path.home() / ".navmax" / "wordlists"
        target_dir = Path(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        target_file = target_dir / "rockyou.txt"

        # Déjà installé ?
        if target_file.exists():
            logger.info("rockyou.txt déjà présent : %s", target_file)
            return True

        # Vérifier si déjà présent dans les emplacements standards
        existing = CrackingLibrary._find_rockyou()
        if existing:
            logger.info("rockyou.txt trouvé : %s", existing)
            if existing.suffix == ".gz":
                import gzip

                with gzip.open(existing, "rt", encoding="utf-8", errors="replace") as f_in:
                    target_file.write_text(f_in.read(), encoding="utf-8")
            else:
                shutil.copy2(existing, target_file)
            return True

        # Télécharger
        urls = [
            "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz",
        ]

        for url in urls:
            try:
                logger.info("Téléchargement de rockyou.txt depuis %s...", url)
                temp_file = target_dir / "rockyou.dl"
                urllib.request.urlretrieve(url, temp_file)

                if str(temp_file).endswith(".gz") or url.endswith(".tar.gz"):
                    import tarfile

                    if tarfile.is_tarfile(str(temp_file)):
                        with tarfile.open(str(temp_file), "r:*") as tar:
                            for member in tar.getmembers():
                                if "rockyou.txt" in member.name and member.isfile():
                                    tar.extract(member, path=str(target_dir))
                                    extracted = target_dir / member.name
                                    if extracted != target_file:
                                        shutil.move(str(extracted), str(target_file))
                                    break
                        temp_file.unlink()
                    else:
                        import gzip

                        with gzip.open(str(temp_file), "rt", encoding="utf-8", errors="replace") as f_in:
                            target_file.write_text(f_in.read(), encoding="utf-8")
                        temp_file.unlink()
                else:
                    shutil.move(str(temp_file), str(target_file))

                if target_file.exists():
                    size_mb = target_file.stat().st_size / (1024 * 1024)
                    logger.info("rockyou.txt installé : %s (%.1f Mo)", target_file, size_mb)
                    return True
            except Exception as exc:
                logger.warning("Échec du téléchargement depuis %s : %s", url, exc)
                continue

        logger.error(
            "Impossible de télécharger rockyou.txt. "
            "Téléchargez-le manuellement depuis :\n"
            "  https://github.com/brannondorsey/naive-hashcat/releases/tag/data"
        )
        return False

    # ── Sommaire ──────────────────────────────────────────────────────────

    @staticmethod
    def summary() -> dict[str, Any]:
        """Retourne un résumé de la bibliothèque de cracking."""
        wordlists = CrackingLibrary.list_wordlists()
        rules = CrackingLibrary.list_rules()
        masks = CrackingLibrary.list_masks()
        return {
            "wordlists": {
                "total": len(wordlists),
                "installed": sum(1 for w in wordlists if w.installed),
                "items": [w.model_dump() for w in wordlists],
            },
            "rules": {
                "total": len(rules),
                "installed": sum(1 for r in rules if r.installed),
                "items": [r.model_dump() for r in rules],
            },
            "masks": {
                "total": len(masks),
                "installed": sum(1 for m in masks if m.installed),
                "items": [m.model_dump() for m in masks],
            },
        }

    # ── Utilitaires ───────────────────────────────────────────────────────

    @staticmethod
    def verify_file_hash(filepath: str | Path, expected_hash: str, algo: str = "sha256") -> bool:
        """Vérifie l'intégrité d'un fichier avec un hash.

        Args:
            filepath: Chemin du fichier.
            expected_hash: Hash attendu (en hex).
            algo: Algorithme ('sha256', 'md5', 'sha1').

        Returns:
            True si le hash correspond.
        """
        h = hashlib.new(algo)
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest().lower() == expected_hash.lower()


# ── Fonction utilitaire de génération ─────────────────────────────────────────


def _generate_from_template(
    template: str,
    years_long: list[str],
    years_short: list[str],
    seasons: list[str],
    specials: list[str],
    passwords: set[str],
) -> None:
    """Génère des mots de passe à partir d'un template.

    Parcourt récursivement les motifs {motif} et génère les combinaisons.
    """
    # Pattern pour trouver les motifs { ... }
    pattern = re.compile(r"\{(\w+)(?::([^}]+))?\}")

    def _expand(text: str) -> list[str]:
        """Développe un template en liste de chaînes possibles."""
        match = pattern.search(text)
        if not match:
            return [text]

        prefix = text[: match.start()]
        suffix = text[match.end() :]
        keyword = match.group(1).lower()
        arg = match.group(2)

        expansions: list[str] = []

        if keyword == "year":
            if arg and arg.upper() == "YY":
                expansions = years_short
            else:
                expansions = years_long
        elif keyword == "num":
            try:
                n = int(arg) if arg else 100
                expansions = [str(i) for i in range(n + 1)]
            except (ValueError, TypeError):
                expansions = [str(i) for i in range(100)]
        elif keyword == "season":
            expansions = seasons
        elif keyword == "special":
            expansions = specials
        elif keyword == "leet":
            # Applicable à la lettre donnée en argument
            leet_map = {
                "e": ["e", "3"],
                "a": ["a", "@", "4"],
                "i": ["i", "1", "!"],
                "o": ["o", "0"],
                "s": ["s", "5", "$"],
                "t": ["t", "7"],
                "b": ["b", "8"],
                "g": ["g", "9"],
            }
            leet_char = arg.lower() if arg else "e"
            expansions = leet_map.get(leet_char, [leet_char])
        else:
            expansions = [f"{{{keyword}}}"]

        # Combiner préfixe + chaque expansion + suffixe (récursif)
        results: list[str] = []
        for exp in expansions:
            for suffix_expanded in _expand(suffix):
                results.append(f"{prefix}{exp}{suffix_expanded}")
        return results

    for candidate in _expand(template):
        passwords.add(candidate)
