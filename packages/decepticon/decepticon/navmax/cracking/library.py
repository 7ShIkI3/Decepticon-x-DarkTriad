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
import urllib.error
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

    # ── Téléchargements ───────────────────────────────────────────────────

    @staticmethod
    def _check_disk_space(path: Path, required_bytes: int) -> bool:
        """Vérifie l'espace disque disponible sur le filesystem contenant *path*.

        Args:
            path: Chein de référence pour le filesystem.
            required_bytes: Nombre d'octets nécessaires.

        Returns:
            True si l'espace disponible est suffisant (+10% de marge).
        """
        try:
            usage = shutil.disk_usage(path.parent if path.is_file() else path)
            free = usage.free
            if free < required_bytes * 1.1:
                logger.warning(
                    "Espace disque insuffisant : %s libre, %s requis (avec marge)",
                    _format_bytes(free),
                    _format_bytes(int(required_bytes * 1.1)),
                )
                return False
            return True
        except OSError:
            logger.warning("Impossible de vérifier l'espace disque pour %s", path)
            return True  # mode optimiste si la vérification échoue

    @staticmethod
    def _sha256_file(filepath: str | Path) -> str:
        """Calcule le SHA256 d'un fichier."""
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest().lower()

    @staticmethod
    def download_rockyou(
        target_dir: str | Path | None = None,
        expected_sha256: str | None = None,
    ) -> Path | None:
        """Télécharge rockyou.txt depuis le dépôt GitHub SecLists.

        Télécharge le fichier tar.gz, l'extrait et vérifie l'intégrité.
        Affiche la progression du téléchargement via le logger.

        Args:
            target_dir: Répertoire de destination (défaut : data/wordlists/).
            expected_sha256: Hash SHA256 attendu pour la vérification (optionnel).

        Returns:
            Path vers rockyou.txt si réussi, None sinon.
        """
        if target_dir is None:
            target_dir = WORDLISTS_DIR
        target_dir = Path(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        target_file = target_dir / "rockyou.txt"

        # Déjà présent ?
        if target_file.exists():
            logger.info("rockyou.txt déjà présent : %s", target_file)
            return target_file

        url = (
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
            "Passwords/Leaked-Databases/rockyou.txt.tar.gz"
        )
        temp_file = target_dir / "rockyou.tar.gz.dl"

        # Vérifier espace disque (~140 Mo décompressé + ~50 Mo pour l'archive)
        if not CrackingLibrary._check_disk_space(target_dir, 200 * 1024 * 1024):
            logger.error("Espace disque insuffisant pour télécharger rockyou.txt")
            return None

        try:
            logger.info("Téléchargement de rockyou.txt depuis SecLists...")
            logger.info("URL : %s", url)

            # Progression via reporthook
            last_pct = [0]

            def _reporthook(count: int, block_size: int, total: int) -> None:
                if total > 0:
                    pct = min(int(count * block_size / total * 100), 100)
                    if pct >= last_pct[0] + 10:
                        last_pct[0] = pct
                        downloaded = count * block_size
                        logger.info(
                            "  Progression : %d%% (%s / %s)",
                            pct,
                            _format_bytes(downloaded),
                            _format_bytes(total),
                        )

            urllib.request.urlretrieve(url, temp_file, _reporthook)
            dl_size = temp_file.stat().st_size
            logger.info("Téléchargement terminé : %s (%s)", temp_file, _format_bytes(dl_size))

            # SHA256 de l'archive téléchargée
            if expected_sha256:
                dl_hash = CrackingLibrary._sha256_file(temp_file)
                if dl_hash != expected_sha256.lower():
                    logger.error(
                        "Hash SHA256 inattendu pour l'archive : attendu=%s, obtenu=%s",
                        expected_sha256,
                        dl_hash,
                    )
                    temp_file.unlink(missing_ok=True)
                    return None
                logger.info("SHA256 vérifié avec succès : %s", dl_hash)

            # Extraction du tar.gz
            import tarfile

            if not tarfile.is_tarfile(str(temp_file)):
                logger.error("Le fichier téléchargé n'est pas une archive tar valide")
                temp_file.unlink(missing_ok=True)
                return None

            with tarfile.open(str(temp_file), "r:gz") as tar:
                extracted = False
                for member in tar.getmembers():
                    if "rockyou.txt" in member.name and member.isfile():
                        logger.info("Extraction de : %s", member.name)
                        tar.extract(member, path=str(target_dir))
                        extracted_path = target_dir / member.name
                        if extracted_path != target_file:
                            if target_file.exists():
                                target_file.unlink()
                            shutil.move(str(extracted_path), str(target_file))
                        # Nettoyer les dossiers vides créés par l'extraction
                        parent = extracted_path.parent
                        while parent != target_dir:
                            try:
                                parent.rmdir()
                            except OSError:
                                break
                            parent = parent.parent
                        extracted = True
                        break

                if not extracted:
                    logger.error("rockyou.txt introuvable dans l'archive")
                    temp_file.unlink(missing_ok=True)
                    return None

            temp_file.unlink(missing_ok=True)

            if target_file.exists():
                final_size = target_file.stat().st_size
                logger.info(
                    "rockyou.txt installé avec succès : %s (%s, %s mots)",
                    target_file,
                    _format_bytes(final_size),
                    _format_number(final_size // 8),  # ~estimation
                )
                return target_file

            logger.error("Le fichier rockyou.txt est introuvable après extraction")
            return None

        except urllib.error.URLError as exc:
            logger.error("Erreur réseau lors du téléchargement : %s", exc)
        except OSError as exc:
            logger.error("Erreur fichier lors du téléchargement : %s", exc)
        except Exception as exc:
            logger.exception("Erreur inattendue lors du téléchargement : %s", exc)

        # Nettoyage en cas d'échec
        temp_file.unlink(missing_ok=True)
        return None

    @staticmethod
    def download_seclists(
        wordlists: list[dict[str, str]],
        target_dir: str | Path | None = None,
    ) -> dict[str, Path | None]:
        """Télécharge des wordlists depuis le dépôt GitHub SecLists.

        Args:
            wordlists: Liste de dictionnaires avec les clés :
                       - 'name'       : identifiant local (ex: '10k-most-common')
                       - 'remote_path': chemin dans le repo SecLists
                         (ex: 'Passwords/Common-Credentials/10k-most-common.txt')
                       - 'expected_sha256' : hash SHA256 optionnel
            target_dir: Répertoire de destination (défaut : data/wordlists/).

        Returns:
            Dictionnaire {name: Path|None} indiquant le chemin local pour
            chaque wordlist téléchargée, ou None si échec.
        """
        if target_dir is None:
            target_dir = WORDLISTS_DIR
        target_dir = Path(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        base_url = (
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        )
        results: dict[str, Path | None] = {}

        for wl in wordlists:
            name = wl.get("name", wl["remote_path"].split("/")[-1])
            remote = wl["remote_path"]
            expected = wl.get("expected_sha256")
            target_file = target_dir / remote.split("/")[-1]

            # Déjà présent ?
            if target_file.exists():
                logger.info("[%s] déjà présent : %s", name, target_file)
                results[name] = target_file
                continue

            url = base_url + remote
            temp_file = target_dir / f"{name}.dl"

            # Estimer la taille (on ne peut pas la connaître avant le HEAD)
            # On vérifie juste qu'il y a au moins 50 Mo de libre
            if not CrackingLibrary._check_disk_space(target_dir, 50 * 1024 * 1024):
                logger.error("[%s] Espace disque insuffisant", name)
                results[name] = None
                continue

            try:
                logger.info("[%s] Téléchargement depuis SecLists...", name)
                logger.info("  URL : %s", url)

                last_pct = [0]

                def _make_reporthook(label: str = name) -> Any:
                    def _hook(count: int, block_size: int, total: int) -> None:
                        if total > 0:
                            pct = min(int(count * block_size / total * 100), 100)
                            if pct >= last_pct[0] + 10:
                                last_pct[0] = pct
                                logger.info(
                                    "  [%s] Progression : %d%%",
                                    label,
                                    pct,
                                )
                    return _hook

                urllib.request.urlretrieve(url, temp_file, _make_reporthook(name))
                dl_size = temp_file.stat().st_size
                logger.info(
                    "[%s] Téléchargé : %s (%s)",
                    name,
                    temp_file,
                    _format_bytes(dl_size),
                )

                # SHA256
                if expected:
                    dl_hash = CrackingLibrary._sha256_file(temp_file)
                    if dl_hash != expected.lower():
                        logger.error(
                            "[%s] SHA256 inattendu : attendu=%s, obtenu=%s",
                            name,
                            expected,
                            dl_hash,
                        )
                        temp_file.unlink(missing_ok=True)
                        results[name] = None
                        continue
                    logger.info("[%s] SHA256 vérifié : %s", name, dl_hash)

                # Si c'est un tar.gz, extraire
                if remote.endswith(".tar.gz") or remote.endswith(".tgz"):
                    import tarfile

                    if tarfile.is_tarfile(str(temp_file)):
                        with tarfile.open(str(temp_file), "r:*") as tar:
                            tar.extractall(path=str(target_dir))
                        temp_file.unlink(missing_ok=True)
                        # Chercher le fichier extrait
                        found = list(target_dir.rglob(target_file.name))
                        if found:
                            results[name] = found[0]
                        else:
                            results[name] = target_file
                        continue

                shutil.move(str(temp_file), str(target_file))
                results[name] = target_file
                logger.info("[%s] Installé : %s", name, target_file)

            except urllib.error.URLError as exc:
                logger.error("[%s] Erreur réseau : %s", name, exc)
                results[name] = None
                temp_file.unlink(missing_ok=True)
            except OSError as exc:
                logger.error("[%s] Erreur fichier : %s", name, exc)
                results[name] = None
                temp_file.unlink(missing_ok=True)
            except Exception as exc:
                logger.exception("[%s] Erreur inattendue : %s", name, exc)
                results[name] = None
                temp_file.unlink(missing_ok=True)

        return results

    # ── Catalogue de wordlists en ligne ─────────────────────────────────────

    # Sources de wordlists populaires avec URLs de téléchargement direct.
    # Format : {name: {url, size_mb, description, category, sha256 (optionnel)}}
    POPULAR_WORDLISTS: dict[str, dict[str, str | int | None]] = {
        # ── SecLists (danielmiessler) ──
        "10k-most-common": {
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
            "size_mb": 0.1,
            "description": "Top 10 000 mots de passe les plus courants (SecLists)",
            "category": "common",
        },
        "100k-most-common": {
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/100k-most-common.txt",
            "size_mb": 1,
            "description": "Top 100 000 mots de passe (SecLists)",
            "category": "common",
        },
        "xato-net-10-million": {
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords-100000.txt",
            "size_mb": 0.8,
            "description": "Top 100k du dump Xato.net (10M) — SecLists",
            "category": "common",
        },
        "darkweb2017-top10000": {
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top10000.txt",
            "size_mb": 0.1,
            "description": "Top 10k du dump DarkWeb 2017",
            "category": "leaked",
        },
        # ── Weakpass ──
        "weakpass_2": {
            "url": "https://weakpass.com/wordlists/weakpass_2",
            "size_mb": 4900,
            "description": "Weakpass v2 — 7.8 milliards de mots (4.9 Go, compressé .gz)",
            "category": "massive",
        },
        "weakpass_3": {
            "url": "https://weakpass.com/wordlists/weakpass_3",
            "size_mb": 18000,
            "description": "Weakpass v3 — dernière version massive (18 Go)",
            "category": "massive",
        },
        # ── CrackStation ──
        "crackstation-human-only": {
            "url": "https://crackstation.net/files/crackstation-human-only.txt.gz",
            "size_mb": 684,
            "description": "CrackStation — mots de passe humains uniquement (684 Mo .gz)",
            "category": "common",
        },
        "crackstation-full": {
            "url": "https://crackstation.net/files/crackstation.txt.gz",
            "size_mb": 4130,
            "description": "CrackStation — full (1.5 milliard d'entrées, 4 Go .gz)",
            "category": "massive",
        },
        # ── Probable-Wordlists (berzerk0) ──
        "probable-top1575": {
            "url": "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top1575-probable-v2.txt",
            "size_mb": 0.02,
            "description": "Top 1575 mots de passe les plus probables",
            "category": "common",
        },
        "probable-top12000": {
            "url": "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top12Thousand-probable-v2.txt",
            "size_mb": 0.1,
            "description": "Top 12 000 mots de passe probables",
            "category": "common",
        },
        "probable-wpa": {
            "url": "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/WPA-Length-8-Filtered-WPA-2.0.txt",
            "size_mb": 0.5,
            "description": "Mots de passe WPA optimisés (longueur 8)",
            "category": "wifi",
        },
        # ── Hashes.org ──
        "hashesorg-found": {
            "url": "https://download.weakpass.com/wordlists/1948/hashesorg-found.txt",
            "size_mb": 1400,
            "description": "Hashes.org — mots de passe trouvés (1.4 Go)",
            "category": "leaked",
        },
        # ── Autres sources ──
        "ignis-10m": {
            "url": "https://github.com/ignis-sec/Pwdb-Public/raw/master/10-million-combos.txt",
            "size_mb": 640,
            "description": "Ignis 10 millions combos (user:pass)",
            "category": "leaked",
        },
        "bt4-password": {
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Software/bt4-password.txt",
            "size_mb": 0.03,
            "description": "BackTrack 4 — wordlist par défaut",
            "category": "common",
        },
        "500-worst": {
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/500-worst-passwords.txt",
            "size_mb": 0.005,
            "description": "Les 500 pires mots de passe",
            "category": "common",
        },
    }

    # Catalogue de règles hashcat téléchargeables
    POPULAR_RULES: dict[str, dict[str, str | int | None]] = {
        "OneRuleToRuleThemAll": {
            "url": "https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemAll.rule",
            "size_mb": 80,
            "description": "Règle ultime — 51k règles optimisées (80 Mo)",
        },
        "dive": {
            "url": "https://raw.githubusercontent.com/hashcat/hashcat/master/rules/dive.rule",
            "size_mb": 31,
            "description": "Règles dive.rule — 130k règles de l'équipe hashcat",
        },
        "NSAKEY": {
            "url": "https://raw.githubusercontent.com/NSAKEY/nsa-rules/master/nsa-rules-v2.rule",
            "size_mb": 10,
            "description": "NSA Rules v2 — règles orientées entreprise",
        },
        "pantagrule-private": {
            "url": "https://raw.githubusercontent.com/rarecoil/pantagrule/master/rules/pantagrule.private.v5.popular.rule",
            "size_mb": 45,
            "description": "Pantagrule — règles générées par ML (v5 popular)",
        },
    }

    @staticmethod
    def download_popular(
        *selection: str,
        target_dir: str | Path | None = None,
        categories: list[str] | None = None,
        max_size_mb: float | None = None,
    ) -> dict[str, Path | None]:
        """Télécharge une ou plusieurs wordlists populaires par lot.

        Args:
            *selection: Noms de wordlists (voir POPULAR_WORDLISTS).
                        Si vide + categories vide → télécharge les < 100 Mo.
            target_dir: Répertoire cible (défaut: WORDLISTS_DIR).
            categories: Filtrer par catégories (ex: ['common', 'wifi']).
            max_size_mb: Taille max par wordlist en Mo (défaut: 100).

        Returns:
            {name: Path | None} — None si échec.
        """
        if target_dir is None:
            target_dir = WORDLISTS_DIR
        target_dir = Path(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        # Construire la sélection
        if selection:
            names = list(selection)
        elif categories:
            names = [
                n for n, w in CrackingLibrary.POPULAR_WORDLISTS.items()
                if w.get("category") in categories
            ]
        else:
            # Par défaut : toutes les wordlists ≤ 100 Mo
            limit = max_size_mb or 100
            names = [
                n for n, w in CrackingLibrary.POPULAR_WORDLISTS.items()
                if w.get("size_mb", 999) <= limit
            ]

        if not names:
            logger.warning("Aucune wordlist sélectionnée.")
            return {}

        logger.info(
            "Téléchargement de %d wordlist(s) — espace estimé : %.0f Mo",
            len(names),
            sum(
                CrackingLibrary.POPULAR_WORDLISTS[n].get("size_mb", 0)
                for n in names
                if n in CrackingLibrary.POPULAR_WORDLISTS
            ),
        )

        results: dict[str, Path | None] = {}
        for name in names:
            if name not in CrackingLibrary.POPULAR_WORDLISTS:
                logger.warning("Wordlist inconnue : %s", name)
                results[name] = None
                continue

            wl = CrackingLibrary.POPULAR_WORDLISTS[name]
            url = str(wl["url"])
            size = wl.get("size_mb", 0)
            desc = wl.get("description", name)

            # Skip si trop gros
            if max_size_mb and size and size > max_size_mb:
                logger.info(
                    "[%s] Ignorée (%.0f Mo > limite %.0f Mo)", name, size, max_size_mb
                )
                results[name] = None
                continue

            target_file = target_dir / f"{name}.txt"
            if target_file.exists():
                logger.info("[%s] Déjà présent : %s", name, target_file)
                results[name] = target_file
                continue

            # Espace disque
            needed = int(size * 1024 * 1024 * 2) if size else 200 * 1024 * 1024
            if not CrackingLibrary._check_disk_space(target_dir, needed):
                logger.error("[%s] Espace disque insuffisant", name)
                results[name] = None
                continue

            temp_file = target_dir / f"{name}.dl"
            try:
                logger.info("[%s] %s", name, desc)
                logger.info("  URL : %s", url)

                last_pct = [0]

                def _hook(count: int, block_size: int, total: int) -> None:
                    if total > 0:
                        pct = min(int(count * block_size / total * 100), 100)
                        if pct >= last_pct[0] + 10:
                            last_pct[0] = pct
                            logger.info("  [%s] %d%%", name, pct)

                urllib.request.urlretrieve(url, temp_file, _hook)

                # Décompresser si .gz
                if url.endswith(".gz"):
                    import gzip
                    import shutil as _shutil

                    extracted = target_dir / f"{name}.txt"
                    with gzip.open(temp_file, "rb") as f_in:
                        with open(extracted, "wb") as f_out:
                            _shutil.copyfileobj(f_in, f_out)
                    temp_file.unlink()
                    target_file = extracted
                else:
                    shutil.move(str(temp_file), str(target_file))

                final_size = target_file.stat().st_size
                logger.info(
                    "[%s] ✓ Installé : %s (%s)",
                    name,
                    target_file.name,
                    _format_bytes(final_size),
                )
                results[name] = target_file

            except urllib.error.URLError as exc:
                logger.error("[%s] Erreur réseau : %s", name, exc)
                results[name] = None
                temp_file.unlink(missing_ok=True)
            except OSError as exc:
                logger.error("[%s] Erreur disque : %s", name, exc)
                results[name] = None
                temp_file.unlink(missing_ok=True)
            except Exception as exc:
                logger.exception("[%s] Erreur : %s", name, exc)
                results[name] = None
                temp_file.unlink(missing_ok=True)

        ok = sum(1 for v in results.values() if v is not None)
        logger.info("Terminé : %d/%d wordlists téléchargées", ok, len(names))
        return results

    @staticmethod
    def download_rules_popular(
        *selection: str,
        target_dir: str | Path | None = None,
    ) -> dict[str, Path | None]:
        """Télécharge des règles hashcat populaires.

        Args:
            *selection: Noms de règles (voir POPULAR_RULES).
                        Si vide → télécharge tout.
            target_dir: Répertoire cible (défaut: RULES_DIR).

        Returns:
            {name: Path | None}
        """
        if target_dir is None:
            target_dir = RULES_DIR
        target_dir = Path(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        names = list(selection) if selection else list(CrackingLibrary.POPULAR_RULES)

        results: dict[str, Path | None] = {}
        for name in names:
            if name not in CrackingLibrary.POPULAR_RULES:
                logger.warning("Règle inconnue : %s", name)
                results[name] = None
                continue

            rule = CrackingLibrary.POPULAR_RULES[name]
            url = str(rule["url"])
            desc = rule.get("description", name)

            target_file = target_dir / f"{name}.rule"
            if target_file.exists():
                logger.info("[%s] Déjà présent", name)
                results[name] = target_file
                continue

            temp_file = target_dir / f"{name}.dl"
            try:
                logger.info("[%s] %s", name, desc)
                urllib.request.urlretrieve(url, temp_file)
                shutil.move(str(temp_file), str(target_file))
                logger.info(
                    "[%s] ✓ Installé : %s (%s)",
                    name,
                    target_file.name,
                    _format_bytes(target_file.stat().st_size),
                )
                results[name] = target_file
            except Exception as exc:
                logger.error("[%s] Échec : %s", name, exc)
                results[name] = None
                temp_file.unlink(missing_ok=True)

        return results

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


# ── Utilitaires de formatage ──────────────────────────────────────────────────


def _format_bytes(n: int) -> str:
    """Formate un nombre d'octets en chaîne lisible (Ko, Mo, Go)."""
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "o" else f"{n} o"
        n /= 1024
    return f"{n:.1f} Po"


def _format_number(n: int) -> str:
    """Formate un grand nombre avec séparateurs de milliers."""
    if n < 1000:
        return str(n)
    return f"{n:,}".replace(",", " ")
