"""JohnWrapper — wrapper asynchrone autour de John the Ripper (subprocess).

Support :
- Formats : SSH keys, ZIP, RAR, PDF, Kerberos TGT, NTLM, bcrypt, …
- Commande : john --format=<fmt> --wordlist=<wl> <file>
- Parsing du output (john --show)
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import time
from typing import Any

from ..core.logging import get_logger

from .base import (
    BaseCracker,
    CrackResult,
    CrackStatus,
    JOHN_FORMATS,
    HashType,
    detect_hash_type,
)

logger = get_logger(__name__)

# ── Regex ────────────────────────────────────────────────────────

RE_JOHN_VERSION = re.compile(r"John the Ripper\s+(\d+\.\d+[^\s]*)", re.IGNORECASE)
RE_JOHN_CRACKED = re.compile(r"^(.*?)\s*\(([^)]+)\)\s*$", re.MULTILINE)
RE_JOHN_PROGRESS = re.compile(
    r"(\d+g\s+\d+:\d+:\d+:\d+)\s+.*?(\d+\.\d+)g/s", re.IGNORECASE
)
RE_JOHN_PWD = re.compile(r"^([^:]+):([^:]+):", re.MULTILINE)


class JohnWrapper(BaseCracker):
    """Wrapper asynchrone autour de John the Ripper.

    Usage:
        john = JohnWrapper()
        result = await john.crack("hash.txt", "rockyou.txt", fmt="nt")
    """

    _binary_name = "john"

    def __init__(self, john_path: str | None = None) -> None:
        super().__init__()
        self._john_path = john_path

    # ── Installation ─────────────────────────────────────────────

    @property
    def available(self) -> bool:
        if self._available is not None:
            return self._available
        if self._john_path:
            self._available = os.path.isfile(self._john_path)
        else:
            self._available = shutil.which(self._binary_name) is not None
        return self._available

    def get_version(self) -> str:
        if self._version:
            return self._version
        if not self.available:
            return ""
        binary = self._john_path or self._binary_name
        try:
            proc = asyncio.run(
                asyncio.create_subprocess_exec(
                    binary, "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            )
            stdout, _ = proc.communicate(timeout=10)
            ver = stdout.decode("utf-8", errors="replace").strip()
            self._version = ver
            return ver
        except Exception:
            # Fallback: parse --help header
            try:
                proc = asyncio.run(
                    asyncio.create_subprocess_exec(
                        binary, "--help",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                )
                stdout, stderr = proc.communicate(timeout=10)
                output = stdout.decode("utf-8", errors="replace") + (
                    stderr.decode("utf-8", errors="replace")
                )
                match = RE_JOHN_VERSION.search(output)
                if match:
                    self._version = match.group(1)
                    return self._version
            except Exception:
                pass
            return ""

    # ── Cracking ─────────────────────────────────────────────────

    def _build_args(
        self,
        hash_file: str,
        wordlist: str,
        fmt: str = "nt",
        **options: Any,
    ) -> list[str]:
        """Construit la liste d'arguments pour john.

        Args:
            hash_file: Chemin du fichier de hash.
            wordlist: Chemin de la wordlist.
            fmt: Format john (ex: "nt", "raw-md5").
            **options: Options supplémentaires.

        Returns:
            Liste d'arguments pour subprocess.
        """
        binary = self._john_path or self._binary_name
        args: list[str] = [binary]

        # Format
        args.extend(["--format", fmt])

        # Wordlist
        if wordlist:
            args.extend(["--wordlist", wordlist])

        # Options additionnelles
        fork = options.get("fork", 0)
        if fork > 0:
            args.extend(["--fork", str(fork)])

        session = options.get("session", "")
        if session:
            args.extend(["--session", session])

        rules = options.get("rules", "")
        if rules:
            args.extend(["--rules", rules])

        # Potfile
        potfile = options.get("potfile", "")
        if potfile:
            args.extend(["--pot", potfile])

        if options.get("no_potfile", False):
            args.append("--potfile-mem-only")

        # Fichier de hash
        args.append(hash_file)

        return args

    def _parse_show_output(self, stdout: str) -> dict[str, str]:
        """Parse la sortie de john --show.

        Args:
            stdout: Sortie de john --show.

        Returns:
            Dictionnaire {user/hash: password}.
        """
        results: dict[str, str] = {}
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line or ":" not in line:
                continue
            if line.count(":") >= 1:
                parts = line.split(":")
                user = parts[0].strip()
                pwd = parts[1].strip() if len(parts) > 1 else ""
                if user and pwd and pwd != "?":
                    results[user] = pwd
        return results

    async def crack(
        self,
        hash_file: str,
        wordlist: str,
        **options: Any,
    ) -> CrackResult:
        """Lance john en subprocess asynchrone.

        Args:
            hash_file: Chemin du fichier de hash.
            wordlist: Chemin de la wordlist.
            **options:
                fmt: Format john (ex: "nt", "raw-md5", "ssh", "zip", "rar", "pdf").
                fork: Nombre de forks.
                session: Nom de session john.
                rules: Fichier de règles.
                potfile: Chemin du fichier pot.
                no_potfile: Ne pas utiliser le fichier pot.
                timeout: Timeout en secondes (défaut: 600).

        Returns:
            CrackResult avec le résultat.
        """
        result = CrackResult()

        if not self.available:
            result.status = CrackStatus.ERROR
            result.error = f"{self._binary_name} n'est pas installé"
            return result

        if not os.path.isfile(hash_file):
            result.status = CrackStatus.ERROR
            result.error = f"Fichier de hash introuvable: {hash_file}"
            return result
        if wordlist and not os.path.isfile(wordlist):
            result.status = CrackStatus.ERROR
            result.error = f"Wordlist introuvable: {wordlist}"
            return result

        # Détecter le format
        fmt = options.get("fmt", "nt")
        if fmt == "auto" or not fmt:
            with open(hash_file, encoding="utf-8", errors="replace") as f:
                first_line = f.readline().strip()
            info = detect_hash_type(first_line)
            fmt = info.format_john or "nt"
            result.hash_type = info.hash_type
            result.hash_value = first_line[:80]
        else:
            # Déduire le HashType à partir du format
            for ht, jf in JOHN_FORMATS.items():
                if jf == fmt:
                    result.hash_type = ht
                    break

        logger.info(
            "john_start",
            format=fmt,
            hash_file=hash_file,
            wordlist=wordlist,
        )

        # Construire et lancer la commande — retirer fmt de options
        # pour éviter le double passage à _build_args
        crack_opts = {k: v for k, v in options.items() if k != "fmt"}
        args = self._build_args(hash_file, wordlist, fmt=fmt, **crack_opts)
        result.command = " ".join(args)

        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            timeout = options.get("timeout", 600)
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout,
                )
            except TimeoutError:
                proc.kill()
                await proc.wait()
                result.status = CrackStatus.CANCELLED
                result.error = f"Timeout ({timeout}s) dépassé"
                result.duration_seconds = time.monotonic() - start
                return result

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")
            result.stdout = stdout_str
            result.stderr = stderr_str
            result.duration_seconds = time.monotonic() - start

            if proc.returncode == 0:
                # John retourne 0 même si rien de cracké — on check le output
                if "password" in stdout_str.lower() or "cracked" in stdout_str.lower():
                    cracked = self._parse_show_output(stdout_str)
                    if cracked:
                        first_user = next(iter(cracked.keys()))
                        result.status = CrackStatus.SUCCESS
                        result.cracked_password = cracked[first_user]
                        logger.info(
                            "john_success",
                            user=first_user,
                            password=result.cracked_password,
                        )
                    else:
                        result.status = CrackStatus.FAILED
                        result.error = (
                            "Aucun mot de passe trouvé (john terminé sans résultat)"
                        )
                else:
                    result.status = CrackStatus.FAILED
                    result.error = (
                        "Aucun mot de passe trouvé (john terminé sans crack)"
                    )
            elif proc.returncode == 1:
                result.status = CrackStatus.ERROR
                result.error = "John a rencontré une erreur (code 1)"
            else:
                result.status = CrackStatus.ERROR
                result.error = (
                    f"John terminé avec le code {proc.returncode}"
                )

        except FileNotFoundError:
            result.status = CrackStatus.ERROR
            result.error = f"Binaire {self._binary_name} introuvable"
        except Exception as e:
            result.status = CrackStatus.ERROR
            result.error = f"Erreur inattendue: {e!s}"
            logger.exception("john_unexpected_error")

        return result

    async def show_results(self, hash_file: str, fmt: str = "") -> CrackResult:
        """Exécute john --show pour afficher les résultats précédents.

        Args:
            hash_file: Fichier de hash.
            fmt: Format john (optionnel).

        Returns:
            CrackResult avec les résultats parsés.
        """
        options: dict[str, Any] = {"no_potfile": False}
        if fmt:
            options["fmt"] = fmt
        return await self.crack(hash_file, "", **options)

    def list_formats(self) -> dict[str, str]:
        """Retourne les formats john supportés par ce wrapper.

        Returns:
            Dictionnaire {nom_format: description}.
        """
        return {k.value: v for k, v in JOHN_FORMATS.items()}
