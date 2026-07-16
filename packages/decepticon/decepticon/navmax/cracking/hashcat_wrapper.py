"""HashcatWrapper — wrapper asynchrone autour de hashcat (subprocess).

Support :
- Modes : NTLM (1000), WPA2 (22000), bcrypt (3200), MD5 (0), SHA256 (1400)
- Détection GPU (--opencl-platforms, --backend-devices)
- Options : -O (optimisé), -w (workload), --session (reprise)
- Parsing output (hashcat --show --machine-readable)
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
    HASHCAT_MODES,
    HashInfo,
    HashType,
    detect_hash_type,
)

logger = get_logger(__name__)

# ── Regex de parsing ─────────────────────────────────────────────

RE_SPEED = re.compile(
    r"Speed\.\*?\s*:\s*([\d.,]+)\s*(\w[Hh]/s)", re.IGNORECASE
)
RE_HASHCAT_PROGRESS = re.compile(
    r"Session\.+:\s*(.+)", re.IGNORECASE
)
RE_CRACKED = re.compile(
    r"([a-fA-F0-9]{32}|[^\s]+)\s*:\s*(.*)", re.IGNORECASE
)
RE_CRACKED_SHOW = re.compile(
    r"^([^:]+):([^:]+)$", re.MULTILINE
)
RE_VERSION = re.compile(r"v(\d+\.\d+\.\d+)")

# ── Options par défaut ───────────────────────────────────────────

DEFAULT_OPTS: dict[str, Any] = {
    "optimized": True,       # -O
    "workload": 3,           # -w 3
    "opencl": False,         # --opencl-platforms
    "backend_devices": "",   # --backend-devices "1,2"
    "session_name": "",      # --session <name>
    "rules": "",             # -r <rules_file>
    "increment": False,      # --increment
    "increment_min": 1,      # --increment-min
    "increment_max": 8,      # --increment-max
    "timeout": 600,          # Timeout max (s)
    "show": False,           # --show (ne pas lancer, juste afficher)
    "username": False,       # --username (inclure username dans output)
}


class HashcatWrapper(BaseCracker):
    """Wrapper asynchrone autour de hashcat.

    Usage:
        hc = HashcatWrapper()
        result = await hc.crack("hashes.txt", "rockyou.txt", mode=1000)
    """

    _binary_name = "hashcat"

    def __init__(self, hashcat_path: str | None = None) -> None:
        super().__init__()
        self._hashcat_path = hashcat_path
        self._gpu_info: str = ""

    # ── Installation ─────────────────────────────────────────────

    @property
    def available(self) -> bool:
        if self._available is not None:
            return self._available
        if self._hashcat_path:
            self._available = os.path.isfile(self._hashcat_path)
        else:
            self._available = shutil.which(self._binary_name) is not None
        return self._available

    def get_version(self) -> str:
        if self._version:
            return self._version
        if not self.available:
            return ""
        binary = self._hashcat_path or self._binary_name
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
            return ""

    # ── Détection GPU ────────────────────────────────────────────

    def detect_gpu(self) -> str:
        """Détecte les GPU disponibles via --backend-info.

        Returns:
            Chaîne d'information GPU ou message d'erreur.
        """
        if not self.available:
            return "hashcat non disponible"
        if self._gpu_info:
            return self._gpu_info

        binary = self._hashcat_path or self._binary_name
        try:
            proc = asyncio.run(
                asyncio.create_subprocess_exec(
                    binary, "--backend-info",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            )
            stdout, stderr = proc.communicate(timeout=30)
            output = stdout.decode("utf-8", errors="replace")
            err = stderr.decode("utf-8", errors="replace")
            info = output or err
            self._gpu_info = info
            return info
        except Exception as e:
            logger.warning("hashcat_gpu_detect_error", error=str(e))
            return f"Erreur détection GPU: {e!s}"

    # ── Cracking ─────────────────────────────────────────────────

    def _build_args(
        self,
        hash_file: str,
        wordlist: str,
        mode: int = 1000,
        **options: Any,
    ) -> list[str]:
        """Construit la liste d'arguments pour hashcat.

        Args:
            hash_file: Chemin du fichier de hash.
            wordlist: Chemin de la wordlist.
            mode: Mode hashcat (ex: 1000 pour NTLM).
            **options: Options supplémentaires.

        Returns:
            Liste d'arguments pour subprocess.
        """
        opts = {**DEFAULT_OPTS, **options}
        binary = self._hashcat_path or self._binary_name
        args: list[str] = [binary]

        # Mode
        args.extend(["-m", str(mode)])

        # Attack mode (dictionary)
        args.append("-a0")

        # Optimized kernel
        if opts.get("optimized", True):
            args.append("-O")

        # Workload profile
        workload = opts.get("workload", 3)
        args.extend(["-w", str(workload)])

        # Session
        session = opts.get("session_name", "")
        if session:
            args.extend(["--session", session])

        # Rules
        rules = opts.get("rules", "")
        if rules:
            args.extend(["-r", rules])

        # Increment
        if opts.get("increment", False):
            args.append("--increment")
            args.extend(["--increment-min", str(opts.get("increment_min", 1))])
            args.extend(["--increment-max", str(opts.get("increment_max", 8))])

        # Status only
        if opts.get("show", False):
            args.append("--show")

        # Username in output
        if opts.get("username", False):
            args.append("--username")

        # GPU backend
        if opts.get("opencl", False):
            args.append("--opencl-platforms")

        backend_devices = opts.get("backend_devices", "")
        if backend_devices:
            args.extend(["--backend-devices", str(backend_devices)])

        # Force (ignore warnings)
        args.append("--force")

        # Potfile (disable to avoid interference)
        args.append("--potfile-disable")

        # Fichiers
        args.append(hash_file)
        args.append(wordlist)

        return args

    def _parse_show_output(self, stdout: str) -> dict[str, str]:
        """Parse le résultat de hashcat --show.

        Args:
            stdout: Sortie de hashcat --show.

        Returns:
            Dictionnaire {hash: password}.
        """
        results: dict[str, str] = {}
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("Status"):
                continue
            parts = line.split(":", 1)
            if len(parts) == 2:
                h, pwd = parts
                results[h.strip()] = pwd.strip()
        return results

    async def crack(
        self,
        hash_file: str,
        wordlist: str,
        **options: Any,
    ) -> CrackResult:
        """Lance hashcat en subprocess asynchrone.

        Args:
            hash_file: Chemin du fichier de hash.
            wordlist: Chemin de la wordlist.
            **options: Voir DEFAULT_OPTS pour les options disponibles.

        Returns:
            CrackResult avec le résultat.
        """
        result = CrackResult()

        if not self.available:
            result.status = CrackStatus.ERROR
            result.error = f"{self._binary_name} n'est pas installé"
            return result

        # Valider les fichiers
        if not os.path.isfile(hash_file):
            result.status = CrackStatus.ERROR
            result.error = f"Fichier de hash introuvable: {hash_file}"
            return result
        if not os.path.isfile(wordlist):
            result.status = CrackStatus.ERROR
            result.error = f"Wordlist introuvable: {wordlist}"
            return result

        # Déterminer le mode
        mode = options.get("mode", 1000)
        hashcat_mode = mode

        # Détecter le type de hash pour le rapport
        with open(hash_file, encoding="utf-8", errors="replace") as f:
            first_line = f.readline().strip()
        info = detect_hash_type(first_line)
        if mode == 1000 and info.hash_type == HashType.UNKNOWN:
            pass  # On garde le mode spécifié

        result.hash_type = info.hash_type
        result.hash_value = first_line[:80]

        # Construire les args
        args = self._build_args(hash_file, wordlist, mode=hashcat_mode, **options)
        result.command = " ".join(args)

        logger.info(
            "hashcat_start",
            mode=hashcat_mode,
            hash_file=hash_file,
            wordlist=wordlist,
        )

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

            # Analyser le résultat
            if proc.returncode == 0:
                # Vérifier si crack réussi
                cracked = self._parse_show_output(stdout_str)
                if cracked:
                    first_hash = next(iter(cracked.keys()))
                    result.status = CrackStatus.SUCCESS
                    result.cracked_password = cracked[first_hash]
                    logger.info(
                        "hashcat_success",
                        hash=first_hash[:16],
                        password=result.cracked_password,
                    )
                else:
                    result.status = CrackStatus.FAILED
                    result.error = (
                        "Aucun mot de passe trouvé (hashcat terminé sans résultat)"
                    )
            elif proc.returncode == 1:
                result.status = CrackStatus.FAILED
                result.error = "Hashcat a échoué (aucun hash chargé ou erreur)"
            elif proc.returncode == 2:
                result.status = CrackStatus.ERROR
                result.error = "Hashcat a rencontré une erreur interne"
            else:
                result.status = CrackStatus.ERROR
                result.error = (
                    f"Hashcat terminé avec le code {proc.returncode}"
                )

            # Extraire la vitesse
            speed_match = RE_SPEED.search(stdout_str)
            if speed_match:
                speed_str = speed_match.group(1).replace(",", "")
                try:
                    result.speed = float(speed_str)
                except ValueError:
                    result.speed = 0.0

        except FileNotFoundError:
            result.status = CrackStatus.ERROR
            result.error = f"Binaire {self._binary_name} introuvable"
        except Exception as e:
            result.status = CrackStatus.ERROR
            result.error = f"Erreur inattendue: {e!s}"
            logger.exception("hashcat_unexpected_error")

        return result

    async def show_results(self, hash_file: str, mode: int = 1000) -> CrackResult:
        """Exécute hashcat --show pour afficher les résultats précédents.

        Args:
            hash_file: Fichier de hash.
            mode: Mode hashcat.

        Returns:
            CrackResult avec les résultats parsés.
        """
        return await self.crack(hash_file, "", mode=mode, show=True)

    def list_modes(self) -> dict[str, int]:
        """Retourne la liste des modes hashcat supportés.

        Returns:
            Dictionnaire {nom_mode: id_hashcat}.
        """
        return {k.value: v for k, v in HASHCAT_MODES.items()}
