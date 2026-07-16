"""HydraWrapper — wrapper asynchrone autour de Hydra (subprocess).

Support :
- Services : ssh, ftp, http-get, http-post, smb, rdp, mssql, mysql
- Options : -t (tasks), -w (wait), -f (exit on first)
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import time
from dataclasses import dataclass
from typing import Any

from ..core.logging import get_logger

from .base import (
    BaseCracker,
    CrackResult,
    CrackStatus,
)

logger = get_logger(__name__)

# ── Regex ────────────────────────────────────────────────────────

RE_HYDRA_VERSION = re.compile(r"Hydra\s+v(\d+\.\d+[^\s]*)", re.IGNORECASE)
RE_HYDRA_LOGIN = re.compile(
    r"\[(\d+)\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)",
    re.IGNORECASE,
)
RE_HYDRA_STAT = re.compile(
    r"(\d+)\s+of\s+(\d+)\s+targets?\s+successfully\s+completed",
    re.IGNORECASE,
)

# ── Services supportés ───────────────────────────────────────────

SERVICE_PROTOCOLS: dict[str, str] = {
    "ssh": "ssh",
    "ftp": "ftp",
    "http-get": "http-get",
    "http-post": "http-post",
    "smb": "smb",
    "rdp": "rdp",
    "mssql": "mssql",
    "mysql": "mysql",
    "telnet": "telnet",
    "vnc": "vnc",
    "pop3": "pop3",
    "imap": "imap",
    "ldap2": "ldap2",
    "postgres": "postgres",
    "redis": "redis",
    "smtp": "smtp",
}


@dataclass
class HydraLogin:
    """Login trouvé par Hydra."""

    service: str
    port: int
    host: str
    login: str
    password: str

    def __str__(self) -> str:
        return f"{self.service}://{self.login}:{self.password}@{self.host}:{self.port}"


class HydraWrapper(BaseCracker):
    """Wrapper asynchrone autour de Hydra.

    Usage:
        hydra = HydraWrapper()
        result = await hydra.crack(
            "target.txt",
            "users.txt",
            service="ssh",
            password_list="passwords.txt",
        )
    """

    _binary_name = "hydra"

    def __init__(self, hydra_path: str | None = None) -> None:
        super().__init__()
        self._hydra_path = hydra_path

    # ── Installation ─────────────────────────────────────────────

    @property
    def available(self) -> bool:
        if self._available is not None:
            return self._available
        if self._hydra_path:
            self._available = os.path.isfile(self._hydra_path)
        else:
            self._available = shutil.which(self._binary_name) is not None
        return self._available

    def get_version(self) -> str:
        if self._version:
            return self._version
        if not self.available:
            return ""
        binary = self._hydra_path or self._binary_name
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

    # ── Cracking ─────────────────────────────────────────────────

    def _build_args(
        self,
        target: str,
        login_options: dict[str, Any],
        service: str = "ssh",
        password_list: str = "",
        **options: Any,
    ) -> list[str]:
        """Construit la liste d'arguments pour hydra.

        Args:
            target: Cible (IP:port ou hostname:port).
            login_options: Options de login (user, pass, userlist, passwordlist).
            service: Service à attaquer (ssh, ftp, http-get, …).
            password_list: Chemin vers le fichier de mots de passe (alternative).
            **options: Options supplémentaires.

        Returns:
            Liste d'arguments pour subprocess.
        """
        binary = self._hydra_path or self._binary_name
        args: list[str] = [binary]

        # Login options
        user = login_options.get("user", "")
        userlist = login_options.get("userlist", "")
        password = login_options.get("password", "")
        passlist = login_options.get("passwordlist", password_list)

        if user:
            args.extend(["-l", user])
        if userlist:
            args.extend(["-L", userlist])
        if password:
            args.extend(["-p", password])
        if passlist:
            args.extend(["-P", passlist])

        # Tasks (threads)
        tasks = options.get("tasks", 4)
        args.extend(["-t", str(tasks)])

        # Wait (delay between attempts)
        wait = options.get("wait", 0)
        if wait > 0:
            args.extend(["-w", str(wait)])

        # Exit on first find
        if options.get("exit_first", True):
            args.append("-f")

        # Verbose
        if options.get("verbose", False):
            args.append("-V")

        # Timeout
        timeout = options.get("timeout", 30)
        args.extend(["-s", str(options.get("port", 0)) or None])

        # Service
        args.extend(["-s", str(login_options.get("port", 0))])

        # Target
        args.append(target)

        # Service
        args.append(service)

        # Port (optionnel, via -s)
        port = login_options.get("port", 0)
        if port:
            args.append(f"-s{port}")

        # Nettoyer les None
        args = [a for a in args if a is not None]

        return args

    def _parse_output(self, stdout: str) -> list[HydraLogin]:
        """Parse la sortie d'Hydra pour extraire les logins trouvés.

        Args:
            stdout: Sortie brute d'Hydra.

        Returns:
            Liste de HydraLogin trouvés.
        """
        logins: list[HydraLogin] = []
        for match in RE_HYDRA_LOGIN.finditer(stdout):
            port = int(match.group(1))
            service = match.group(2)
            host = match.group(3)
            login = match.group(4)
            password = match.group(5)
            logins.append(
                HydraLogin(
                    service=service,
                    port=port,
                    host=host,
                    login=login,
                    password=password,
                )
            )
        return logins

    async def crack(
        self,
        hash_file: str,
        wordlist: str,
        **options: Any,
    ) -> CrackResult:
        """Lance Hydra en subprocess asynchrone.

        Note: hash_file et wordlist sont réinterprétés pour Hydra :
            - hash_file = target (IP:hostname)
            - wordlist = fichier de mots de passe (passlist)
            - options['userlist'] = fichier d'utilisateurs
            - options['user'] = utilisateur unique

        Args:
            hash_file: Cible (IP:port ou hostname:port).
            wordlist: Fichier de mots de passe.
            **options:
                service: Service (ssh, ftp, http-get, …).
                user: Nom d'utilisateur unique.
                userlist: Fichier d'utilisateurs.
                password: Mot de passe unique.
                tasks: Nombre de tâches/threads (défaut: 4).
                wait: Délai entre tentatives (secondes, défaut: 0).
                exit_first: S'arrêter au premier succès (défaut: True).
                verbose: Mode verbeux (défaut: False).
                port: Port à attaquer (0 = port par défaut du service).
                timeout: Timeout global (secondes, défaut: 600).

        Returns:
            CrackResult avec les identifiants trouvés.
        """
        result = CrackResult()

        if not self.available:
            result.status = CrackStatus.ERROR
            result.error = f"{self._binary_name} n'est pas installé"
            return result

        # Paramètres Hydra
        target = hash_file
        service = options.get("service", "ssh")

        if service not in SERVICE_PROTOCOLS:
            result.status = CrackStatus.ERROR
            result.error = (
                f"Service non supporté: '{service}'. "
                f"Supportés: {', '.join(sorted(SERVICE_PROTOCOLS.keys()))}"
            )
            return result

        login_options = {
            "user": options.get("user", ""),
            "userlist": options.get("userlist", ""),
            "password": options.get("password", ""),
            "passwordlist": wordlist,
            "port": options.get("port", 0),
        }

        logger.info(
            "hydra_start",
            target=target,
            service=service,
            user=login_options["user"] or "<userlist>",
        )

        # Retirer service de options pour éviter le double passage
        crack_opts = {k: v for k, v in options.items() if k != "service"}
        args = self._build_args(target, login_options, service=service, **crack_opts)
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

            # Parser les logins trouvés
            logins = self._parse_output(stdout_str)

            if logins:
                best = logins[0]
                result.status = CrackStatus.SUCCESS
                result.cracked_password = f"{best.login}:{best.password}"
                result.hash_type = service  # On stocke le service dans hash_type
                logger.info(
                    "hydra_success",
                    service=service,
                    host=best.host,
                    login=best.login,
                    password=best.password,
                )
            elif proc.returncode == 0:
                result.status = CrackStatus.FAILED
                result.error = (
                    "Hydra terminé sans trouver d'identifiants valides"
                )
            elif proc.returncode == 255:
                result.status = CrackStatus.ERROR
                result.error = (
                    "Hydra a rencontré une erreur fatale (code 255). "
                    "Vérifiez la cible et les permissions."
                )
            else:
                result.status = CrackStatus.ERROR
                result.error = (
                    f"Hydra terminé avec le code {proc.returncode}"
                )

        except FileNotFoundError:
            result.status = CrackStatus.ERROR
            result.error = f"Binaire {self._binary_name} introuvable"
        except Exception as e:
            result.status = CrackStatus.ERROR
            result.error = f"Erreur inattendue: {e!s}"
            logger.exception("hydra_unexpected_error")

        return result

    def list_services(self) -> dict[str, str]:
        """Liste les services supportés par Hydra.

        Returns:
            Dictionnaire {service: description}.
        """
        return {s: s for s in SERVICE_PROTOCOLS}
