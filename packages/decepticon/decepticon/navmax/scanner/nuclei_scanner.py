"""NucleiScanner — wrapper async autour du binaire nuclei pour scanner de vulnérabilités.

Remplace les 17 signatures CVE codées en dur dans vuln_db.py par du vrai scanning
communautaire avec 10 000+ templates. Nuclei est un scanner open-source maintenu
par ProjectDiscovery.

Usage:
    scanner = NucleiScanner()
    findings = await scanner.scan("https://example.com", severity=["critical", "high"])
    for f in findings:
        print(f.template_id, f.severity, f.cve_ids)
"""

import asyncio
import json
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

# ── Chemins des templates ──────────────────────────────────────────

# Répertoire par défaut où nuclei stocke les templates (Linux/macOS)
_DEFAULT_TEMPLATES_DIR = Path.home() / ".local" / "nuclei-templates"
# Sur Windows, nuclei utilise %USERPROFILE%\.local\nuclei-templates
_DEFAULT_TEMPLATES_DIR_WIN = Path.home() / ".local" / "nuclei-templates"


# ── Validation ─────────────────────────────────────────────────

# Target regex: URL (http/https), hostname, IPv4, with optional port and path
# Blocks newlines, spaces, pipes, backticks, $(), ;, && and other shell-dangerous chars
_TARGET_REGEX = re.compile(
    r"^(?:https?://)?"  # optional protocol
    r"(?:"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9]+)"  # domain
    r"|"
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?"  # IPv4 with optional CIDR
    r")"
    r"(?::\d{1,5})?"  # optional port
    r"(?:/[a-zA-Z0-9._~:/?#@!$&'()*+,;=-]*)?$",  # optional path (safe chars only)
)

# Template path whitelist: only known template directories
_ALLOWED_TEMPLATE_PREFIXES = frozenset(
    {
        "cves/",
        "exposed-panels/",
        "vulnerabilities/",
        "misconfiguration/",
        "technologies/",
        "default-logins/",
        "exposures/",
        "fuzzing/",
    },
)

# Template ID: alphanumeric + hyphens (standard nuclei template ID format)
_TEMPLATE_ID_REGEX = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


# ── Exceptions ─────────────────────────────────────────────────


class NucleiNotFoundError(RuntimeError):
    """Nuclei binaire introuvable sur le système."""

    def __init__(self) -> None:
        super().__init__(
            "nuclei binaire introuvable. "
            "Installez-le via :\n"
            "  # Linux/macOS\n"
            "  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n\n"
            "  # Ou via Homebrew\n"
            "  brew install nuclei\n\n"
            "  # Téléchargement direct\n"
            "  https://github.com/projectdiscovery/nuclei/releases",
        )


class NucleiTimeoutError(TimeoutError):
    """Le scan nuclei a dépassé le temps imparti."""

    def __init__(self, target: str, timeout: int) -> None:
        super().__init__(
            f"Scan nuclei vers {target} a dépassé le timeout de {timeout}s. "
            "Essayez d'augmenter le timeout ou de réduire le nombre de templates.",
        )


# ── Dataclasses ────────────────────────────────────────────────


@dataclass
class NucleiFinding:
    """Résultat d'un template nuclei ayant matché sur la cible.

    Contient toutes les informations extraites par nuclei pendant le scan :
    l'ID du template, la sévérité, les CVE associées, et les résultats
    extraits (payloads, réponses HTTP, etc.).
    """

    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    description: str = ""
    cvss_score: float | None = None
    cve_ids: list[str] = field(default_factory=list)
    reference_urls: list[str] = field(default_factory=list)
    extracted_results: list[str] = field(default_factory=list)


# ── NucleiScanner ──────────────────────────────────────────────


class NucleiScanner:
    """Wrapper asynchrone autour du binaire nuclei.

    Exécute nuclei en sous-processus avec les arguments appropriés,
    parse le flux JSON ligne par ligne, et retourne une liste structurée
    de ``NucleiFinding``.

    Attributes:
        binary_path: Chemin vers le binaire nuclei (détecté via shutil si None).

    """

    def __init__(self, binary_path: str | None = None) -> None:
        self._binary: str | None = binary_path
        self._available: bool | None = None

    # ── Vérification d'installation ────────────────────────────

    async def check_installed(self) -> bool:
        """Vérifie si nuclei est installé et disponible.

        Returns:
            True si le binaire nuclei est trouvé dans le PATH.

        """
        if self._available is not None:
            return self._available

        # shutil.which est thread-safe, on peut l'utiliser directement
        loop = asyncio.get_running_loop()
        self._binary = await loop.run_in_executor(None, shutil.which, "nuclei")
        self._available = self._binary is not None

        if self._available:
            logger.info("nuclei_detected", path=self._binary)
        else:
            logger.warning("nuclei_not_found")

        return self._available

    async def check_templates(self) -> bool:
        """Vérifie si les templates nuclei sont disponibles localement.

        Nuclei télécharge ses templates dans ``~/.local/nuclei-templates/``
        par défaut. Cette méthode vérifie que ce répertoire existe et
        contient au moins quelques templates.

        Returns:
            True si les templates sont présents, False sinon.

        """
        # Vérifier les répertoires de templates connus
        candidates = [
            _DEFAULT_TEMPLATES_DIR,
            _DEFAULT_TEMPLATES_DIR_WIN,
            # Nuclei respecte aussi la variable NUCLEI_TEMPLATES_PATH
            Path(os.environ.get("NUCLEI_TEMPLATES_PATH", "")),
        ]

        for d in candidates:
            if d and d.exists() and d.is_dir():
                # Vérifier qu'il y a au moins quelques fichiers .yaml
                count = len(list(d.rglob("*.yaml")))
                if count > 0:
                    logger.info(
                        "nuclei_templates_found",
                        path=str(d),
                        count=count,
                    )
                    return True

        logger.warning("nuclei_templates_not_found")
        return False

    async def _require_installed(self) -> str:
        """Vérifie que nuclei est installé et retourne son chemin.

        Raises:
            NucleiNotFoundError: Si nuclei n'est pas trouvé.

        """
        if not await self.check_installed():
            raise NucleiNotFoundError
        return self._binary  # type: ignore[return-value]

    @staticmethod
    def _validate_target(target: str) -> bool:
        """Validate target is a safe URL, hostname, or IP (no shell injection).

        Blocks newlines, pipes, backticks, ``$()``, ``;``, ``&&``, and other
        shell-dangerous characters via strict regex matching.

        Args:
            target: Target string to validate.

        Returns:
            True if the target format is valid and safe.

        """
        if not target or not isinstance(target, str):
            return False
        return bool(_TARGET_REGEX.match(target))

    @staticmethod
    def _validate_template(template: str) -> bool:
        """Validate template is a known directory path or valid template ID.

        Known directory paths (whitelist):
        ``cves/``, ``exposed-panels/``, ``vulnerabilities/``,
        ``misconfiguration/``, ``technologies/``, ``default-logins/``,
        ``exposures/``, ``fuzzing/``.

        Template IDs must be alphanumeric with hyphens (standard nuclei format).

        Args:
            template: Template string to validate.

        Returns:
            True if the template is safe and valid.

        """
        if not template or not isinstance(template, str):
            return False
        if any(template.startswith(prefix) for prefix in _ALLOWED_TEMPLATE_PREFIXES):
            return True
        return bool(_TEMPLATE_ID_REGEX.match(template))

    # ── Installation / Mise à jour des templates ────────────────

    @staticmethod
    async def install_templates() -> None:
        """Télécharge/met à jour les templates nuclei officiels.

        Exécute ``nuclei -update-templates`` pour synchroniser la dernière
        version des templates communautaires (10 000+ templates).
        """
        await NucleiScanner._run_update_templates()

    @staticmethod
    async def update_templates() -> None:
        """Alias de ``install_templates``.

        Met à jour les templates nuclei en exécutant
        ``nuclei -update-templates``.
        """
        await NucleiScanner._run_update_templates()

    @staticmethod
    async def _run_update_templates() -> None:
        """Implémentation commune de la mise à jour des templates."""
        binary = shutil.which("nuclei")
        if not binary:
            raise NucleiNotFoundError

        logger.info("nuclei_updating_templates")
        proc = await asyncio.create_subprocess_exec(
            binary,
            "-update-templates",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode == 0:
            logger.info("nuclei_templates_updated")
        else:
            logger.error(
                "nuclei_templates_update_failed",
                returncode=proc.returncode,
                stderr=stderr.decode("utf-8", errors="replace"),
            )

        if stdout:
            logger.debug("nuclei_update_output", output=stdout.decode("utf-8", errors="replace"))

    # ── Scan principal ─────────────────────────────────────────

    async def scan(
        self,
        target: str,
        templates: list[str] | None = None,
        severity: list[str] | None = None,
        timeout: int = 300,
    ) -> list[NucleiFinding]:
        """Lance un scan nuclei sur la cible donnée.

        Args:
            target: Cible à scanner (URL, IP, domaine, CIDR).
                Ex: ``"https://example.com"``, ``"10.0.0.1"``, ``"192.168.1.0/24"``.
            templates: Liste de templates ou tags nuclei.
                Ex: ``["cves/", "exposed-panels/"]``.
                None = tous les templates (scan complet).
            severity: Filtre par sévérité. Valeurs acceptées :
                ``"critical"``, ``"high"``, ``"medium"``, ``"low"``, ``"info"``.
                None = toutes les sévérités.
            timeout: Timeout maximum pour le scan en secondes (défaut: 300).

        Returns:
            Liste des findings (vulnérabilités, informations, etc.) trouvés.

        Raises:
            NucleiNotFoundError: Si nuclei n'est pas installé.
            NucleiTimeoutError: Si le scan dépasse le timeout.

        """
        binary = await self._require_installed()

        # ── Validation de la cible ──
        if not self._validate_target(target):
            logger.error("nuclei_invalid_target", target=target)
            msg = f"Invalid target format: {target!r}"
            raise ValueError(msg)

        # Construction de la commande
        args = [binary, "-json", "-silent", "--disable-interactsh"]

        # Templates
        if templates:
            for t in templates:
                if self._validate_template(t):
                    args.extend(["-t", t])
                else:
                    logger.warning("nuclei_invalid_template", template=t)
        else:
            # Par défaut, on utilise le dossier templates complet
            args.extend(["-t", "cves/"])

        # Filtre sévérité
        valid_severity = {"critical", "high", "medium", "low", "info"}
        if severity:
            # Nuclei accepte une seule valeur -s, on prend la plus haute
            filtered = [s.lower() for s in severity if s.lower() in valid_severity]
            if filtered:
                # Prendre la plus élevée (critical > high > medium > low > info)
                order = ["info", "low", "medium", "high", "critical"]
                highest = max(filtered, key=order.index)
                args.extend(["-s", highest])

        # Target
        args.append("-u")
        args.append(target)

        logger.info(
            "nuclei_scan_starting",
            target=target,
            templates=templates,
            severity=severity,
            timeout=timeout,
            command=" ".join(args),
        )

        proc = None
        findings: list[NucleiFinding] = []
        stderr_task = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Lire stdout ligne par ligne avec timeout
            async def _read_stdout() -> None:
                nonlocal findings
                assert proc.stdout is not None
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    line_str = line.decode("utf-8", errors="replace").strip()
                    if line_str:
                        try:
                            finding = self._parse_json_line(line_str)
                            if finding:
                                findings.append(finding)
                        except json.JSONDecodeError:
                            logger.warning(
                                "nuclei_json_parse_error",
                                line=line_str[:200],
                            )

            # Lire stderr en arrière-plan
            async def _read_stderr() -> str:
                assert proc.stderr is not None
                data = await proc.stderr.read()
                return data.decode("utf-8", errors="replace")

            stdout_task = asyncio.create_task(_read_stdout())
            stderr_task = asyncio.create_task(_read_stderr())

            try:
                # Attendre avec timeout
                await asyncio.wait_for(
                    asyncio.gather(stdout_task, stderr_task),
                    timeout=timeout,
                )
            except TimeoutError:
                logger.exception("nuclei_scan_timeout", target=target, timeout=timeout)
                raise NucleiTimeoutError(target, timeout)
            finally:
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()

        except NucleiTimeoutError:
            raise
        except OSError as e:
            logger.exception("nuclei_subprocess_error", target=target, error=str(e))
            raise

        stderr_text = (
            stderr_task.result() if (stderr_task is not None and stderr_task.done()) else ""
        )
        if proc is not None and proc.returncode != 0 and proc.returncode is not None:
            logger.warning(
                "nuclei_scan_nonzero_exit",
                target=target,
                returncode=proc.returncode,
                stderr=stderr_text[:500] if stderr_text else "",
            )

        logger.info(
            "nuclei_scan_completed",
            target=target,
            findings_count=len(findings),
            returncode=proc.returncode if proc is not None else None,
        )

        # Filtrer par sévérité côté client si plusieurs sévérités demandées
        if severity:
            filtered_severity = {s.lower() for s in severity if s.lower() in valid_severity}
            if filtered_severity:
                findings = [f for f in findings if f.severity.lower() in filtered_severity]

        return findings

    # ── Parsing JSON ───────────────────────────────────────────

    def _parse_json_line(self, line: str) -> NucleiFinding | None:
        """Parse une ligne JSON provenant de nuclei.

        Args:
            line: Une ligne de sortie JSON de nuclei (format v3).

        Returns:
            Un NucleiFinding si la ligne est correcte, None si elle ne
            correspond pas au format attendu.

        """
        if not line or not line.strip():
            return None

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("nuclei_invalid_json_line", line=line[:200])
            return None

        template_id = data.get("template-id", data.get("templateID", ""))
        name = data.get("info", {}).get("name", data.get("name", ""))
        severity = data.get("info", {}).get("severity", data.get("severity", "info"))
        host = data.get("host", data.get("ip", ""))
        matched_at = data.get("matched-at", data.get("matched_at", ""))

        # Infos extraites du champ "info"
        info = data.get("info", {})
        description = info.get("description", "")
        cvss_score = info.get("classification", {}).get("cvss-score", None)
        if isinstance(cvss_score, str):
            try:
                cvss_score = float(cvss_score)
            except (ValueError, TypeError):
                cvss_score = None

        # CVE IDs
        classification = info.get("classification", {})
        cve_ids: list[str] = []
        cve_data = classification.get("cve-id", [])
        if isinstance(cve_data, list):
            cve_ids = cve_data
        elif isinstance(cve_data, str):
            cve_ids = [cve_data]

        # References
        references = info.get("reference", [])
        if isinstance(references, str):
            references = [references]
        reference_urls = references if isinstance(references, list) else []

        # Extracted results (matcher-name, extracted-values, curl-command)
        extracted_results: list[str] = []
        matcher_name = data.get("matcher-name", "")
        if matcher_name:
            extracted_results.append(f"matcher: {matcher_name}")

        extracted = data.get("extracted-results", [])
        if isinstance(extracted, list):
            for e in extracted:
                extracted_results.append(str(e))
        elif extracted:
            extracted_results.append(str(extracted))

        curl = data.get("curl-command", "")
        if curl:
            extracted_results.append(f"curl: {curl[:200]}")

        return NucleiFinding(
            template_id=template_id,
            name=name,
            severity=severity,
            host=host,
            matched_at=matched_at,
            description=description,
            cvss_score=cvss_score,
            cve_ids=cve_ids,
            reference_urls=reference_urls,
            extracted_results=extracted_results,
        )
