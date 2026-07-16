"""Configuration centralisée via variables d'environnement et fichier .env."""

import re
import warnings
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Config(BaseSettings):
    """Configuration NavMAX chargée depuis l'environnement et .env."""

    model_config = SettingsConfigDict(
        env_prefix="NAVMAX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Général ---
    debug: bool = False
    data_dir: Path = Path.home() / ".navmax"
    log_level: str = "INFO"
    log_format: str = "json"  # json | console

    # --- API ---
    api_host: str = "127.0.0.1"
    api_port: int = 8443
    api_workers: int = 1

    # --- Base de données ---
    db_url: str = ""

    @property
    def database_url(self) -> str:
        """Retourne l'URL de la BDD (SQLite par défaut).

        Les credentials présents dans l'URL ne sont pas loggués.
        """
        if self.db_url:
            return self.db_url
        db_path = self.data_dir / "navmax.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite+aiosqlite:///{db_path}"

    @property
    def database_url_safe(self) -> str:
        """Retourne l'URL de la BDD avec les credentials masqués (safe pour les logs)."""
        url = self.database_url
        # Masque user:password@host → ***@host
        return re.sub(r"//[^@]+@", "//***@", url)

    # --- Scanner ---
    scanner_default_timeout: float = 2.0  # secondes
    scanner_default_ports: str = (
        "22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,27017"
    )
    scanner_max_concurrency: int = 100
    scanner_udp_enabled: bool = False  # UDP nécessite admin

    # --- Proxy ---
    proxy_port: int = 8080
    proxy_ca_dir: Path = Path.home() / ".navmax" / "certs"

    # --- Exploit ---
    exploit_modules_dir: Path = Path.home() / ".navmax" / "exploits"
    exploit_payload_dir: Path = Path.home() / ".navmax" / "payloads"

    # --- JWT ---
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # --- Redis (rate limiting & cache) ---
    redis_url: str = ""  # ex: redis://localhost:6379/0

    def validate_critical(self) -> None:
        """Valide les valeurs critiques de la configuration et émet des avertissements."""
        if self.jwt_secret and len(self.jwt_secret) < 32:
            warnings.warn(
                f"[NavMAX] NAVMAX_JWT_SECRET trop court ({len(self.jwt_secret)} chars) — "
                "minimum recommandé : 32 caractères.",
                UserWarning,
                stacklevel=2,
            )
        elif not self.jwt_secret:
            warnings.warn(
                "[NavMAX] NAVMAX_JWT_SECRET absent — l'authentification JWT sera non sécurisée.",
                UserWarning,
                stacklevel=2,
            )


# Instance globale
config = Config()
config.validate_critical()
