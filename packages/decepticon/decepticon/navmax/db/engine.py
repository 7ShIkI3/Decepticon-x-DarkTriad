"""Moteur SQLAlchemy asynchrone — session factory, pool configuré, création des tables.

Optimisations appliquées :
  - pool_size / max_overflow / pool_recycle / pool_pre_ping
  - echo conditionnel sur debug
  - timeout de connexion configurable
"""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from decepticon.navmax.core.config import config
from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)

# ── Configuration du pool ───────────────────────────────────────────
# SQLite (aiosqlite) ignore ces paramètres, mais PostgreSQL et autres
# les utilisent pour une gestion optimale des connexions.
_POOL_SIZE = 10          # connexions permanentes dans le pool
_MAX_OVERFLOW = 20       # connexions supplémentaires temporaires
_POOL_RECYCLE = 3600     # recycler les connexions après 1h
_POOL_PRE_PING = True    # vérifier la connexion avant de l'utiliser
_POOL_TIMEOUT = 30       # timeout d'attente d'une connexion libre

engine = create_async_engine(
    config.database_url,
    echo=config.debug,
    future=True,
    pool_size=_POOL_SIZE,
    max_overflow=_MAX_OVERFLOW,
    pool_recycle=_POOL_RECYCLE,
    pool_pre_ping=_POOL_PRE_PING,
    pool_timeout=_POOL_TIMEOUT,
)

async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def create_all() -> None:
    """Crée toutes les tables en base."""
    from .models import Base  # noqa: PLC0415

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await _create_indexes()
    logger.info("tables_créées_et_indexées")


async def drop_all() -> None:
    """Supprime toutes les tables (⚠️ dév uniquement)."""
    from .models import Base  # noqa: PLC0415

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    logger.warning("tables_supprimées")


async def _create_indexes() -> None:
    """Crée les index manquants pour les performances des queries fréquentes.

    Certains index sont déclarés dans models.py via ``Index(...)``,
    d'autres sont créés ici pour les colonnes FK fréquemment filtrées
    qui n'ont pas d'index automatique.
    """
    indexes = [
        # AuditEntry — recherches par workspace et phase
        "CREATE INDEX IF NOT EXISTS idx_audit_workspace_id ON audit_entries(workspace_id);",
        "CREATE INDEX IF NOT EXISTS idx_audit_phase_id ON audit_entries(phase_id);",
        "CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_entries(created_at);",
        "CREATE INDEX IF NOT EXISTS idx_audit_action_module ON audit_entries(action, module);",

        # Scan — recherches par target et status
        "CREATE INDEX IF NOT EXISTS idx_scan_target_id ON scans(target_id);",
        "CREATE INDEX IF NOT EXISTS idx_scan_status ON scans(status);",
        "CREATE INDEX IF NOT EXISTS idx_scan_created_at ON scans(created_at);",

        # Service — recherches par target et port
        "CREATE INDEX IF NOT EXISTS idx_service_target_id ON services(target_id);",
        "CREATE INDEX IF NOT EXISTS idx_service_port ON services(port);",
        "CREATE INDEX IF NOT EXISTS idx_service_target_port ON services(target_id, port);",
        "CREATE INDEX IF NOT EXISTS idx_service_service_name ON services(service_name);",

        # Vulnerability — recherches par target, CVE, severity
        "CREATE INDEX IF NOT EXISTS idx_vuln_target_id ON vulnerabilities(target_id);",
        "CREATE INDEX IF NOT EXISTS idx_vuln_cve_id ON vulnerabilities(cve_id);",
        "CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);",
        "CREATE INDEX IF NOT EXISTS idx_vuln_detected_at ON vulnerabilities(detected_at);",

        # Target — recherche par workspace et adresse
        "CREATE INDEX IF NOT EXISTS idx_target_workspace_id ON targets(workspace_id);",
        "CREATE INDEX IF NOT EXISTS idx_target_alive ON targets(alive);",
        "CREATE INDEX IF NOT EXISTS idx_target_kind ON targets(kind);",
    ]

    async with engine.begin() as conn:
        for stmt in indexes:
            try:
                await conn.execute(stmt)
            except Exception as exc:
                logger.warning("index_creation_ignored", stmt=stmt[:60], error=str(exc))

    logger.info("index_créés", count=len(indexes))


async def get_session() -> AsyncSession:  # type: ignore[empty-body]
    """Dépendance FastAPI : fournit une session DB."""
    async with async_session() as session:
        yield session
