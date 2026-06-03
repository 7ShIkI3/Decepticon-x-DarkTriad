"""Migration runner for the KG schema.

Reads ``V*.cypher`` files from ``kg_internal/migrations/``, executes
the pending ones in filename order, and records applied names in a
``:MigrationLog`` node so reruns no-op. Each Cypher file is split on
``;`` boundaries (after line-comment stripping) and run statement by
statement via :meth:`KGStore.execute_write`.

The runner uses the reserved engagement label ``"schema"`` because the
``MigrationLog`` and schema DDL are out-of-band of any real engagement.
The label is documented as reserved in
``docs/design/2026-06-03-kg-middleware-implementation-research.md``.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from decepticon.middleware.kg_internal.store import KGStore
from decepticon_core.utils.logging import get_logger

log = get_logger("kg.migrations")

_DEFAULT_MIGRATIONS_DIR = Path(__file__).parent / "migrations"

# Reserved engagement label for schema operations. Real engagements
# never use this name (it's lowercase, structurally valid, and
# semantically clear in any Cypher trace).
_MIGRATION_ENGAGEMENT = "schema"


def _strip_line_comments(text: str) -> str:
    """Remove ``-- ...`` line comments before statement splitting.

    Cypher does not have block comments. Line comments end at the next
    newline. Stripping them up-front is safe because they cannot
    contain semicolons that would survive into the splitter.
    """
    out_lines: list[str] = []
    for line in text.splitlines():
        idx = line.find("--")
        if idx != -1:
            line = line[:idx]
        out_lines.append(line)
    return "\n".join(out_lines)


def _split_cypher_statements(text: str) -> list[str]:
    """Split a multi-statement Cypher file into individual statements.

    Cypher statements are separated by ``;``. Empty statements (e.g.
    trailing semicolons after the last command) are dropped. Returned
    statements are stripped of surrounding whitespace.
    """
    body = _strip_line_comments(text)
    chunks = [chunk.strip() for chunk in body.split(";")]
    return [chunk for chunk in chunks if chunk]


def list_applied(store: KGStore) -> set[str]:
    """Return the names of migrations already recorded as applied.

    On a fresh Neo4j (no constraints, no MigrationLog) the underlying
    MATCH returns an empty result rather than raising, so this is safe
    to call before V001 has ever run.
    """
    cypher = "MATCH (m:MigrationLog) RETURN m.name AS name"
    rows = store.execute_read(cypher, {}, engagement=_MIGRATION_ENGAGEMENT)
    return {str(row["name"]) for row in rows if row.get("name")}


def apply_migrations(
    store: KGStore,
    *,
    migrations_dir: Path | None = None,
) -> list[str]:
    """Apply pending ``V*.cypher`` migrations in filename order.

    Returns the list of newly-applied migration names (excluding ones
    that were already recorded). Idempotent — calling twice in a row
    runs the second invocation with no Cypher executed.

    Raises whatever the driver raises if a statement fails. Failure
    rolls back its own write transaction; previously-applied
    migrations in the same call remain recorded.
    """
    chosen_dir = migrations_dir or _DEFAULT_MIGRATIONS_DIR
    cypher_files = sorted(chosen_dir.glob("V*.cypher"))
    if not cypher_files:
        log.info("no KG migrations found in %s", chosen_dir)
        return []

    applied = list_applied(store)
    new_applied: list[str] = []

    for path in cypher_files:
        name = path.stem  # e.g. "V001__initial_schema"
        if name in applied:
            log.debug("KG migration %s already applied; skipping", name)
            continue
        cypher_text = path.read_text(encoding="utf-8")
        sha = hashlib.sha256(cypher_text.encode("utf-8")).hexdigest()
        statements = _split_cypher_statements(cypher_text)
        log.info(
            "applying KG migration %s (statements=%d sha=%s)",
            name,
            len(statements),
            sha[:8],
        )
        for stmt in statements:
            store.execute_write(stmt, {}, engagement=_MIGRATION_ENGAGEMENT)
        store.execute_write(
            (
                "MERGE (m:MigrationLog {name: $name}) "
                "ON CREATE SET m.applied_at = $now, m.cypher_sha = $sha, "
                "              m.engagement = $engagement"
            ),
            {
                "name": name,
                "now": int(time.time()),
                "sha": sha,
                "engagement": _MIGRATION_ENGAGEMENT,
            },
            engagement=_MIGRATION_ENGAGEMENT,
        )
        new_applied.append(name)

    return new_applied
