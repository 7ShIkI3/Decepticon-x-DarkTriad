"""Cypher migrations for the KG schema.

Each migration is a ``V###__description.cypher`` file. Applied in
filename order by ``migration_runner.apply_migrations``. Idempotent:
all statements use ``IF NOT EXISTS`` so re-running is a no-op.

The runner records applied migration names in a ``:MigrationLog`` node
so a fresh container picks up where the last left off without rerunning
anything.
"""

from __future__ import annotations
