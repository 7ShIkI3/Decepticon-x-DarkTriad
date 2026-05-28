"""Defense-in-depth APOC safety check for Cypher strings.

The primary security boundary is the Neo4j server's own procedure
allowlist (see ``docs/security/neo4j-hardening.md`` and the ``neo4j``
service definition in ``docker-compose.yml``). This module is a
client-side belt-and-braces second check that inspects every Cypher
string before it is sent to the driver and rejects ones that reference
banned APOC procedures.

The intended use is at any boundary where agent-influenced strings can
reach ``session.run(cypher, **params)`` - which today means
``query_by_kind`` (the only path in ``neo4j_store.py`` that interpolates
a caller-supplied identifier into a Cypher template) and any future
tool that exposes a Cypher surface to LLM-driven inputs.

This is NOT a Cypher parser. A motivated attacker who can already
influence Cypher strings has many ways to phrase a query, and the
server-side procedure allowlist is what actually blocks execution. The
client-side check catches the obvious payload classes (file I/O,
sub-cypher, system-db reach, trigger creation) before they hit the
wire, which keeps the failure mode loud (Python exception with a
useful message) instead of silent (server rejection deep inside the
driver stack).
"""

from __future__ import annotations

import re

APOC_PROCEDURE_ALLOWLIST: frozenset[str] = frozenset(
    {
        "apoc.coll",
        "apoc.text",
        "apoc.path",
        "apoc.create",
        "apoc.merge",
        "apoc.refactor",
        "apoc.periodic",
        "apoc.lock",
        "apoc.case",
        "apoc.do",
        "apoc.when",
        "apoc.help",
        "apoc.version",
        "apoc.diff",
        "apoc.label",
        "apoc.node",
        "apoc.nodes",
        "apoc.rel",
        "apoc.util",
    }
)

APOC_PROCEDURE_DENYLIST: frozenset[str] = frozenset(
    {
        "apoc.cypher.runfile",
        "apoc.cypher.runfromfile",
        "apoc.cypher.runfiles",
        "apoc.cypher.runschema",
        "apoc.cypher.runtimeboxed",
        "apoc.cypher.parallel",
        "apoc.load.json",
        "apoc.load.jsonparams",
        "apoc.load.csv",
        "apoc.load.xml",
        "apoc.load.html",
        "apoc.load.directory",
        "apoc.load.jdbc",
        "apoc.import.csv",
        "apoc.import.json",
        "apoc.import.xml",
        "apoc.import.graphml",
        "apoc.import.file",
        "apoc.export.csv.query",
        "apoc.export.csv.all",
        "apoc.export.csv.graph",
        "apoc.export.csv.data",
        "apoc.export.json.all",
        "apoc.export.json.query",
        "apoc.export.cypher.all",
        "apoc.export.cypher.query",
        "apoc.export.graphml.all",
        "apoc.export.graphml.query",
        "apoc.export.xml.all",
        "apoc.systemdb.execute",
        "apoc.systemdb.graph",
        "apoc.trigger.add",
        "apoc.trigger.install",
        "apoc.trigger.remove",
        "apoc.trigger.removeall",
        "apoc.dbms.exec",
        "apoc.spatial.geocode",
        "apoc.uuid",
        "apoc.metrics",
    }
)

_APOC_INVOKE_RE = re.compile(
    r"\b(apoc\.[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+)",
    re.IGNORECASE,
)


class CypherSafetyError(ValueError):
    """A Cypher string referenced a banned APOC procedure."""

    def __init__(self, procedures: list[str], cypher: str) -> None:
        self.procedures = list(procedures)
        self.cypher = cypher
        super().__init__(
            f"banned APOC procedure(s) {self.procedures!r} in Cypher; "
            "see docs/security/neo4j-hardening.md for the allowlist policy"
        )


def _two_segment_prefix(proc: str) -> str:
    parts = proc.split(".")
    if len(parts) < 2:
        return proc
    return ".".join(parts[:2])


def find_violations(cypher: str) -> list[str]:
    """Return procedure names in ``cypher`` that violate the allowlist."""
    if not cypher:
        return []
    found = _APOC_INVOKE_RE.findall(cypher)
    allow_lower = {p.lower() for p in APOC_PROCEDURE_ALLOWLIST}
    deny_lower = {p.lower() for p in APOC_PROCEDURE_DENYLIST}
    violations: list[str] = []
    for raw in found:
        proc = raw.lower()
        if proc in deny_lower:
            violations.append(raw)
            continue
        if _two_segment_prefix(proc) not in allow_lower:
            violations.append(raw)
    return violations


def ensure_safe(cypher: str) -> None:
    """Raise ``CypherSafetyError`` if ``cypher`` references a banned procedure."""
    violations = find_violations(cypher)
    if violations:
        raise CypherSafetyError(procedures=violations, cypher=cypher)
