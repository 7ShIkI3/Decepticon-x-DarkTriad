"""Neo4j-backed storage for the skillogy service.

Replaces the in-memory ``SkillRegistry`` (kept in ``registry.py`` for
the migration window). The server now opens a Bolt session to the same
Neo4j instance that ``skillogy.builder`` populates via ``skills.cypher``.

The wire protocol stays the same — the same ``SkillEnvelope`` /
``SkillMeta`` proto types are returned — but every read now answers from
the live graph instead of an in-memory dict.

Read-only enforcement
---------------------
Server-driven Cypher (``run_cypher_read`` RPC, Phase 1b-onwards
``recall``) is the obvious attack surface. The backend enforces three
defenses, layered: ``default_access_mode=READ`` on the Bolt session
(server-side), AST-style keyword denylist applied to the inbound
``query`` string (belt-and-suspenders), and a per-query parameter cap
+ row-count cap so a malformed query can't exhaust the agent context.
"""

from __future__ import annotations

import logging
import re
from typing import Any

log = logging.getLogger(__name__)

# Write-mode Cypher keywords we refuse to forward, even though the
# Neo4j driver session is also opened in READ mode. The check is
# whole-word, case-insensitive, after stripping line comments + string
# literals so a benign body like "// MERGE example" cannot be flagged.
_WRITE_KEYWORDS = (
    "CREATE",
    "MERGE",
    "SET",
    "DELETE",
    "DETACH",
    "REMOVE",
    "DROP",
    "LOAD",
    "USING PERIODIC COMMIT",
    "FOREACH",
)


class CypherWriteRejected(ValueError):
    """Raised when a client query trips the write-keyword denylist."""


_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_STRING_RE = re.compile(r"'([^'\\]|\\.)*'|\"([^\"\\]|\\.)*\"")
_WORD_BOUNDARY = r"(?<![A-Za-z_])({kw})(?![A-Za-z_])"


def _strip_noise(query: str) -> str:
    """Drop line comments + string literals before keyword scanning."""
    no_comments = _LINE_COMMENT_RE.sub("", query)
    return _STRING_RE.sub("''", no_comments)


def assert_read_only(query: str) -> None:
    """Raise ``CypherWriteRejected`` if ``query`` contains a write keyword."""
    cleaned = _strip_noise(query)
    for kw in _WRITE_KEYWORDS:
        pattern = _WORD_BOUNDARY.format(kw=re.escape(kw))
        if re.search(pattern, cleaned, flags=re.IGNORECASE):
            raise CypherWriteRejected(
                f"Cypher write keyword {kw!r} is not allowed in read-only RPC"
            )


class Neo4jBackend:
    """Thin Bolt wrapper used by the FastAPI / grpcio server.

    Created once at server boot, shared across requests. Holds a single
    driver instance; sessions are short-lived (request-scoped). The
    driver is closed in ``close()`` so unit tests with testcontainers
    can tear it down deterministically.
    """

    def __init__(
        self,
        *,
        uri: str,
        user: str,
        password: str,
        database: str = "neo4j",
        max_rows: int = 200,
    ) -> None:
        try:
            from neo4j import GraphDatabase  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError(
                "Skillogy server requires the neo4j driver. Install with: pip install neo4j>=5.24"
            ) from exc
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
        self._database = database
        self._max_rows = max_rows

    def close(self) -> None:
        self._driver.close()

    # ---- skill ops ----

    def load_skill(self, path: str) -> dict[str, Any] | None:
        """Fetch one ``:Skill`` node by canonical path. Returns its full
        property dict, or ``None`` if no such skill exists."""
        query = "MATCH (s:Skill {path: $path}) RETURN properties(s) AS props"
        with self._driver.session(database=self._database, default_access_mode="READ") as session:
            result = session.run(query, path=path).single()
        return None if result is None else dict(result["props"])

    def health(self) -> dict[str, Any]:
        """Return service liveness + a count of :Skill nodes in the graph."""
        query = "MATCH (s:Skill) RETURN count(s) AS skill_count"
        with self._driver.session(database=self._database, default_access_mode="READ") as session:
            result = session.run(query).single()
        skill_count = 0 if result is None else int(result["skill_count"])
        return {"status": "ok", "skill_count": skill_count}

    # ---- relationship-aware search (used by find_skill RPC) ----

    def find_skill(
        self,
        *,
        query: str | None = None,
        subdomain: str | None = None,
        mitre_id: str | None = None,
        tag: str | None = None,
        tactic_id: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Relationship-aware skill discovery.

        Composable filters combined with AND semantics. Each filter
        prunes the candidate set via a different edge:

        - ``query``: substring match on name / description / when_to_use.
          Cheap signal for when the agent has a keyword like "kerberoast"
          but not a path.
        - ``subdomain``: ``(s:Skill)-[:IN_PHASE]->(:Phase {name: $sub})``.
        - ``mitre_id``: ``(s:Skill)-[:IMPLEMENTS]->(:Technique {id: $id})``
          where ``$id`` can be a top-level T1xxx or a sub-T1xxx.yyy.
        - ``tag``: ``(s:Skill)-[:TAGGED]->(:Tag {name: $tag})``.
        - ``tactic_id``: anchors on a Tactic, follows ``HAS_TECHNIQUE`` to
          its techniques, then back to skills via ``IMPLEMENTS``. Lets
          the agent ask "show me skills covering Initial Access".

        Returns each match's ``name``, ``path``, ``subdomain``,
        ``description`` and the matched dimensions (``matched_mitre``,
        ``matched_tags``) so the agent can see *why* a skill came back.
        """
        wheres: list[str] = []
        params: dict[str, Any] = {"limit": int(min(max(limit, 1), 100))}
        # Path A: subdomain-anchored
        if subdomain:
            wheres.append("(s)-[:IN_PHASE]->(:Phase {name: $subdomain})")
            params["subdomain"] = subdomain
        # Path B: tag-anchored
        if tag:
            wheres.append("(s)-[:TAGGED]->(:Tag {name: $tag})")
            params["tag"] = tag
        # Path C: technique-anchored (direct)
        if mitre_id:
            wheres.append("(s)-[:IMPLEMENTS]->(:Technique {id: $mitre_id})")
            params["mitre_id"] = mitre_id
        # Path D: tactic-anchored (one hop via Technique)
        if tactic_id:
            wheres.append(
                "(s)-[:IMPLEMENTS]->(:Technique)<-[:HAS_TECHNIQUE]-(:Tactic {id: $tactic_id})"
            )
            params["tactic_id"] = tactic_id
        # Path E: keyword search across name / description / triggers.
        if query:
            wheres.append(
                "(toLower(s.name) CONTAINS toLower($query) "
                "OR toLower(s.description) CONTAINS toLower($query) "
                "OR toLower(s.when_to_use) CONTAINS toLower($query))"
            )
            params["query"] = query
        if not wheres:
            raise ValueError(
                "find_skill requires at least one of: query, subdomain, mitre_id, tag, tactic_id"
            )
        match_clauses = " AND ".join(wheres)
        cypher = (
            "MATCH (s:Skill) "
            f"WHERE {match_clauses} "
            "OPTIONAL MATCH (s)-[:IMPLEMENTS]->(t:Technique) "
            "OPTIONAL MATCH (s)-[:TAGGED]->(tag:Tag) "
            "WITH s, collect(DISTINCT t.id) AS matched_mitre, "
            "     collect(DISTINCT tag.name) AS matched_tags "
            "RETURN s.name AS name, s.path AS path, s.subdomain AS subdomain, "
            "       s.description AS description, "
            "       matched_mitre, matched_tags "
            "ORDER BY name "
            "LIMIT $limit"
        )
        with self._driver.session(database=self._database, default_access_mode="READ") as session:
            return [dict(record) for record in session.run(cypher, parameters=params)]

    # ---- explicit graph traversal (used by traverse RPC) ----

    def traverse(
        self, from_path: str, edge_types: list[str] | None = None, depth: int = 2
    ) -> list[dict[str, Any]]:
        """Variable-length BFS from a Skill node along whitelisted edge types.

        Returns the neighbouring nodes flattened, each with its
        ``label``, key identifier, depth from the seed, and a string
        representation of the connecting edge type.
        """
        depth = max(1, min(int(depth), 5))
        # Default edge whitelist mirrors the spec §5.7.2 list.
        whitelist = edge_types or [
            "IN_PHASE",
            "IMPLEMENTS",
            "TAGGED",
            "BELONGS_TO",
            "RELATED_TO",
            "HAS_TECHNIQUE",
            "HAS_SUBTECHNIQUE",
        ]
        # Cypher relationship pattern: ``[r:A|B|C*1..N]``.
        rel_pattern = f"[r:{'|'.join(whitelist)}*1..{depth}]"
        cypher = (
            "MATCH (seed:Skill {path: $from_path}) "
            f"MATCH path = (seed)-{rel_pattern}-(neighbour) "
            "RETURN labels(neighbour) AS labels, "
            "       coalesce(neighbour.name, neighbour.id, neighbour.path) AS key, "
            "       length(path) AS hop_depth, "
            "       [rel IN relationships(path) | type(rel)] AS edge_chain "
            "LIMIT $cap"
        )
        with self._driver.session(database=self._database, default_access_mode="READ") as session:
            return [
                {
                    "labels": list(rec["labels"]),
                    "key": rec["key"],
                    "depth": int(rec["hop_depth"]),
                    "edge_chain": list(rec["edge_chain"]),
                }
                for rec in session.run(
                    cypher,
                    parameters={"from_path": from_path, "cap": self._max_rows},
                )
            ]

    # ---- read-only cypher escape hatch (used by run_cypher_read RPC, Phase 1a) ----

    def run_cypher_read(
        self, query: str, params: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """Execute an agent-supplied read-only Cypher query.

        ``assert_read_only`` is the syntactic guard; the Bolt session's
        ``default_access_mode='READ'`` is the server-side guard. Results
        are capped at ``self._max_rows`` so a runaway query cannot exhaust
        the agent context window or wire bandwidth.
        """
        assert_read_only(query)
        with self._driver.session(database=self._database, default_access_mode="READ") as session:
            result = session.run(query, params or {})
            return [dict(record) for record in result.fetch(self._max_rows)]
