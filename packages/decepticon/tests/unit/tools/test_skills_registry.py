"""Tests for ``decepticon.tools.skills_registry`` — slug resolver + safety."""

from __future__ import annotations

from pathlib import Path

import pytest

from decepticon.tools.skills_registry import (
    SKILL_PATH_PREFIX,
    AmbiguousSkill,
    SkillRecord,
    is_safe_skill_path,
    iter_skill_records,
    list_skill_strings,
    normalize_slug,
    resolve_skill,
)


def _make_record(
    id_: str,
    *,
    slug: str | None = None,
    name: str | None = None,
    description: str = "",
    source: str = SKILL_PATH_PREFIX,
) -> SkillRecord:
    if slug is None:
        parts = id_[len(SKILL_PATH_PREFIX):].split("/")
        slug = parts[-2] if parts[-1] == "SKILL.md" else parts[-1].removesuffix(".md")
    return SkillRecord(
        id=id_, slug=slug, name=name or slug, description=description, source=source
    )


@pytest.fixture
def small_registry() -> list[SkillRecord]:
    return [
        _make_record(
            "/skills/standard/analyst/sql-injection/SKILL.md",
            description="Hunt SQL injection (CWE-89).",
        ),
        _make_record(
            "/skills/standard/analyst/auth-bypass/SKILL.md",
            description="Authentication-bypass triage.",
        ),
        _make_record(
            "/skills/standard/contracts/reentrancy/SKILL.md",
            description="Hunt reentrancy bugs in Solidity contracts.",
        ),
        _make_record(
            "/skills/standard/exploit/web/smuggling.md",
            slug="smuggling",
            description="HTTP request smuggling (HRS).",
        ),
        _make_record(
            "/skills/shared/finding-protocol/SKILL.md",
            description="Operational finding template.",
        ),
        _make_record(
            "/skills/standard/analyst/reporting/SKILL.md",
            description="Analyst reporting guide.",
        ),
        _make_record(
            "/skills/standard/decepticon/reporting/SKILL.md",
            description="Decepticon reporting guide.",
        ),
    ]


class TestNormalizeSlug:
    def test_lowercases_and_strips(self) -> None:
        assert normalize_slug("  SQL Injection ") == "sql-injection"

    def test_underscores_become_hyphens(self) -> None:
        assert normalize_slug("auth_bypass") == "auth-bypass"

    def test_mixed_whitespace_collapses(self) -> None:
        assert normalize_slug("HTTP   request smuggling") == "http-request-smuggling"


class TestIsSafeSkillPath:
    @pytest.mark.parametrize(
        "path",
        [
            "/skills/standard/analyst/sql-injection/SKILL.md",
            "/skills/shared/finding-protocol/SKILL.md",
            "/skills/standard/exploit/web/smuggling.md",
        ],
    )
    def test_accepts_valid_paths(self, path: str) -> None:
        assert is_safe_skill_path(path) is True

    @pytest.mark.parametrize(
        "path",
        [
            "",
            "skills/standard/analyst/sql-injection/SKILL.md",
            "/etc/passwd",
            "/skills/../etc/passwd",
            "/skills/standard/../../etc/passwd",
            "/skills/standard/analyst/sql-injection",
            "C:\\Users\\x\\skills.md",
            None,
        ],
    )
    def test_rejects_bad_paths(self, path: object) -> None:
        assert is_safe_skill_path(path) is False  # type: ignore[arg-type]


class TestResolveSkill:
    def test_exact_path_match(self, small_registry: list[SkillRecord]) -> None:
        rec = resolve_skill(
            "/skills/standard/analyst/sql-injection/SKILL.md", small_registry
        )
        assert isinstance(rec, SkillRecord)
        assert rec.slug == "sql-injection"

    def test_exact_path_unsafe_rejected(self, small_registry: list[SkillRecord]) -> None:
        assert (
            resolve_skill("/skills/../etc/passwd", small_registry) is None
        )

    def test_trailing_slug_match(self, small_registry: list[SkillRecord]) -> None:
        rec = resolve_skill("sql-injection", small_registry)
        assert isinstance(rec, SkillRecord)
        assert rec.id == "/skills/standard/analyst/sql-injection/SKILL.md"

    def test_slug_with_spaces_normalizes(self, small_registry: list[SkillRecord]) -> None:
        rec = resolve_skill("sql injection", small_registry)
        assert isinstance(rec, SkillRecord)
        assert rec.slug == "sql-injection"

    def test_flat_file_slug_resolves(self, small_registry: list[SkillRecord]) -> None:
        rec = resolve_skill("smuggling", small_registry)
        assert isinstance(rec, SkillRecord)
        assert rec.id == "/skills/standard/exploit/web/smuggling.md"

    def test_fuzzy_single_match(self, small_registry: list[SkillRecord]) -> None:
        rec = resolve_skill("reenterancy", small_registry, fuzzy_cutoff=0.6)
        assert isinstance(rec, SkillRecord)
        assert rec.slug == "reentrancy"

    def test_ambiguous_slug_returns_disambiguation(
        self, small_registry: list[SkillRecord]
    ) -> None:
        result = resolve_skill("reporting", small_registry)
        assert isinstance(result, AmbiguousSkill)
        ids = {c.id for c in result.candidates}
        assert "/skills/standard/analyst/reporting/SKILL.md" in ids
        assert "/skills/standard/decepticon/reporting/SKILL.md" in ids

    def test_unknown_skill_returns_none(self, small_registry: list[SkillRecord]) -> None:
        assert resolve_skill("not-a-real-skill-anywhere", small_registry) is None

    def test_empty_query_returns_none(self, small_registry: list[SkillRecord]) -> None:
        assert resolve_skill("   ", small_registry) is None

    def test_allowed_sources_filter_blocks_outside_records(
        self, small_registry: list[SkillRecord]
    ) -> None:
        result = resolve_skill(
            "reentrancy",
            small_registry,
            allowed_sources=["/skills/standard/analyst/"],
        )
        assert result is None

    def test_allowed_sources_passes_matching_records(
        self, small_registry: list[SkillRecord]
    ) -> None:
        rec = resolve_skill(
            "sql-injection",
            small_registry,
            allowed_sources=["/skills/standard/analyst/", "/skills/shared/"],
        )
        assert isinstance(rec, SkillRecord)


class TestListSkillStrings:
    def test_no_filter_returns_all_sorted(
        self, small_registry: list[SkillRecord]
    ) -> None:
        out = list_skill_strings(small_registry)
        assert len(out) == len(small_registry)
        assert out == sorted(out)

    def test_filter_matches_by_description(
        self, small_registry: list[SkillRecord]
    ) -> None:
        out = list_skill_strings(small_registry, filter="injection")
        assert len(out) == 1
        assert "sql-injection" in out[0]

    def test_filter_matches_by_slug_substring(
        self, small_registry: list[SkillRecord]
    ) -> None:
        out = list_skill_strings(small_registry, filter="smuggl")
        assert len(out) == 1
        assert "/skills/standard/exploit/web/smuggling.md" in out[0]


class TestIterSkillRecords:
    def test_walks_real_filesystem_tree(self, tmp_path: Path) -> None:
        (tmp_path / "standard" / "analyst" / "sql-injection").mkdir(parents=True)
        (tmp_path / "standard" / "analyst" / "sql-injection" / "SKILL.md").write_text(
            "---\nname: sql-injection\ndescription: hunt SQL injection\n---\n# body\n",
            encoding="utf-8",
        )
        (tmp_path / "standard" / "exploit" / "web").mkdir(parents=True)
        (tmp_path / "standard" / "exploit" / "web" / "smuggling.md").write_text(
            "---\nname: smuggling\ndescription: HTTP smuggling\n---\n# body\n",
            encoding="utf-8",
        )

        records = list(iter_skill_records(tmp_path))
        ids = {r.id for r in records}
        assert "/skills/standard/analyst/sql-injection/SKILL.md" in ids
        assert "/skills/standard/exploit/web/smuggling.md" in ids

        sql = next(r for r in records if r.slug == "sql-injection")
        assert sql.description == "hunt SQL injection"
        smug = next(r for r in records if r.slug == "smuggling")
        assert smug.description == "HTTP smuggling"

    def test_handles_missing_root_gracefully(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist"
        assert list(iter_skill_records(missing)) == []

    def test_skips_files_with_no_frontmatter(self, tmp_path: Path) -> None:
        (tmp_path / "raw.md").write_text("# no frontmatter\nbody\n", encoding="utf-8")
        records = list(iter_skill_records(tmp_path))
        assert len(records) == 1
        assert records[0].description == ""
        assert records[0].name == "raw"
