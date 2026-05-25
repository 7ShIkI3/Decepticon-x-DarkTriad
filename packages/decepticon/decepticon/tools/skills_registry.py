"""Decepticon skill registry + slug / fuzzy resolver.

This module is the data-layer counterpart to ``decepticon.tools.skills``.
The existing ``load_skill`` tool reads a single fully-qualified
``/skills/...`` path. The registry walks the package's skill tree
(plus virtual ``/skills/...`` paths shipped from plugins / shared
sources) and lets callers resolve a skill by:

1. exact ``/skills/...`` virtual path,
2. trailing slug (``sql-injection`` → ``/skills/standard/analyst/sql-injection/SKILL.md``),
3. fuzzy match with disambiguation (no silent guessing on ambiguity).

A future PR will plug this resolver into the existing ``load_skill``
tool so a running agent can name a skill by slug and persist the
loaded id into LangGraph state for the next turn's prompt. Shipping
the resolver as a standalone library here lets the integration land
as a small, focused follow-up against well-tested ground truth.

Path safety contract:

* All resolved paths start with ``/skills/``.
* ``..`` traversal segments and backslashes are rejected.
* Resolved paths must point to a discovered registry entry; raw
  filesystem reads are never performed against caller-controlled input.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

SKILL_PATH_PREFIX = "/skills/"
_SLUG_NORMALIZE = re.compile(r"[\s_]+")
_RULE_SAFE = re.compile(r"[^A-Za-z0-9_\-]+")


@dataclass(frozen=True, slots=True)
class SkillRecord:
    """One discovered skill markdown file.

    Fields:

    * ``id`` — canonical virtual path (e.g. ``/skills/standard/analyst/sql-injection/SKILL.md``)
    * ``slug`` — trailing directory or file slug (``sql-injection`` or ``crypto``)
    * ``name`` — frontmatter ``name`` field or slug fallback
    * ``description`` — frontmatter ``description`` field or empty string
    * ``source`` — first allowlist source prefix that exposed this record
    """

    id: str
    slug: str
    name: str
    description: str
    source: str


@dataclass(frozen=True, slots=True)
class AmbiguousSkill:
    """Returned by :func:`resolve_skill` when multiple candidates tie.

    Callers (typically the ``load_skill`` tool wrapper) should render the
    ``candidates`` list back to the agent so it can disambiguate. The
    resolver never silently picks a winner under ambiguity.
    """

    query: str
    candidates: tuple[SkillRecord, ...]


def normalize_slug(text: str) -> str:
    """Lowercase, trim, convert spaces/underscores to hyphens.

    ``"SQL Injection"`` -> ``"sql-injection"``.
    """
    cleaned = _SLUG_NORMALIZE.sub("-", text.strip().lower())
    return cleaned.strip("-")


def is_safe_skill_path(path: str) -> bool:
    """Return True if ``path`` is a syntactically safe virtual skill path."""
    if not isinstance(path, str) or not path:
        return False
    if not path.startswith(SKILL_PATH_PREFIX):
        return False
    if not path.endswith(".md"):
        return False
    if "\\" in path:
        return False
    segments = path.split("/")
    if ".." in segments:
        return False
    return True


def _frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---\n", 4)
    if end == -1:
        return {}
    block = text[4:end]
    out: dict[str, str] = {}
    for line in block.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def _walk_skills_root(skills_root: Path) -> Iterator[tuple[Path, str]]:
    """Yield ``(file_path, virtual_path)`` for every ``*.md`` skill file."""
    if not skills_root.exists():
        return
    for md in skills_root.rglob("*.md"):
        rel = md.relative_to(skills_root).as_posix()
        virtual = f"{SKILL_PATH_PREFIX}{rel}"
        yield md, virtual


def iter_skill_records(
    skills_root: Path, source_prefix: str = SKILL_PATH_PREFIX
) -> Iterator[SkillRecord]:
    """Walk ``skills_root`` and yield one :class:`SkillRecord` per ``*.md``.

    ``source_prefix`` is the virtual-path prefix to record on each
    entry; callers walking shared/plugin trees should pass the matching
    virtual prefix so allowlist filtering downstream stays accurate.
    """
    for path, virtual in _walk_skills_root(skills_root):
        try:
            body = path.read_text(encoding="utf-8")
        except OSError:
            continue
        fm = _frontmatter(body)
        rel = virtual[len(SKILL_PATH_PREFIX):]
        parts = rel.split("/")
        if parts[-1] == "SKILL.md" and len(parts) >= 2:
            slug = parts[-2]
        else:
            slug = parts[-1].removesuffix(".md")
        name = fm.get("name") or slug
        description = fm.get("description", "").strip()
        yield SkillRecord(
            id=virtual,
            slug=slug,
            name=name,
            description=description,
            source=source_prefix,
        )


def build_registry_from_package(package_skills_root: Path) -> list[SkillRecord]:
    """Convenience builder for the shipped package skill tree."""
    return list(iter_skill_records(package_skills_root))


def resolve_skill(
    query: str,
    registry: Iterable[SkillRecord],
    *,
    allowed_sources: Iterable[str] | None = None,
    fuzzy_cutoff: float = 0.7,
) -> SkillRecord | AmbiguousSkill | None:
    """Resolve a user/agent query against the registry.

    Resolution order: exact ``/skills/...`` id match → trailing-slug
    match → fuzzy match (with disambiguation). When ``allowed_sources``
    is provided every candidate's ``id`` must start with one of the
    allowed prefixes; otherwise the record is filtered out before
    matching.

    Returns:

    * a single :class:`SkillRecord` on a definite match,
    * an :class:`AmbiguousSkill` listing candidates when multiple
      records tie on slug/name or fuzzy score,
    * ``None`` when no candidate is reachable.
    """
    if not isinstance(query, str) or not query.strip():
        return None
    pool = list(registry)
    if allowed_sources is not None:
        prefixes = tuple(s.rstrip("/") for s in allowed_sources)
        if prefixes:
            pool = [r for r in pool if any(r.id.startswith(p) for p in prefixes)]
    if not pool:
        return None

    q = query.strip()

    if q.startswith(SKILL_PATH_PREFIX):
        if not is_safe_skill_path(q):
            return None
        for rec in pool:
            if rec.id == q:
                return rec
        return None

    normalized = normalize_slug(q.removesuffix(".md").removesuffix("/SKILL"))
    slug_hits = [r for r in pool if r.slug == normalized]
    if len(slug_hits) == 1:
        return slug_hits[0]
    if len(slug_hits) > 1:
        return AmbiguousSkill(query=q, candidates=tuple(slug_hits))

    name_hits = [r for r in pool if normalize_slug(r.name) == normalized]
    if len(name_hits) == 1:
        return name_hits[0]
    if len(name_hits) > 1:
        return AmbiguousSkill(query=q, candidates=tuple(name_hits))

    slug_index = {r.slug: r for r in pool}
    fuzzy = difflib.get_close_matches(
        normalized, list(slug_index.keys()), n=5, cutoff=fuzzy_cutoff
    )
    if not fuzzy:
        return None
    if len(fuzzy) == 1:
        return slug_index[fuzzy[0]]
    return AmbiguousSkill(
        query=q, candidates=tuple(slug_index[s] for s in fuzzy)
    )


def list_skill_strings(
    registry: Iterable[SkillRecord], *, filter: str | None = None
) -> list[str]:
    """Return ``slug — id — description`` strings, optionally filtered."""
    out: list[str] = []
    needle = filter.strip().lower() if isinstance(filter, str) else ""
    for rec in registry:
        if needle:
            haystack = " ".join(
                [rec.slug, rec.name, rec.description, rec.id]
            ).lower()
            if needle not in haystack:
                continue
        desc = rec.description or "(no description)"
        out.append(f"{rec.slug} — {rec.id} — {desc}")
    out.sort()
    return out


__all__ = [
    "AmbiguousSkill",
    "SKILL_PATH_PREFIX",
    "SkillRecord",
    "build_registry_from_package",
    "is_safe_skill_path",
    "iter_skill_records",
    "list_skill_strings",
    "normalize_slug",
    "resolve_skill",
]
