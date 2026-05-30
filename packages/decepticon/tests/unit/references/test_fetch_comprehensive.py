"""Comprehensive tests for decepticon.tools.references.fetch.

Covers: _default_cache_root, ReferenceCache.to_dict, _entry, _dir_size,
_run_git (hardened env), ensure_cached (clone / pull / symlink / URL-mismatch),
search_cache (grep / fallback paths), _which, _parse_grep_line, _pyfind.

All subprocess and filesystem side-effects are mocked — passes offline.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from decepticon.tools.references import fetch as fetch_mod
from decepticon.tools.references.fetch import (
    ReferenceCache,
    _default_cache_root,
    _dir_size,
    _entry,
    _parse_grep_line,
    _pyfind,
    _run_git,
    _which,
    cache_path,
    cache_status,
    ensure_cached,
    search_cache,
)

# ---------------------------------------------------------------------------
# _default_cache_root
# ---------------------------------------------------------------------------


class TestDefaultCacheRoot:
    def test_returns_home_based_path_without_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("DECEPTICON_REFERENCES_ROOT", raising=False)
        result = _default_cache_root()
        assert result == Path.home() / ".decepticon" / "references"

    def test_env_override_takes_precedence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("DECEPTICON_REFERENCES_ROOT", str(tmp_path))
        result = _default_cache_root()
        assert result == tmp_path

    def test_env_override_returns_path_object(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("DECEPTICON_REFERENCES_ROOT", str(tmp_path / "custom"))
        result = _default_cache_root()
        assert isinstance(result, Path)
        assert result == tmp_path / "custom"


# ---------------------------------------------------------------------------
# ReferenceCache.to_dict
# ---------------------------------------------------------------------------


class TestReferenceCacheToDict:
    def test_to_dict_keys_and_types(self, tmp_path: Path) -> None:
        rc = ReferenceCache(
            slug="hackerone-reports",
            url="https://github.com/reddelexc/hackerone-reports",
            path=tmp_path / "hackerone-reports",
            present=False,
            size_bytes=0,
        )
        d = rc.to_dict()
        assert set(d.keys()) == {"slug", "url", "path", "present", "size_bytes"}
        assert d["slug"] == "hackerone-reports"
        assert d["url"] == "https://github.com/reddelexc/hackerone-reports"
        assert d["path"] == str(tmp_path / "hackerone-reports")
        assert d["present"] is False
        assert d["size_bytes"] == 0

    def test_to_dict_present_true(self, tmp_path: Path) -> None:
        rc = ReferenceCache(
            slug="trickest-cve",
            url="https://github.com/trickest/cve",
            path=tmp_path / "trickest-cve",
            present=True,
            size_bytes=12345,
        )
        d = rc.to_dict()
        assert d["present"] is True
        assert d["size_bytes"] == 12345

    def test_to_dict_path_is_string(self, tmp_path: Path) -> None:
        rc = ReferenceCache(
            slug="hackerone-reports",
            url="https://example.com",
            path=tmp_path / "hackerone-reports",
            present=False,
            size_bytes=0,
        )
        assert isinstance(rc.to_dict()["path"], str)


# ---------------------------------------------------------------------------
# _entry
# ---------------------------------------------------------------------------


class TestEntry:
    def test_known_slug_returns_entry(self) -> None:
        entry = _entry("hackerone-reports")
        assert entry.slug == "hackerone-reports"
        assert entry.url.startswith("https://")

    def test_unknown_slug_raises_key_error(self) -> None:
        with pytest.raises(KeyError, match="unknown reference slug"):
            _entry("totally-nonexistent-slug-xyz")

    def test_returns_first_match(self) -> None:
        # Each slug is unique; calling twice returns the same object
        e1 = _entry("trickest-cve")
        e2 = _entry("trickest-cve")
        assert e1 is e2


# ---------------------------------------------------------------------------
# _dir_size
# ---------------------------------------------------------------------------


class TestDirSize:
    def test_empty_dir_returns_zero(self, tmp_path: Path) -> None:
        assert _dir_size(tmp_path) == 0

    def test_single_file(self, tmp_path: Path) -> None:
        (tmp_path / "file.txt").write_bytes(b"hello")
        assert _dir_size(tmp_path) == 5

    def test_nested_files(self, tmp_path: Path) -> None:
        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "a.txt").write_bytes(b"aa")
        (sub / "b.txt").write_bytes(b"bbb")
        assert _dir_size(tmp_path) == 5

    def test_oserror_on_stat_skips_file(self, tmp_path: Path) -> None:
        # Patch stat on one file to raise; size should still sum the rest
        real_file = tmp_path / "real.txt"
        real_file.write_bytes(b"xyz")

        original_stat = Path.stat

        def patched_stat(self: Path, **kwargs: Any) -> Any:
            if self.name == "real.txt":
                raise OSError("permission denied")
            return original_stat(self, **kwargs)

        with patch.object(Path, "stat", patched_stat):
            result = _dir_size(tmp_path)
        assert result == 0  # the only file raised, so total stays 0

    def test_oserror_on_rglob_returns_zero(self, tmp_path: Path) -> None:
        with patch.object(Path, "rglob", side_effect=OSError("boom")):
            assert _dir_size(tmp_path) == 0

    def test_nonexistent_dir_returns_zero(self, tmp_path: Path) -> None:
        missing = tmp_path / "does_not_exist"
        assert _dir_size(missing) == 0


# ---------------------------------------------------------------------------
# _run_git
# ---------------------------------------------------------------------------


class TestRunGit:
    def test_merges_git_env_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Hardened env keys must be present in the subprocess call."""
        captured: dict[str, Any] = {}

        def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
            captured["env"] = kwargs.get("env", {})
            captured["argv"] = argv
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        monkeypatch.setattr(fetch_mod.subprocess, "run", fake_run)
        _run_git(["git", "version"], timeout=5.0)

        env = captured["env"]
        assert env.get("GIT_TERMINAL_PROMPT") == "0"
        assert env.get("GIT_CONFIG_NOSYSTEM") == "1"
        assert env.get("GIT_CONFIG_COUNT") == "0"
        # Only https and http are permitted
        assert "https" in env.get("GIT_ALLOW_PROTOCOL", "")

    def test_passes_check_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
            captured.update(kwargs)
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        monkeypatch.setattr(fetch_mod.subprocess, "run", fake_run)
        _run_git(["git", "version"], timeout=10.0)
        assert captured.get("check") is False

    def test_passes_capture_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
            captured.update(kwargs)
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        monkeypatch.setattr(fetch_mod.subprocess, "run", fake_run)
        _run_git(["git", "version"], timeout=10.0)
        assert captured.get("capture_output") is True

    def test_preserves_existing_env_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MY_CUSTOM_VAR", "preserved")
        captured: dict[str, Any] = {}

        def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
            captured["env"] = kwargs.get("env", {})
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        monkeypatch.setattr(fetch_mod.subprocess, "run", fake_run)
        _run_git(["git", "version"], timeout=5.0)
        # Custom env var should be present (merged with os.environ)
        assert captured["env"].get("MY_CUSTOM_VAR") == "preserved"


# ---------------------------------------------------------------------------
# cache_path / cache_status (additional edge cases)
# ---------------------------------------------------------------------------


class TestCachePathStatus:
    def test_cache_path_uses_default_root_when_none(self) -> None:
        # When root=None, uses CACHE_ROOT (module-level constant)
        p = cache_path("hackerone-reports", root=None)
        assert p.name == "hackerone-reports"
        # Must be an absolute path under some cache root
        assert p.is_absolute()

    def test_cache_status_to_dict_roundtrip(self, tmp_path: Path) -> None:
        status = cache_status("hackerone-reports", root=tmp_path)
        d = status.to_dict()
        assert d["slug"] == "hackerone-reports"
        assert d["present"] is False

    def test_cache_status_size_with_multiple_files(self, tmp_path: Path) -> None:
        repo = tmp_path / "trickest-cve"
        repo.mkdir(parents=True)
        (repo / "file_a.txt").write_bytes(b"a" * 100)
        (repo / "file_b.txt").write_bytes(b"b" * 200)
        status = cache_status("trickest-cve", root=tmp_path)
        assert status.present is True
        assert status.size_bytes >= 300


# ---------------------------------------------------------------------------
# ensure_cached — run=True paths
# ---------------------------------------------------------------------------


class TestEnsureCachedRunTrue:
    def _make_fake_run(
        self,
        captured_calls: list[list[str]],
        stdout_map: dict[str, bytes] | None = None,
    ):
        """Return a fake subprocess.run that records calls."""
        stdout_map = stdout_map or {}

        def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
            captured_calls.append(list(argv))
            key = " ".join(argv[:3])
            stdout = stdout_map.get(key, b"")
            return subprocess.CompletedProcess(argv, 0, stdout, b"")

        return fake_run

    def test_clones_when_not_present(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[list[str]] = []
        monkeypatch.setattr(fetch_mod.subprocess, "run", self._make_fake_run(calls))

        status = ensure_cached("hackerone-reports", root=tmp_path, run=True)
        # Only one call — clone (no .git dir present)
        assert any("clone" in c for c in calls)
        assert status.slug == "hackerone-reports"

    def test_clone_uses_correct_url(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[list[str]] = []
        monkeypatch.setattr(fetch_mod.subprocess, "run", self._make_fake_run(calls))

        entry = _entry("hackerone-reports")
        ensure_cached("hackerone-reports", root=tmp_path, run=True)
        clone_call = next(c for c in calls if "clone" in c)
        assert entry.url in clone_call

    def test_clone_passes_depth(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[list[str]] = []
        monkeypatch.setattr(fetch_mod.subprocess, "run", self._make_fake_run(calls))

        ensure_cached("hackerone-reports", root=tmp_path, depth=3, run=True)
        clone_call = next(c for c in calls if "clone" in c)
        assert "--depth" in clone_call
        assert "3" in clone_call

    def test_pulls_when_git_dir_present_and_url_matches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Set up a fake .git dir so the pull path is triggered
        repo = tmp_path / "hackerone-reports"
        repo.mkdir(parents=True)
        (repo / ".git").mkdir()

        entry = _entry("hackerone-reports")
        calls: list[list[str]] = []
        # url-check returns matching URL
        url_bytes = (entry.url + "\n").encode()
        monkeypatch.setattr(
            fetch_mod.subprocess,
            "run",
            self._make_fake_run(calls, {"git -C config": url_bytes}),
        )

        # Override the fake_run stdout_map lookup to return URL for config --get call
        def smart_fake(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
            calls.append(list(argv))
            if "config" in argv and "--get" in argv:
                return subprocess.CompletedProcess(argv, 0, url_bytes, b"")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        monkeypatch.setattr(fetch_mod.subprocess, "run", smart_fake)
        ensure_cached("hackerone-reports", root=tmp_path, run=True)

        # Should have a config check + a pull
        assert any("config" in c for c in calls)
        assert any("pull" in c for c in calls)

    def test_url_mismatch_skips_pull(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        repo = tmp_path / "hackerone-reports"
        repo.mkdir(parents=True)
        (repo / ".git").mkdir()

        calls: list[list[str]] = []

        def mismatch_fake(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
            calls.append(list(argv))
            if "config" in argv and "--get" in argv:
                return subprocess.CompletedProcess(argv, 0, b"https://evil.com/repo\n", b"")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        monkeypatch.setattr(fetch_mod.subprocess, "run", mismatch_fake)
        ensure_cached("hackerone-reports", root=tmp_path, run=True)

        # pull must NOT be called when URL mismatches
        assert not any("pull" in c for c in calls)

    def test_symlink_path_skips_git(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """If the slug path is a symlink, refuse to clone/pull."""
        # Create a real dir to point at
        real_dir = tmp_path / "real_target"
        real_dir.mkdir()
        link = tmp_path / "hackerone-reports"
        try:
            link.symlink_to(real_dir)
        except OSError:
            pytest.skip("symlinks not supported on this filesystem")

        calls: list[list[str]] = []
        monkeypatch.setattr(fetch_mod.subprocess, "run", self._make_fake_run(calls))
        ensure_cached("hackerone-reports", root=tmp_path, run=True)
        # No git calls should happen
        assert calls == []

    def test_run_false_skips_subprocess(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[list[str]] = []
        monkeypatch.setattr(fetch_mod.subprocess, "run", self._make_fake_run(calls))
        ensure_cached("hackerone-reports", root=tmp_path, run=False)
        assert calls == []

    def test_non_git_fetch_hint_skips_clone(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """excalibur has fetch_hint='web' — no git call should be issued."""
        calls: list[list[str]] = []
        monkeypatch.setattr(fetch_mod.subprocess, "run", self._make_fake_run(calls))
        ensure_cached("excalibur", root=tmp_path, run=True)
        assert all("clone" not in c and "pull" not in c for c in calls)

    def test_base_dir_created_if_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = tmp_path / "deep" / "nested" / "cache"
        monkeypatch.setattr(fetch_mod.subprocess, "run", self._make_fake_run([]))
        ensure_cached("hackerone-reports", root=base, run=False)
        assert base.exists()


# ---------------------------------------------------------------------------
# _which
# ---------------------------------------------------------------------------


class TestWhich:
    def test_returns_true_for_existing_executable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_name = "myfakebinary"
        fake_bin = tmp_path / binary_name
        fake_bin.write_bytes(b"#!/bin/sh")
        fake_bin.chmod(0o755)
        monkeypatch.setenv("PATH", str(tmp_path))
        assert _which(binary_name) is True

    def test_returns_false_when_not_on_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PATH", str(tmp_path))  # empty dir
        assert _which("definitely_not_here_xyz") is False

    def test_empty_path_entries_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # PATH with leading/trailing colons
        monkeypatch.setenv("PATH", os.pathsep + str(tmp_path) + os.pathsep)
        assert _which("nonexistent_bin") is False

    def test_non_executable_file_not_matched(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_bin = tmp_path / "mybin"
        fake_bin.write_bytes(b"data")
        fake_bin.chmod(0o644)  # not executable
        monkeypatch.setenv("PATH", str(tmp_path))
        # On Windows os.access(X_OK) always returns True, so skip check
        import sys

        if sys.platform == "win32":
            pytest.skip("os.access(X_OK) always True on Windows")
        assert _which("mybin") is False


# ---------------------------------------------------------------------------
# _parse_grep_line
# ---------------------------------------------------------------------------


class TestParseGrepLine:
    def test_valid_line_returns_tuple(self) -> None:
        result = _parse_grep_line("/path/to/file.py:42:some content here")
        assert result == ("/path/to/file.py", 42, "some content here")

    def test_content_truncated_at_240(self) -> None:
        long_content = "x" * 300
        result = _parse_grep_line(f"/path/file.py:1:{long_content}")
        assert result is not None
        _path, _lineno, snippet = result
        assert len(snippet) == 240

    def test_returns_none_for_too_few_parts(self) -> None:
        assert _parse_grep_line("/path/file.py:42") is None
        assert _parse_grep_line("/path/file.py") is None
        assert _parse_grep_line("") is None

    def test_returns_none_for_non_integer_line_number(self) -> None:
        assert _parse_grep_line("/path/file.py:abc:content") is None

    def test_content_with_colons_preserved(self) -> None:
        result = _parse_grep_line("/file.py:10:http://example.com:8080/path")
        assert result is not None
        assert result[2] == "http://example.com:8080/path"

    def test_line_number_zero_parsed(self) -> None:
        result = _parse_grep_line("/file.py:0:content")
        assert result == ("/file.py", 0, "content")

    def test_empty_content_part(self) -> None:
        result = _parse_grep_line("/file.py:5:")
        assert result == ("/file.py", 5, "")


# ---------------------------------------------------------------------------
# _pyfind
# ---------------------------------------------------------------------------


class TestPyfind:
    def test_finds_matching_line(self, tmp_path: Path) -> None:
        (tmp_path / "target.txt").write_text(
            "no match\nfind this needle here\nalso no\n", encoding="utf-8"
        )
        results = _pyfind(tmp_path, "needle", 10)
        assert len(results) == 1
        path, lineno, snippet = results[0]
        assert "needle" in snippet.lower()
        assert lineno == 2

    def test_case_insensitive_match(self, tmp_path: Path) -> None:
        (tmp_path / "f.txt").write_text("NEEDLE_UPPER\n", encoding="utf-8")
        results = _pyfind(tmp_path, "needle", 10)
        assert len(results) == 1

    def test_max_results_respected(self, tmp_path: Path) -> None:
        # Write 10 matching lines
        (tmp_path / "big.txt").write_text("\n".join(["needle"] * 10), encoding="utf-8")
        results = _pyfind(tmp_path, "needle", 3)
        assert len(results) == 3

    def test_no_match_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / "f.txt").write_text("no match at all\n", encoding="utf-8")
        assert _pyfind(tmp_path, "zzz_not_present", 10) == []

    def test_oserror_on_file_open_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "good.txt").write_text("needle here\n", encoding="utf-8")
        bad = tmp_path / "bad.txt"
        bad.write_text("needle here\n", encoding="utf-8")

        original_open = Path.open

        def patched_open(self: Path, *args: Any, **kwargs: Any):
            if self.name == "bad.txt":
                raise OSError("no permission")
            return original_open(self, *args, **kwargs)

        with patch.object(Path, "open", patched_open):
            results = _pyfind(tmp_path, "needle", 10)
        # Only the good file should contribute
        assert len(results) >= 1

    def test_snippet_truncated_at_240(self, tmp_path: Path) -> None:
        long_line = "needle " + "x" * 300
        (tmp_path / "f.txt").write_text(long_line + "\n", encoding="utf-8")
        results = _pyfind(tmp_path, "needle", 10)
        assert results
        assert len(results[0][2]) <= 240

    def test_nonexistent_root_returns_empty(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing_dir"
        results = _pyfind(missing, "needle", 10)
        assert results == []

    def test_returns_correct_structure(self, tmp_path: Path) -> None:
        (tmp_path / "code.py").write_text("# needle\npass\n", encoding="utf-8")
        results = _pyfind(tmp_path, "needle", 10)
        assert len(results) == 1
        path_str, lineno, snippet = results[0]
        assert isinstance(path_str, str)
        assert isinstance(lineno, int)
        assert isinstance(snippet, str)
        assert lineno == 1


# ---------------------------------------------------------------------------
# search_cache — additional paths
# ---------------------------------------------------------------------------


class TestSearchCacheAdditional:
    def test_returns_empty_when_not_cached(self, tmp_path: Path) -> None:
        result = search_cache("hackerone-reports", "pattern", root=tmp_path)
        assert result == []

    def test_uses_grep_when_rg_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "hackerone-reports"
        repo.mkdir(parents=True)
        (repo / "report.md").write_text("some content\n", encoding="utf-8")

        captured: list[list[str]] = []

        def fake_run(cmd: list[str], **kwargs: Any) -> SimpleNamespace:
            captured.append(list(cmd))
            return SimpleNamespace(stdout="")

        # rg absent, grep present
        monkeypatch.setattr(fetch_mod, "_which", lambda binary: binary == "grep")
        monkeypatch.setattr(fetch_mod.subprocess, "run", fake_run)

        search_cache("hackerone-reports", "pattern", root=tmp_path)
        assert captured
        assert captured[0][0] == "grep"

    def test_falls_back_to_python_when_no_binaries(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "hackerone-reports"
        repo.mkdir(parents=True)
        (repo / "file.txt").write_text("find me needle\n", encoding="utf-8")

        monkeypatch.setattr(fetch_mod, "_which", lambda binary: False)

        results = search_cache("hackerone-reports", "needle", root=tmp_path)
        assert len(results) >= 1

    def test_timeout_triggers_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "hackerone-reports"
        repo.mkdir(parents=True)
        (repo / "file.txt").write_text("needle content\n", encoding="utf-8")

        def raising_run(cmd: list[str], **kwargs: Any) -> SimpleNamespace:
            raise subprocess.TimeoutExpired(cmd, 30)

        monkeypatch.setattr(fetch_mod, "_which", lambda binary: binary == "rg")
        monkeypatch.setattr(fetch_mod.subprocess, "run", raising_run)

        # Should fall through to _pyfind
        results = search_cache("hackerone-reports", "needle", root=tmp_path)
        # _pyfind is called after TimeoutExpired breaks out of the loop
        assert isinstance(results, list)

    def test_file_not_found_triggers_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "hackerone-reports"
        repo.mkdir(parents=True)
        (repo / "file.txt").write_text("needle is here\n", encoding="utf-8")

        def raising_run(cmd: list[str], **kwargs: Any) -> SimpleNamespace:
            raise FileNotFoundError("rg not found")

        monkeypatch.setattr(fetch_mod, "_which", lambda binary: binary == "rg")
        monkeypatch.setattr(fetch_mod.subprocess, "run", raising_run)

        results = search_cache("hackerone-reports", "needle", root=tmp_path)
        assert isinstance(results, list)

    def test_max_results_limits_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "hackerone-reports"
        repo.mkdir(parents=True)

        # Generate 50 matching lines across files
        for i in range(10):
            (repo / f"f{i}.txt").write_text("\n".join(["needle match"] * 5), encoding="utf-8")

        monkeypatch.setattr(fetch_mod, "_which", lambda binary: False)
        results = search_cache("hackerone-reports", "needle", root=tmp_path, max_results=5)
        assert len(results) <= 5

    def test_grep_output_parsed_correctly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "hackerone-reports"
        repo.mkdir(parents=True)
        (repo / "r.md").write_text("placeholder\n", encoding="utf-8")

        fake_output = "/path/file.py:10:matching content\n/path/file.py:20:another match\n"

        def fake_run(cmd: list[str], **kwargs: Any) -> SimpleNamespace:
            return SimpleNamespace(stdout=fake_output)

        monkeypatch.setattr(fetch_mod, "_which", lambda binary: binary == "rg")
        monkeypatch.setattr(fetch_mod.subprocess, "run", fake_run)

        results = search_cache("hackerone-reports", "content", root=tmp_path)
        assert len(results) == 2
        assert results[0] == ("/path/file.py", 10, "matching content")
        assert results[1] == ("/path/file.py", 20, "another match")
