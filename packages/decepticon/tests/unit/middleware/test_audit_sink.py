from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import pytest

from decepticon.middleware._audit_sink import (
    AuditChainState,
    RoEAuditSink,
    iter_records,
    verify_ledger,
)


class TestPostInitStrToPath:
    def test_str_path_coerced_to_path_object(self, tmp_path: Path) -> None:
        sink = RoEAuditSink(path=str(tmp_path / "audit.jsonl"))
        assert isinstance(sink.path, Path)

    def test_path_object_unchanged(self, tmp_path: Path) -> None:
        p = tmp_path / "audit.jsonl"
        sink = RoEAuditSink(path=p)
        assert sink.path == p


class TestPostInitHmacKeyEnvFallback:
    def test_env_key_used_when_hmac_key_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("DECEPTICON_AUDIT_HMAC_KEY", "env-secret")
        sink = RoEAuditSink(path=tmp_path / "a.jsonl")
        assert sink.hmac_key == b"env-secret"
        sink.append({"event": "x"})
        result = verify_ledger(tmp_path / "a.jsonl", hmac_key=b"env-secret")
        assert result.ok

    def test_env_key_absent_hmac_key_stays_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("DECEPTICON_AUDIT_HMAC_KEY", raising=False)
        sink = RoEAuditSink(path=tmp_path / "a.jsonl")
        assert sink.hmac_key is None
        stamped = sink.append({"event": "x"})
        assert stamped["hmac"] == ""

    def test_explicit_hmac_key_not_overridden_by_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("DECEPTICON_AUDIT_HMAC_KEY", "env-secret")
        sink = RoEAuditSink(path=tmp_path / "a.jsonl", hmac_key=b"explicit-key")
        assert sink.hmac_key == b"explicit-key"


class TestEnsureHydratedSkipsBlanksAndCorrupt:
    def test_blank_line_skipped_during_hydration(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        s1 = RoEAuditSink(path=path)
        s1.append({"event": "a"})
        s1.append({"event": "b"})
        lines = path.read_text().splitlines()
        lines.insert(1, "")
        path.write_text("\n".join(lines) + "\n")
        s2 = RoEAuditSink(path=path)
        s2.append({"event": "c"})
        result = verify_ledger(path)
        assert result.ok
        assert result.records_checked == 3

    def test_corrupt_json_line_skipped_during_hydration_seq_advances(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        s1 = RoEAuditSink(path=path)
        s1.append({"event": "valid"})
        with path.open("a", encoding="utf-8") as fh:
            fh.write("not-json-at-all\n")
        s2 = RoEAuditSink(path=path)
        stamped = s2.append({"event": "after-corrupt"})
        assert stamped["seq"] == 2

    def test_oserror_on_read_logs_warning_and_does_not_raise(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        path = tmp_path / "audit.jsonl"
        path.write_text('{"seq":1,"hash":"a","prev_hash":"' + "0" * 64 + '"}\n', encoding="utf-8")
        sink = RoEAuditSink(path=path)
        sink._hydrated = True
        original_open = Path.open

        def raising_open(self_: Path, mode: str = "r", **kwargs: Any) -> Any:
            if mode == "r":
                raise OSError("no read")
            return original_open(self_, mode, **kwargs)

        decepticon_logger = logging.getLogger("decepticon")
        original_propagate = decepticon_logger.propagate
        decepticon_logger.propagate = True
        try:
            monkeypatch.setattr(Path, "open", raising_open)
            sink._hydrated = False
            with caplog.at_level(logging.WARNING):
                sink._ensure_hydrated()
        finally:
            decepticon_logger.propagate = original_propagate
        assert sink._state == AuditChainState()
        assert "failed to hydrate" in caplog.text


class TestAppendFsyncAndWriteErrors:
    def test_fsync_oserror_swallowed_record_still_written(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("no fsync")))
        sink = RoEAuditSink(path=tmp_path / "audit.jsonl")
        sink.append({"event": "x"})
        lines = (tmp_path / "audit.jsonl").read_text().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["event"] == "x"

    def test_write_oserror_logs_error_and_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        path = tmp_path / "audit.jsonl"
        sink = RoEAuditSink(path=path)
        original_open = Path.open

        def raising_write_open(self_: Path, mode: str = "r", **kwargs: Any) -> Any:
            if mode == "a" and self_ == path:
                raise OSError("disk full")
            return original_open(self_, mode, **kwargs)

        decepticon_logger = logging.getLogger("decepticon")
        original_propagate = decepticon_logger.propagate
        decepticon_logger.propagate = True
        try:
            monkeypatch.setattr(Path, "open", raising_write_open)
            with caplog.at_level(logging.ERROR):
                with pytest.raises(OSError):
                    sink.append({"event": "x"})
        finally:
            decepticon_logger.propagate = original_propagate
        assert "failed to write" in caplog.text


class TestVerifyLedgerEdgeCases:
    def test_nonexistent_path_returns_ok_zero_records(self, tmp_path: Path) -> None:
        result = verify_ledger(tmp_path / "missing.jsonl")
        assert result.ok is True
        assert result.records_checked == 0
        assert result.first_bad_seq is None

    def test_blank_lines_skipped_in_verify(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = RoEAuditSink(path=path)
        sink.append({"event": "first"})
        sink.append({"event": "second"})
        lines = path.read_text().splitlines()
        lines.insert(1, "")
        path.write_text("\n".join(lines) + "\n")
        result = verify_ledger(path)
        assert result.ok is True
        assert result.records_checked == 2

    def test_sequence_gap_detected(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = RoEAuditSink(path=path)
        sink.append({"event": "one"})
        sink.append({"event": "two"})
        sink.append({"event": "three"})
        lines = path.read_text().splitlines()
        lines.pop(1)
        path.write_text("\n".join(lines) + "\n")
        result = verify_ledger(path)
        assert not result.ok
        assert "sequence gap or duplicate" in result.reason
        assert result.first_bad_seq == 2

    def test_prev_hash_mismatch_detected(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = RoEAuditSink(path=path)
        sink.append({"event": "one"})
        lines = path.read_text().splitlines()
        rec = json.loads(lines[0])
        rec["prev_hash"] = "f" * 64
        lines[0] = json.dumps(rec)
        path.write_text("\n".join(lines) + "\n")
        result = verify_ledger(path)
        assert not result.ok
        assert "prev_hash mismatch" in result.reason
        assert result.first_bad_seq == 1

    def test_corrupt_first_line_triggers_parse_error(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        path.write_text("{bad json\n", encoding="utf-8")
        result = verify_ledger(path)
        assert not result.ok
        assert "ledger parse error" in result.reason
        assert result.first_bad_seq == 1


class TestIterRecords:
    def test_nonexistent_path_yields_nothing(self, tmp_path: Path) -> None:
        assert list(iter_records(tmp_path / "none.jsonl")) == []

    def test_valid_records_yielded_blanks_and_corrupt_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        path.write_text(
            '{"seq":1,"event":"first"}\n\ngarbage-not-json\n{"seq":2,"event":"second"}\n',
            encoding="utf-8",
        )
        recs = list(iter_records(path))
        assert len(recs) == 2
        assert recs[0] == {"seq": 1, "event": "first"}
        assert recs[1] == {"seq": 2, "event": "second"}


class TestRoundTripIntegration:
    def test_append_returns_stamped_dict_with_chain_fields(self, tmp_path: Path) -> None:
        sink = RoEAuditSink(path=tmp_path / "audit.jsonl")
        stamped = sink.append({"event": "probe", "target": "10.0.0.1"})
        assert stamped["seq"] == 1
        assert stamped["prev_hash"] == "0" * 64
        assert len(stamped["hash"]) == 64
        assert "hmac" in stamped

    def test_two_appends_verify_ok(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = RoEAuditSink(path=path)
        sink.append({"event": "a"})
        sink.append({"event": "b"})
        result = verify_ledger(path)
        assert result.ok
        assert result.records_checked == 2
