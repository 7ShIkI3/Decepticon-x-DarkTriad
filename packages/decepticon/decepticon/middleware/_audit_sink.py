"""HMAC-chained append-only audit log for RoE decisions.

Every RoE evaluation (pass or refuse) emits one record. Records are
appended as JSON Lines. Each record carries:

  * ``seq`` - monotonic per-engagement counter.
  * ``ts`` - UTC timestamp.
  * ``prev_hash`` - SHA-256 of the previous record's canonical
    encoding (or 64 zero hex digits for the first record).
  * ``hash`` - SHA-256 over canonical encoding of this record's
    fields PLUS ``prev_hash``. Chaining means tampering with record N
    invalidates every record after N.
  * ``hmac`` - HMAC-SHA-256 of ``hash`` using a key from
    ``DECEPTICON_AUDIT_HMAC_KEY``. When set, the HMAC binds the chain
    to an operator-held secret; without the secret a tamperer can
    recompute the chain but cannot forge a valid hmac. When unset,
    the field is ``""`` and integrity rests only on the chain.

The sink is intentionally LOCAL FILE only in this commit. Remote
shipping (S3, syslog, Loki via mTLS) belongs in a follow-up - the
local file is the primary integrity boundary and the simplest thing
to audit at engagement out-brief.

Concurrency: a single writer is assumed per file. The Decepticon
runtime guarantees this because the LangGraph orchestrator runs one
event loop per engagement workspace; the writer's append-then-fsync
is atomic per record on POSIX append-only files. On Windows the
append is still atomic for buffer sizes < 4096 bytes.

Verification: a separate ``verify`` helper walks the file end-to-end,
recomputes each ``prev_hash`` -> ``hash`` chain link, and checks the
``hmac`` when a key is available. The CLI hook
``decepticon audit verify`` (TODO) will surface this.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger(__name__)


_GENESIS_PREV_HASH = "0" * 64


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _record_hash(record: dict[str, Any], prev_hash: str) -> str:
    payload = dict(record)
    payload["prev_hash"] = prev_hash
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _record_hmac(this_hash: str, key: bytes | None) -> str:
    if not key:
        return ""
    return hmac.new(key, this_hash.encode("ascii"), hashlib.sha256).hexdigest()


@dataclass
class AuditChainState:
    seq: int = 0
    last_hash: str = _GENESIS_PREV_HASH


@dataclass
class RoEAuditSink:
    """Append RoE decisions to an HMAC-chained JSONL ledger.

    Construction kwargs:
        path: filesystem path. Parent directory is created on demand.
        hmac_key: optional bytes for the HMAC binder. When ``None``,
            falls back to ``os.environ['DECEPTICON_AUDIT_HMAC_KEY']``
            (utf-8 encoded). When that's also unset, ``hmac`` field
            stays empty in every record.
    """

    path: Path
    hmac_key: bytes | None = None
    _state: AuditChainState = field(default_factory=AuditChainState)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _hydrated: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.path, str):
            self.path = Path(self.path)
        if self.hmac_key is None:
            env_key = os.environ.get("DECEPTICON_AUDIT_HMAC_KEY")
            if env_key:
                self.hmac_key = env_key.encode("utf-8")

    def _ensure_hydrated(self) -> None:
        if self._hydrated:
            return
        self._hydrated = True
        if not self.path.exists():
            return
        last_seq = 0
        last_hash = _GENESIS_PREV_HASH
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    last_seq = int(rec.get("seq", last_seq))
                    last_hash = str(rec.get("hash", last_hash))
        except OSError as exc:
            log.warning("audit_sink: failed to hydrate from %s: %s", self.path, exc)
        self._state = AuditChainState(seq=last_seq, last_hash=last_hash)

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        """Append ``record`` to the ledger; return the persisted form."""
        with self._lock:
            self._ensure_hydrated()
            seq = self._state.seq + 1
            stamped = dict(record)
            stamped["seq"] = seq
            this_hash = _record_hash(stamped, self._state.last_hash)
            stamped["prev_hash"] = self._state.last_hash
            stamped["hash"] = this_hash
            stamped["hmac"] = _record_hmac(this_hash, self.hmac_key)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(stamped, ensure_ascii=False) + "\n")
                    fh.flush()
                    try:
                        os.fsync(fh.fileno())
                    except OSError:
                        # fsync best-effort. The audit line is already in the
                        # kernel buffer and the outer write succeeded; fsync
                        # not being supported on this fs (tmpfs, network mounts)
                        # must not block the hot path.
                        pass
            except OSError as exc:
                log.error("audit_sink: failed to write to %s: %s", self.path, exc)
                raise
            self._state = AuditChainState(seq=seq, last_hash=this_hash)
            return stamped


@dataclass(frozen=True, slots=True)
class VerifyResult:
    ok: bool
    records_checked: int
    first_bad_seq: int | None
    reason: str = ""


def verify_ledger(path: Path, hmac_key: bytes | None = None) -> VerifyResult:
    """Walk a JSONL ledger and verify the chain + (optional) HMAC."""
    p = Path(path)
    if not p.exists():
        return VerifyResult(ok=True, records_checked=0, first_bad_seq=None)
    expected_seq = 1
    prev_hash = _GENESIS_PREV_HASH
    checked = 0
    try:
        with p.open("r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                rec = json.loads(line)
                checked += 1
                seq = int(rec.get("seq", -1))
                if seq != expected_seq:
                    return VerifyResult(
                        ok=False,
                        records_checked=checked,
                        first_bad_seq=expected_seq,
                        reason=f"sequence gap or duplicate at seq={seq} (expected {expected_seq})",
                    )
                if rec.get("prev_hash") != prev_hash:
                    return VerifyResult(
                        ok=False,
                        records_checked=checked,
                        first_bad_seq=seq,
                        reason=f"prev_hash mismatch at seq={seq}",
                    )
                stored_hash = rec.pop("hash", "")
                stored_hmac = rec.pop("hmac", "")
                recomputed = _record_hash(
                    {k: v for k, v in rec.items() if k not in {"prev_hash"}},
                    rec.get("prev_hash", _GENESIS_PREV_HASH),
                )
                if recomputed != stored_hash:
                    return VerifyResult(
                        ok=False,
                        records_checked=checked,
                        first_bad_seq=seq,
                        reason=f"hash mismatch at seq={seq}",
                    )
                if hmac_key is not None:
                    expected_hmac = _record_hmac(stored_hash, hmac_key)
                    if not hmac.compare_digest(expected_hmac, stored_hmac):
                        return VerifyResult(
                            ok=False,
                            records_checked=checked,
                            first_bad_seq=seq,
                            reason=f"hmac mismatch at seq={seq}",
                        )
                prev_hash = stored_hash
                expected_seq = seq + 1
    except (OSError, json.JSONDecodeError) as exc:
        return VerifyResult(
            ok=False,
            records_checked=checked,
            first_bad_seq=expected_seq,
            reason=f"ledger parse error: {exc}",
        )
    return VerifyResult(ok=True, records_checked=checked, first_bad_seq=None)


def iter_records(path: Path) -> Iterable[dict[str, Any]]:
    """Yield decoded records from a ledger without verifying integrity."""
    p = Path(path)
    if not p.exists():
        return
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                yield json.loads(stripped)
            except json.JSONDecodeError:
                continue
