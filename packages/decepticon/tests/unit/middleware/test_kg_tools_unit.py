"""Unit tests for :mod:`kg_internal.tools` — driver-free.

Verifies the factory output, engagement-scope rejection, payload
parsing, the InjectedState fallback to ``engagement_name``, and the
dispatch through to the store / adapter registry.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from decepticon.middleware.kg_internal.tools import (
    DEFAULT_KG_TOOLS,
    build_kg_tools,
)


# ── Tool invocation envelope (matches OPPLAN test pattern) ──────────────


def _call(tool: Any, args: dict[str, Any], state: dict[str, Any]) -> str:
    """Invoke a middleware tool with a synthetic ToolCall envelope.

    LangChain's ``InjectedToolCallId`` requires the tool to be called
    via a ``{"type": "tool_call", "id": ..., "args": ...}`` payload,
    not as a bare kwargs dict.
    """
    payload = {
        "name": getattr(tool, "name", "tool"),
        "type": "tool_call",
        "id": "test-tool-call-id",
        "args": {**args, "state": state},
    }
    return tool.invoke(payload)


def _fake_store(record_result: dict[str, Any] | None = None) -> MagicMock:
    """Mock KGStore with ``record_observations`` recording its inputs."""
    store = MagicMock(name="KGStore")
    store.record_observations.return_value = record_result or {
        "created": 1,
        "merged": 0,
        "edges": 0,
        "revision": "rev-stub",
    }
    return store


# ── Factory shape ───────────────────────────────────────────────────────


def test_default_factory_returns_two_tools() -> None:
    tools = build_kg_tools(_fake_store())
    names = {t.name for t in tools}
    assert names == {"kg_record", "kg_ingest"}


def test_factory_respects_enabled_filter() -> None:
    record_only = build_kg_tools(_fake_store(), enabled={"kg_record"})
    assert [t.name for t in record_only] == ["kg_record"]

    ingest_only = build_kg_tools(_fake_store(), enabled={"kg_ingest"})
    assert [t.name for t in ingest_only] == ["kg_ingest"]


def test_factory_with_empty_enabled_returns_no_tools() -> None:
    assert build_kg_tools(_fake_store(), enabled=set()) == []


def test_default_kg_tools_constant_lists_both() -> None:
    assert DEFAULT_KG_TOOLS == frozenset({"kg_record", "kg_ingest"})


# ── kg_record engagement scope ──────────────────────────────────────────


def test_kg_record_returns_error_when_engagement_unset() -> None:
    store = _fake_store()
    [kg_record, _] = build_kg_tools(store)
    out_msg = _call(
        kg_record,
        {"observations": json.dumps([{"kind": "Host", "key": "h::1", "label": "h"}])},
        state={},
    )
    payload = json.loads(out_msg.content)
    assert "error" in payload
    assert "kg_engagement" in payload["error"]
    store.record_observations.assert_not_called()


def test_kg_record_pulls_engagement_from_kg_engagement_field() -> None:
    store = _fake_store()
    [kg_record, _] = build_kg_tools(store)
    _call(
        kg_record,
        {"observations": json.dumps([{"kind": "Host", "key": "h::1", "label": "h"}])},
        state={"kg_engagement": "acme-q2", "role": "analyst"},
    )
    store.record_observations.assert_called_once()
    kwargs = store.record_observations.call_args.kwargs
    assert kwargs["engagement"] == "acme-q2"
    assert kwargs["created_by"] == "analyst"
    assert kwargs["source_episode_id"] == "test-tool-call-id"


def test_kg_record_falls_back_to_engagement_name_when_kg_engagement_missing() -> None:
    """Upstream EngagementContextMiddleware hydrates engagement_name. If
    the KG middleware hasn't run yet (first turn), the tool can still
    resolve scope from that upstream field."""
    store = _fake_store()
    [kg_record, _] = build_kg_tools(store)
    _call(
        kg_record,
        {"observations": json.dumps([{"kind": "Host", "key": "h::1", "label": "h"}])},
        state={"engagement_name": "acme-fallback"},
    )
    kwargs = store.record_observations.call_args.kwargs
    assert kwargs["engagement"] == "acme-fallback"


def test_kg_record_created_by_falls_back_to_agent_when_role_missing() -> None:
    store = _fake_store()
    [kg_record, _] = build_kg_tools(store)
    _call(
        kg_record,
        {"observations": json.dumps([{"kind": "Host", "key": "h::1", "label": "h"}])},
        state={"kg_engagement": "acme"},
    )
    kwargs = store.record_observations.call_args.kwargs
    assert kwargs["created_by"] == "agent"


# ── kg_record payload parsing ──────────────────────────────────────────


def test_kg_record_rejects_malformed_json_observations() -> None:
    store = _fake_store()
    [kg_record, _] = build_kg_tools(store)
    out_msg = _call(
        kg_record,
        {"observations": "not valid json"},
        state={"kg_engagement": "acme"},
    )
    payload = json.loads(out_msg.content)
    assert "error" in payload
    assert "JSON" in payload["error"]
    store.record_observations.assert_not_called()


def test_kg_record_rejects_non_list_observations() -> None:
    store = _fake_store()
    [kg_record, _] = build_kg_tools(store)
    out_msg = _call(
        kg_record,
        {"observations": json.dumps({"kind": "Host"})},
        state={"kg_engagement": "acme"},
    )
    payload = json.loads(out_msg.content)
    assert "error" in payload
    assert "list" in payload["error"]


def test_kg_record_returns_store_result_as_json() -> None:
    store = _fake_store(
        record_result={"created": 2, "merged": 1, "edges": 3, "revision": "rev-xyz"}
    )
    [kg_record, _] = build_kg_tools(store)
    out_msg = _call(
        kg_record,
        {
            "observations": json.dumps(
                [
                    {"kind": "Host", "key": "h::1", "label": "h"},
                    {"kind": "Service", "key": "s::1", "label": "s"},
                ]
            )
        },
        state={"kg_engagement": "acme"},
    )
    payload = json.loads(out_msg.content)
    assert payload == {"created": 2, "merged": 1, "edges": 3, "revision": "rev-xyz"}


def test_kg_record_surfaces_store_value_error_as_error_payload() -> None:
    store = MagicMock()
    store.record_observations.side_effect = ValueError("observation missing key")
    [kg_record, _] = build_kg_tools(store)
    out_msg = _call(
        kg_record,
        {"observations": json.dumps([{"kind": "Host", "label": "h"}])},
        state={"kg_engagement": "acme"},
    )
    payload = json.loads(out_msg.content)
    assert payload == {"error": "observation missing key"}


# ── kg_ingest dispatch ─────────────────────────────────────────────────


def test_kg_ingest_returns_error_when_engagement_unset() -> None:
    store = _fake_store()
    [_, kg_ingest] = build_kg_tools(store)
    out_msg = _call(
        kg_ingest,
        {"scanner_kind": "nmap_xml", "path": "/tmp/whatever.xml"},
        state={},
    )
    payload = json.loads(out_msg.content)
    assert "error" in payload
    assert "kg_engagement" in payload["error"]


def test_kg_ingest_unknown_scanner_returns_dispatcher_error() -> None:
    store = _fake_store()
    [_, kg_ingest] = build_kg_tools(store)
    out_msg = _call(
        kg_ingest,
        {"scanner_kind": "made_up", "path": "/tmp/whatever"},
        state={"kg_engagement": "acme"},
    )
    payload = json.loads(out_msg.content)
    assert "error" in payload
    assert "unknown scanner_kind" in payload["error"]


def test_kg_ingest_missing_file_returns_dispatcher_error(tmp_path: Any) -> None:
    store = _fake_store()
    [_, kg_ingest] = build_kg_tools(store)
    out_msg = _call(
        kg_ingest,
        {
            "scanner_kind": "nmap_xml",
            "path": str(tmp_path / "missing.xml"),
        },
        state={"kg_engagement": "acme"},
    )
    payload = json.loads(out_msg.content)
    assert "error" in payload
    assert "not found" in payload["error"]


def test_kg_ingest_routes_to_adapter_and_returns_summary(tmp_path: Any) -> None:
    """Happy-path nmap_xml ingest — the adapter writes via the store
    mock, the tool returns the dispatcher's wrapped summary."""
    f = tmp_path / "scan.xml"
    f.write_text(
        """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <ports>
              <port portid="80" protocol="tcp">
                <state state="open"/>
                <service name="http"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """,
        encoding="utf-8",
    )

    store = MagicMock()
    store.record_observations.return_value = {
        "created": 3,
        "merged": 0,
        "edges": 1,
        "revision": "rev-after",
    }
    [_, kg_ingest] = build_kg_tools(store)
    out_msg = _call(
        kg_ingest,
        {"scanner_kind": "nmap_xml", "path": str(f)},
        state={"kg_engagement": "acme", "role": "recon"},
    )
    payload = json.loads(out_msg.content)
    assert payload["scanner"] == "nmap_xml"
    assert payload["path"] == str(f)
    assert payload["hosts"] == 1
    assert payload["services"] == 1
    assert payload["entrypoints"] == 1

    # The adapter must have used the trusted engagement / created_by /
    # source_episode_id from the middleware.
    store.record_observations.assert_called_once()
    kwargs = store.record_observations.call_args.kwargs
    assert kwargs["engagement"] == "acme"
    assert kwargs["created_by"] == "recon"
    assert kwargs["source_episode_id"] == "test-tool-call-id"


# ── Tool docstrings — guard the LLM-facing description surface ─────────


def test_kg_record_description_mentions_observations_shape() -> None:
    [kg_record, _] = build_kg_tools(_fake_store())
    desc = kg_record.description or ""
    assert "JSON" in desc
    assert "key" in desc
    assert "edges_out" in desc


def test_kg_ingest_description_lists_builtin_scanners() -> None:
    [_, kg_ingest] = build_kg_tools(_fake_store())
    desc = kg_ingest.description or ""
    for kind in ("nmap_xml", "nuclei_jsonl", "httpx_jsonl", "sarif"):
        assert kind in desc


# Helper to silence type-warnings on unused tmp_path fixture parameter.
@pytest.fixture
def _silence_tmp_path() -> None:
    return None
