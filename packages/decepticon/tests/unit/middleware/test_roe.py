"""Tests for the RoE enforcement middleware + machine-readable schema."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from langchain_core.messages import ToolMessage

from decepticon.middleware._audit_sink import RoEAuditSink, verify_ledger
from decepticon.middleware._command_targets import extract_targets
from decepticon.middleware.roe import (
    RoEEnforcementMiddleware,
)
from decepticon_core.types.roe import (
    EnforcementMode,
    MachineEnforcement,
    evaluate_command,
    evaluate_target,
)


class TestMachineEnforcementSchema:
    def test_empty_dict_defaults_to_audit(self) -> None:
        rules = MachineEnforcement.from_dict({})
        assert rules.mode == EnforcementMode.AUDIT
        assert rules.in_scope == ()
        assert rules.out_of_scope == ()

    def test_none_defaults_to_audit(self) -> None:
        rules = MachineEnforcement.from_dict(None)
        assert rules.mode == EnforcementMode.AUDIT

    def test_string_rules_parsed(self) -> None:
        rules = MachineEnforcement.from_dict(
            {"in_scope": ["10.0.0.0/24", "*.acme.com", "single-host.example"]}
        )
        assert len(rules.in_scope) == 3
        kinds = [r.resolved_kind() for r in rules.in_scope]
        assert "cidr" in kinds
        assert "domain-glob" in kinds
        assert "host" in kinds

    def test_dict_rules_parsed_with_type(self) -> None:
        rules = MachineEnforcement.from_dict(
            {"in_scope": [{"target": "10.0.0.0/24", "type": "ip-range"}]}
        )
        assert rules.in_scope[0].pattern == "10.0.0.0/24"

    def test_mode_string_to_enum(self) -> None:
        for s, expected in [
            ("audit", EnforcementMode.AUDIT),
            ("warn", EnforcementMode.WARN),
            ("enforce", EnforcementMode.ENFORCE),
            ("ENFORCE", EnforcementMode.ENFORCE),
            ("unknown-value", EnforcementMode.AUDIT),
        ]:
            assert MachineEnforcement.from_dict({"mode": s}).mode == expected

    def test_cloud_metadata_denied_by_default(self) -> None:
        rules = MachineEnforcement.from_dict({"in_scope": ["10.0.0.0/8"]})
        decision = evaluate_target("169.254.169.254", rules)
        assert not decision.allow
        assert decision.reason_code == "FORBIDDEN_DESTINATION"

    def test_cloud_metadata_allowable_when_opted_in(self) -> None:
        rules = MachineEnforcement.from_dict(
            {"in_scope": ["169.254.0.0/16"], "allow_cloud_metadata": True}
        )
        decision = evaluate_target("169.254.169.254", rules)
        assert decision.allow


class TestEvaluateTarget:
    def test_no_in_scope_means_allow_with_out_of_scope_only(self) -> None:
        rules = MachineEnforcement.from_dict(
            {"out_of_scope": ["10.99.0.0/16"], "allow_cloud_metadata": True}
        )
        assert evaluate_target("8.8.8.8", rules).allow
        assert not evaluate_target("10.99.1.1", rules).allow

    def test_in_scope_required_when_set(self) -> None:
        rules = MachineEnforcement.from_dict({"in_scope": ["10.0.0.0/24"]})
        assert evaluate_target("10.0.0.5", rules).allow
        assert not evaluate_target("8.8.8.8", rules).allow

    def test_out_of_scope_precedes_in_scope(self) -> None:
        rules = MachineEnforcement.from_dict(
            {"in_scope": ["10.0.0.0/24"], "out_of_scope": ["10.0.0.5"]}
        )
        assert not evaluate_target("10.0.0.5", rules).allow
        assert evaluate_target("10.0.0.6", rules).allow

    def test_domain_glob_match(self) -> None:
        rules = MachineEnforcement.from_dict({"in_scope": ["*.acme.com"]})
        assert evaluate_target("api.acme.com", rules).allow
        assert evaluate_target("www.acme.com", rules).allow
        assert not evaluate_target("partner.acme-evil.com", rules).allow
        assert not evaluate_target("evilcorp.com", rules).allow

    def test_empty_target_allowed(self) -> None:
        assert evaluate_target("", MachineEnforcement()).allow


class TestEvaluateCommand:
    def test_no_patterns_allow(self) -> None:
        assert evaluate_command("nmap 10.0.0.1", MachineEnforcement()).allow

    def test_forbidden_pattern_blocks(self) -> None:
        rules = MachineEnforcement.from_dict(
            {"forbidden_command_patterns": [r"(?i)\brm\s+-rf\s+/(?!tmp)"]}
        )
        d = evaluate_command("rm -rf /etc", rules)
        assert not d.allow
        assert d.reason_code == "FORBIDDEN_COMMAND"

    def test_invalid_regex_skipped(self) -> None:
        rules = MachineEnforcement.from_dict({"forbidden_command_patterns": ["[unclosed"]})
        assert evaluate_command("rm -rf /etc", rules).allow


class TestExtractTargets:
    def test_empty_returns_empty(self) -> None:
        assert extract_targets("") == set()
        assert extract_targets("  ") == set()
        assert extract_targets("ls -la") == set()

    def test_extracts_nmap_targets(self) -> None:
        cmd = "nmap -sV -p 22,80 10.0.0.5"
        assert "10.0.0.5" in extract_targets(cmd)

    def test_extracts_nmap_cidr(self) -> None:
        cmd = "nmap -sV 10.0.0.0/24"
        assert "10.0.0.0/24" in extract_targets(cmd)

    def test_extracts_ssh_target(self) -> None:
        targets = extract_targets("ssh root@10.0.0.5")
        assert "10.0.0.5" in targets

    def test_extracts_ssh_with_port(self) -> None:
        assert "10.0.0.5" in extract_targets("ssh -p 2222 user@10.0.0.5")

    def test_extracts_curl_url(self) -> None:
        targets = extract_targets("curl -X GET https://api.acme.com/v1/users")
        assert {"api.acme.com"} <= targets

    def test_extracts_hostname_after_verb(self) -> None:
        assert "target.example" in extract_targets("nmap target.example -p 80")

    def test_extracts_impacket_credentials_target(self) -> None:
        cmd = "impacket-secretsdump 'corp/admin:Password!@10.0.0.10'"
        targets = extract_targets(cmd)
        assert "10.0.0.10" in targets


class TestAuditSink:
    def test_append_creates_file(self, tmp_path: Path) -> None:
        sink = RoEAuditSink(path=tmp_path / "audit.jsonl")
        sink.append({"event": "test1"})
        assert (tmp_path / "audit.jsonl").exists()
        lines = (tmp_path / "audit.jsonl").read_text().splitlines()
        assert len(lines) == 1
        rec = json.loads(lines[0])
        assert rec["seq"] == 1
        assert rec["prev_hash"] == "0" * 64
        assert len(rec["hash"]) == 64

    def test_chain_is_consistent(self, tmp_path: Path) -> None:
        sink = RoEAuditSink(path=tmp_path / "audit.jsonl")
        for i in range(5):
            sink.append({"event": f"evt-{i}"})
        result = verify_ledger(tmp_path / "audit.jsonl")
        assert result.ok
        assert result.records_checked == 5

    def test_tamper_detected(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = RoEAuditSink(path=path)
        for i in range(3):
            sink.append({"event": f"evt-{i}"})
        lines = path.read_text().splitlines()
        rec1 = json.loads(lines[1])
        rec1["event"] = "TAMPERED"
        lines[1] = json.dumps(rec1)
        path.write_text("\n".join(lines) + "\n")
        result = verify_ledger(path)
        assert not result.ok
        assert result.first_bad_seq == 2

    def test_hmac_chain_when_key_set(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = RoEAuditSink(path=path, hmac_key=b"operator-secret-key")
        for i in range(3):
            sink.append({"event": f"evt-{i}"})
        result = verify_ledger(path, hmac_key=b"operator-secret-key")
        assert result.ok
        assert result.records_checked == 3

    def test_hmac_mismatch_detected(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = RoEAuditSink(path=path, hmac_key=b"correct-key")
        sink.append({"event": "test"})
        result = verify_ledger(path, hmac_key=b"wrong-key")
        assert not result.ok
        assert "hmac mismatch" in result.reason

    def test_new_sink_hydrates_from_existing_file(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        s1 = RoEAuditSink(path=path)
        s1.append({"event": "a"})
        s1.append({"event": "b"})
        s2 = RoEAuditSink(path=path)
        s2.append({"event": "c"})
        result = verify_ledger(path)
        assert result.ok
        assert result.records_checked == 3
        recs = [json.loads(line) for line in path.read_text().splitlines() if line]
        assert [r["seq"] for r in recs] == [1, 2, 3]


def _make_request(tool_name: str, command: str = "", state: dict | None = None):
    request = MagicMock()
    request.tool = MagicMock()
    request.tool.name = tool_name
    request.state = state or {}
    request.tool_call = MagicMock()
    request.tool_call.args = {"command": command}
    request.tool_call.id = "tc-test"
    request.tool_call_args = {"command": command}
    request.tool_call_id = "tc-test"
    return request


def _write_roe(workspace: Path, machine_enforcement: dict) -> None:
    (workspace / "plan").mkdir(parents=True, exist_ok=True)
    (workspace / "plan" / "roe.json").write_text(
        json.dumps({"machine_enforcement": machine_enforcement}), encoding="utf-8"
    )


class TestRoEMiddleware:
    def test_audit_mode_logs_but_allows(self, tmp_path: Path) -> None:
        _write_roe(tmp_path, {"mode": "audit", "in_scope": ["10.0.0.0/24"]})
        sink = RoEAuditSink(path=tmp_path / "audit.jsonl")
        mw = RoEEnforcementMiddleware(sink=sink)
        req = _make_request("bash", "nmap 8.8.8.8", state={"workspace_path": str(tmp_path)})
        handler = MagicMock(return_value=ToolMessage(content="ok", tool_call_id="tc-test"))
        result = mw.wrap_tool_call(req, handler)
        assert handler.called
        assert isinstance(result, ToolMessage)
        assert result.content == "ok"
        assert (tmp_path / "audit.jsonl").exists()

    def test_enforce_mode_refuses_out_of_scope(self, tmp_path: Path) -> None:
        _write_roe(tmp_path, {"mode": "enforce", "in_scope": ["10.0.0.0/24"]})
        mw = RoEEnforcementMiddleware()
        req = _make_request("bash", "nmap 8.8.8.8", state={"workspace_path": str(tmp_path)})
        handler = MagicMock()
        result = mw.wrap_tool_call(req, handler)
        assert not handler.called
        assert "[ROE_REFUSED]" in result.content
        assert result.status == "error"

    def test_enforce_mode_allows_in_scope(self, tmp_path: Path) -> None:
        _write_roe(tmp_path, {"mode": "enforce", "in_scope": ["10.0.0.0/24"]})
        mw = RoEEnforcementMiddleware()
        req = _make_request("bash", "nmap 10.0.0.10", state={"workspace_path": str(tmp_path)})
        handler = MagicMock(return_value=ToolMessage(content="ok", tool_call_id="tc-test"))
        result = mw.wrap_tool_call(req, handler)
        assert handler.called
        assert result.content == "ok"

    def test_enforce_blocks_imds_by_default(self, tmp_path: Path) -> None:
        _write_roe(tmp_path, {"mode": "enforce", "in_scope": ["10.0.0.0/8"]})
        mw = RoEEnforcementMiddleware()
        req = _make_request(
            "bash",
            "curl -s http://169.254.169.254/latest/meta-data/",
            state={"workspace_path": str(tmp_path)},
        )
        handler = MagicMock()
        result = mw.wrap_tool_call(req, handler)
        assert not handler.called
        assert "FORBIDDEN_DESTINATION" in result.content

    def test_warn_mode_allows_with_warning(self, tmp_path: Path) -> None:
        _write_roe(tmp_path, {"mode": "warn", "out_of_scope": ["10.99.0.0/16"]})
        mw = RoEEnforcementMiddleware()
        req = _make_request("bash", "nmap 10.99.1.1", state={"workspace_path": str(tmp_path)})
        handler = MagicMock(return_value=ToolMessage(content="scan output", tool_call_id="tc-test"))
        result = mw.wrap_tool_call(req, handler)
        assert handler.called
        assert "[ROE_WARN]" in result.content
        assert "scan output" in result.content

    def test_ungated_tool_passes_through(self, tmp_path: Path) -> None:
        _write_roe(tmp_path, {"mode": "enforce", "in_scope": ["10.0.0.0/24"]})
        mw = RoEEnforcementMiddleware()
        req = _make_request("opplan_add_objective", "", state={"workspace_path": str(tmp_path)})
        handler = MagicMock(return_value=ToolMessage(content="ok", tool_call_id="tc-test"))
        mw.wrap_tool_call(req, handler)
        assert handler.called

    def test_missing_roe_defaults_to_audit_mode(self, tmp_path: Path) -> None:
        sink = RoEAuditSink(path=tmp_path / "audit.jsonl")
        mw = RoEEnforcementMiddleware(sink=sink)
        req = _make_request("bash", "nmap 8.8.8.8", state={"workspace_path": str(tmp_path)})
        handler = MagicMock(return_value=ToolMessage(content="ok", tool_call_id="tc-test"))
        result = mw.wrap_tool_call(req, handler)
        assert handler.called
        assert result.content == "ok"

    def test_audit_records_carry_engagement_and_command(self, tmp_path: Path) -> None:
        _write_roe(tmp_path, {"mode": "audit", "in_scope": ["10.0.0.0/24"]})
        sink = RoEAuditSink(path=tmp_path / "audit.jsonl")
        mw = RoEEnforcementMiddleware(sink=sink)
        req = _make_request(
            "bash",
            "nmap 10.0.0.10",
            state={"workspace_path": str(tmp_path), "engagement_name": "acme-q2"},
        )
        handler = MagicMock(return_value=ToolMessage(content="ok", tool_call_id="tc-test"))
        mw.wrap_tool_call(req, handler)
        recs = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
        assert len(recs) == 1
        assert recs[0]["engagement"] == "acme-q2"
        assert "nmap 10.0.0.10" in recs[0]["command_excerpt"]
        assert recs[0]["decision"] == "allow"

    def test_audit_records_refuse(self, tmp_path: Path) -> None:
        _write_roe(tmp_path, {"mode": "enforce", "in_scope": ["10.0.0.0/24"]})
        sink = RoEAuditSink(path=tmp_path / "audit.jsonl")
        mw = RoEEnforcementMiddleware(sink=sink)
        req = _make_request("bash", "nmap 8.8.8.8", state={"workspace_path": str(tmp_path)})
        handler = MagicMock()
        mw.wrap_tool_call(req, handler)
        recs = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
        assert len(recs) == 1
        assert recs[0]["decision"] == "refuse"
        assert recs[0]["reason_code"] == "NOT_IN_SCOPE"


class TestSlotRegistration:
    def test_slot_is_in_enum_and_safety_critical(self) -> None:
        from decepticon_core.contracts.slots import (
            SAFETY_CRITICAL_SLOTS,
            SLOTS_PER_ROLE,
            MiddlewareSlot,
        )

        assert MiddlewareSlot.ROE_ENFORCEMENT.value == "roe-enforcement"
        assert MiddlewareSlot.ROE_ENFORCEMENT in SAFETY_CRITICAL_SLOTS
        for role, slots in SLOTS_PER_ROLE.items():
            assert MiddlewareSlot.ROE_ENFORCEMENT in slots, (
                f"role {role!r} missing ROE_ENFORCEMENT slot"
            )

    def test_default_factory_is_registered(self) -> None:
        from decepticon.agents.middleware_slots import DEFAULT_SLOT_FACTORIES
        from decepticon_core.contracts.slots import MiddlewareSlot

        assert MiddlewareSlot.ROE_ENFORCEMENT in DEFAULT_SLOT_FACTORIES
        factory = DEFAULT_SLOT_FACTORIES[MiddlewareSlot.ROE_ENFORCEMENT]
        mw = factory(role="recon")
        assert isinstance(mw, RoEEnforcementMiddleware)
