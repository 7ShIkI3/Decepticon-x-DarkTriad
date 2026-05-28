"""Tests for the Blue Cell detection-rule matcher."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from decepticon.blue_cell.rule_match import (
    DetectionRule,
    RuleMatcher,
    load_rules,
    score_mttd,
)


def _event(
    *,
    cmd: str,
    proc: str = "",
    source: str = "sandbox.tmux.main",
    ts: float = 1000.0,
) -> dict:
    return {
        "ts": ts,
        "source": source,
        "actor": {"process": proc, "command_line": cmd},
        "raw": cmd,
    }


class TestRuleCompilation:
    def test_substring_match_default(self) -> None:
        rule = DetectionRule(
            id="r-1",
            title="kerberoast",
            selections={"selection": {"actor.command_line": "GetUserSPNs"}},
            condition="selection",
        )
        m = RuleMatcher([rule])
        hits = m.match(_event(cmd="impacket-GetUserSPNs corp/user@dc"), now_ts=1001.0)
        assert len(hits) == 1
        assert hits[0].rule.id == "r-1"

    def test_regex_match_with_re_prefix(self) -> None:
        rule = DetectionRule(
            id="r-2",
            title="bash to /tmp",
            selections={"selection": {"actor.command_line": r"re:bash\s.*-c\s+['\"].*\/tmp\/"}},
            condition="selection",
        )
        m = RuleMatcher([rule])
        hits = m.match(_event(cmd="bash -c 'cat /tmp/x.txt'"), now_ts=1.0)
        assert hits
        misses = m.match(_event(cmd="ls /tmp"), now_ts=1.0)
        assert not misses

    def test_no_match_returns_empty(self) -> None:
        rule = DetectionRule(
            id="r-3",
            title="nmap",
            selections={"selection": {"actor.command_line": "nmap"}},
            condition="selection",
        )
        m = RuleMatcher([rule])
        assert m.match(_event(cmd="ls -la"), now_ts=1.0) == []


class TestBooleanConditions:
    def test_and_condition(self) -> None:
        rule = DetectionRule(
            id="r-4",
            title="nmap to dc",
            selections={
                "tool": {"actor.command_line": "nmap"},
                "host": {"actor.command_line": "dc01.corp.local"},
            },
            condition="tool and host",
        )
        m = RuleMatcher([rule])
        assert m.match(_event(cmd="nmap dc01.corp.local"), now_ts=1.0)
        assert not m.match(_event(cmd="nmap web01"), now_ts=1.0)

    def test_not_condition_excludes(self) -> None:
        rule = DetectionRule(
            id="r-5",
            title="suspicious curl excluding allowlisted host",
            selections={
                "tool": {"actor.command_line": "curl"},
                "allowlisted": {"actor.command_line": "internal.corp.local"},
            },
            condition="tool and not allowlisted",
        )
        m = RuleMatcher([rule])
        assert m.match(_event(cmd="curl https://evil.example/"), now_ts=1.0)
        assert not m.match(_event(cmd="curl https://internal.corp.local/api/"), now_ts=1.0)

    def test_or_condition(self) -> None:
        rule = DetectionRule(
            id="r-6",
            title="any of nmap/masscan/rustscan",
            selections={
                "nmap": {"actor.command_line": "nmap"},
                "masscan": {"actor.command_line": "masscan"},
                "rustscan": {"actor.command_line": "rustscan"},
            },
            condition="nmap or masscan or rustscan",
        )
        m = RuleMatcher([rule])
        assert m.match(_event(cmd="masscan -p1-1000 10.0.0.0/24"), now_ts=1.0)
        assert m.match(_event(cmd="rustscan -a 10.0.0.5"), now_ts=1.0)


class TestMTTD:
    def test_score_mttd_positive_delta(self) -> None:
        assert score_mttd(red_event_ts=1000.0, blue_detection_ts=1003.5) == pytest.approx(3.5)

    def test_score_mttd_negative_clamped_to_zero(self) -> None:
        assert score_mttd(red_event_ts=2000.0, blue_detection_ts=1995.0) == 0.0

    def test_detection_event_mttd_property(self) -> None:
        rule = DetectionRule(id="r-7", title="x", selections={"s": {"raw": "test"}}, condition="s")
        m = RuleMatcher([rule])
        hits = m.match(_event(cmd="test", ts=1000.0), now_ts=1004.2)
        assert hits[0].mttd_seconds == pytest.approx(4.2)


class TestRuleLoading:
    def test_load_rules_from_jsonl(self, tmp_path: Path) -> None:
        path = tmp_path / "rules.jsonl"
        path.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "id": "rule-1",
                            "title": "kerberoast",
                            "level": "high",
                            "mitre": ["T1558.003"],
                            "match": {"actor.command_line": "GetUserSPNs"},
                        }
                    ),
                    json.dumps(
                        {
                            "id": "rule-2",
                            "title": "bloodhound",
                            "level": "medium",
                            "mitre": ["T1087.002"],
                            "selections": {
                                "tool": {"actor.command_line": "bloodhound-python"},
                            },
                            "condition": "tool",
                        }
                    ),
                    "",
                    "not json",
                ]
            ),
            encoding="utf-8",
        )
        rules = load_rules(path)
        assert len(rules) == 2
        assert rules[0].id == "rule-1"
        assert rules[0].mitre == ("T1558.003",)
        assert rules[1].condition == "tool"

    def test_load_rules_directory(self, tmp_path: Path) -> None:
        for i in range(2):
            (tmp_path / f"r{i}.jsonl").write_text(
                json.dumps(
                    {
                        "id": f"r-{i}",
                        "title": f"rule {i}",
                        "match": {"raw": f"pattern_{i}"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
        rules = load_rules(tmp_path)
        assert len(rules) == 2
        assert {r.id for r in rules} == {"r-0", "r-1"}


class TestTapToMatcherShape:
    def test_tap_event_to_dict_shape_matches_rule_event_field_traversal(self) -> None:
        """Regression: TapEvent.to_dict() must emit nested dicts.

        The matcher's _event_field() traverses dotted paths by splitting
        on '.' and walking nested dicts. If TapEvent.to_dict() emits
        flat keys like {'actor.command_line': '...'}, the traversal
        does event.get('actor') which returns None and every rule
        misses. Caught by the E2E audit pass; this test pins the
        contract so the regression can't recur.
        """
        from decepticon.blue_cell.tap import TapEvent

        event = TapEvent(
            ts=1000.0,
            source="sandbox.tmux.main",
            actor_process="nmap",
            actor_command_line="nmap 10.0.0.5",
            network_destinations=("10.0.0.5",),
            raw="nmap 10.0.0.5",
        )
        d = event.to_dict()
        assert isinstance(d.get("actor"), dict), "actor must be a nested dict, not flat dotted keys"
        assert d["actor"]["command_line"] == "nmap 10.0.0.5"
        assert d["actor"]["process"] == "nmap"
        assert isinstance(d.get("network"), dict)
        assert d["network"]["destinations"] == ["10.0.0.5"]

        rule = DetectionRule(
            id="r-pipe",
            title="pipeline-shape",
            selections={"sel": {"actor.command_line": "nmap"}},
            condition="sel",
        )
        matcher = RuleMatcher([rule])
        hits = matcher.match(d, now_ts=1001.0)
        assert len(hits) == 1, (
            "rule with 'actor.command_line' selection MUST match the "
            "tap's emitted event - if this fails, the shapes drifted"
        )


class TestEndToEnd:
    def test_full_pipeline_red_attack_blue_detect(self) -> None:
        """A simulated kerberoast attack should fire the matching rule."""
        rules = [
            DetectionRule(
                id="ATT-T1558.003",
                title="Kerberoast attempt",
                level="high",
                mitre=("T1558.003",),
                selections={
                    "tool": {"actor.command_line": "GetUserSPNs"},
                    "spn_request_flag": {"actor.command_line": "re:-request(?:s)?\\s+"},
                },
                condition="tool and spn_request_flag",
            ),
        ]
        matcher = RuleMatcher(rules)
        event = _event(
            cmd="impacket-GetUserSPNs -request -dc-ip 10.0.0.5 corp.local/lowpriv:Password1",
            proc="impacket-GetUserSPNs",
            ts=1000.0,
        )
        hits = matcher.match(event, now_ts=1002.7)
        assert len(hits) == 1
        hit = hits[0]
        assert hit.rule.mitre == ("T1558.003",)
        assert hit.mttd_seconds == pytest.approx(2.7)
        assert "tool.actor.command_line" in hit.matched_fields
