"""Edge-case + loader coverage for ``decepticon.blue_cell.rule_match``.

``test_rule_match.py`` exercises the happy-path matching behaviour. This
file targets the silent-failure-prone internals that file leaves
uncovered:

* ``_event_field`` dotted-path traversal over malformed / missing / list
  values (a wrong return here makes a detection rule silently never fire);
* ``_compile_pattern`` literal-escaping vs ``re:`` regex mode;
* ``_evaluate_condition`` empty / unknown-selection / malformed-expression
  branches — the sandboxed ``eval`` path must fail closed (``False``),
  never raise;
* the rule-file loader chain (``load_rules`` / ``_load_from_jsonl`` /
  ``_load_from_json`` / ``_rule_from_dict``), which parses untrusted
  on-disk rule files and must skip junk rather than crash.

No network / docker / LLM dependencies.
"""

from __future__ import annotations

import json
from pathlib import Path

from decepticon.blue_cell.rule_match import (
    DetectionRule,
    _compile_pattern,
    _evaluate_condition,
    _event_field,
    _load_from_json,
    _load_from_jsonl,
    _rule_from_dict,
    load_rules,
)

# ---------------------------------------------------------------- _event_field


def test_event_field_nested_dotted_path():
    assert _event_field({"actor": {"command_line": "nmap"}}, "actor.command_line") == "nmap"


def test_event_field_missing_key_returns_empty():
    assert _event_field({}, "actor.command_line") == ""
    assert _event_field({"actor": {}}, "actor.command_line") == ""


def test_event_field_non_dict_midpath_returns_empty():
    # 'actor' is a string, so descending into '.command_line' must bail out.
    assert _event_field({"actor": "scalar"}, "actor.command_line") == ""


def test_event_field_none_value_returns_empty():
    assert _event_field({"actor": None}, "actor") == ""


def test_event_field_list_value_is_space_joined():
    assert _event_field({"args": ["a", "b", 3]}, "args") == "a b 3"


def test_event_field_scalar_is_stringified():
    assert _event_field({"pid": 1234}, "pid") == "1234"


# ---------------------------------------------------------------- _compile_pattern


def test_compile_pattern_literal_is_escaped():
    pat = _compile_pattern("a.b")
    assert pat.search("a.b") is not None
    assert pat.search("axb") is None  # '.' is a literal, not a wildcard


def test_compile_pattern_regex_mode_with_prefix():
    pat = _compile_pattern(r"re:foo\d+")
    assert pat.search("foo123") is not None
    assert pat.search("foo") is None


def test_compile_pattern_is_case_insensitive():
    assert _compile_pattern("GetUserSPNs").search("impacket-getuserspns") is not None
    assert _compile_pattern("re:nmap").search("NMAP -sV") is not None


# ---------------------------------------------------------------- _evaluate_condition


def test_empty_condition_requires_all_selections_true():
    assert _evaluate_condition("", {"a": True, "b": True}) is True
    assert _evaluate_condition("", {"a": True, "b": False}) is False


def test_empty_condition_with_no_selections_is_false():
    assert _evaluate_condition("", {}) is False


def test_condition_and_or_not():
    assert _evaluate_condition("a and b", {"a": True, "b": True}) is True
    assert _evaluate_condition("a and b", {"a": True, "b": False}) is False
    assert _evaluate_condition("a or b", {"a": False, "b": True}) is True
    assert _evaluate_condition("not a", {"a": False}) is True


def test_unknown_selection_name_fails_closed():
    # 'ghost' is not a known selection -> the whole condition is False, not a crash.
    assert _evaluate_condition("ghost", {"a": True}) is False
    assert _evaluate_condition("a and ghost", {"a": True}) is False


def test_malformed_condition_fails_closed():
    # All tokens are whitelisted but form invalid Python -> eval raises -> False.
    assert _evaluate_condition("a and", {"a": True}) is False


# ---------------------------------------------------------------- _rule_from_dict


def test_rule_from_dict_rejects_non_dict():
    assert _rule_from_dict(["not", "a", "dict"]) is None  # type: ignore[arg-type]


def test_rule_from_dict_requires_id():
    assert _rule_from_dict({}) is None
    assert _rule_from_dict({"id": "   "}) is None  # blank after strip


def test_rule_from_dict_match_shorthand_defaults_condition():
    rule = _rule_from_dict({"id": "r1", "match": {"actor.command_line": "nmap"}})
    assert rule is not None
    assert rule.selections == {"selection": {"actor.command_line": "nmap"}}
    assert rule.condition == "selection"


def test_rule_from_dict_explicit_selections_and_condition():
    rule = _rule_from_dict(
        {
            "id": "r2",
            "title": "two-sel",
            "level": "high",
            "mitre": ["T1046", "T1059"],
            "selections": {"sel": {"a": "x"}, "filt": {"b": "y"}},
            "condition": "sel and not filt",
        }
    )
    assert rule is not None
    assert rule.level == "high"
    assert rule.mitre == ("T1046", "T1059")
    assert set(rule.selections) == {"sel", "filt"}
    assert rule.condition == "sel and not filt"


def test_rule_from_dict_skips_non_dict_selection_values():
    rule = _rule_from_dict({"id": "r3", "selections": {"good": {"k": "v"}, "bad": "nope"}})
    assert rule is not None
    assert rule.selections == {"good": {"k": "v"}}


def test_rule_from_dict_rejects_non_dict_selections_block():
    assert _rule_from_dict({"id": "r4", "selections": "not-a-dict"}) is None


# ---------------------------------------------------------------- loaders


def _rule_line(rid: str, cmd: str) -> str:
    return json.dumps({"id": rid, "match": {"actor.command_line": cmd}})


def test_load_from_jsonl_skips_blank_and_malformed(tmp_path: Path):
    f = tmp_path / "rules.jsonl"
    f.write_text(
        "\n".join(
            [
                _rule_line("a", "nmap"),
                "",  # blank line
                "{not valid json",  # malformed
                '{"foo": "bar"}',  # valid JSON but no id -> _rule_from_dict returns None
                _rule_line("b", "masscan"),
            ]
        ),
        encoding="utf-8",
    )
    rules = _load_from_jsonl(f)
    assert [r.id for r in rules] == ["a", "b"]


def test_load_from_jsonl_missing_file_is_non_fatal(tmp_path: Path):
    assert _load_from_jsonl(tmp_path / "nope.jsonl") == []


def test_load_rules_nonexistent_path_returns_empty(tmp_path: Path):
    # Neither a file nor a directory -> load_rules returns [] without raising.
    assert load_rules(tmp_path / "does-not-exist") == []


def test_load_from_json_list_and_single_and_scalar(tmp_path: Path):
    list_file = tmp_path / "list.json"
    list_file.write_text(
        json.dumps([{"id": "x", "match": {"a": "1"}}, {"id": "y", "match": {"a": "2"}}]),
        encoding="utf-8",
    )
    assert [r.id for r in _load_from_json(list_file)] == ["x", "y"]

    single_file = tmp_path / "single.json"
    single_file.write_text(json.dumps({"id": "solo", "match": {"a": "1"}}), encoding="utf-8")
    assert [r.id for r in _load_from_json(single_file)] == ["solo"]

    scalar_file = tmp_path / "scalar.json"
    scalar_file.write_text("42", encoding="utf-8")
    assert _load_from_json(scalar_file) == []


def test_load_from_json_malformed_is_non_fatal(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert _load_from_json(bad) == []


def test_load_rules_from_single_jsonl_file(tmp_path: Path):
    f = tmp_path / "rules.jsonl"
    f.write_text(_rule_line("only", "whoami"), encoding="utf-8")
    rules = load_rules(f)
    assert isinstance(rules[0], DetectionRule)
    assert [r.id for r in rules] == ["only"]


def test_load_rules_from_directory_mixes_json_and_jsonl(tmp_path: Path):
    (tmp_path / "a.json").write_text(
        json.dumps({"id": "from-json", "match": {"a": "1"}}), encoding="utf-8"
    )
    (tmp_path / "b.jsonl").write_text(_rule_line("from-jsonl", "x"), encoding="utf-8")
    (tmp_path / "c.json").write_text(
        json.dumps([{"id": "list-1", "match": {"a": "1"}}, {"id": "list-2", "match": {"a": "2"}}]),
        encoding="utf-8",
    )
    (tmp_path / "ignored.txt").write_text("not a rule file", encoding="utf-8")
    rules = load_rules(tmp_path)
    # sorted(iterdir) => a.json, b.jsonl, c.json ; .txt ignored
    assert [r.id for r in rules] == ["from-json", "from-jsonl", "list-1", "list-2"]
