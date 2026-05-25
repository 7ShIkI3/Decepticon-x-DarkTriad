"""Tests for ``decepticon.agents.task_spec`` — scoped sub-agent handoff."""

from __future__ import annotations

import json
from pathlib import Path

from decepticon.agents.task_spec import (
    SUBAGENT_TASK_SYSTEM_PROMPT,
    SubAgentTaskSpec,
    estimate_token_savings,
    scoped_dispatch_payload,
)


def _full_spec() -> SubAgentTaskSpec:
    return SubAgentTaskSpec(
        objective="Identify SQL injection on /search endpoint",
        scope={
            "in_scope": ["target.example", "api.target.example"],
            "out_of_scope": ["billing.target.example"],
        },
        inputs={"target_url": "https://target.example/search", "credential_id": "test-1"},
        expected_outputs=("FIND-NNN.md if exploitable", "scan log"),
        parent_artifacts=(
            Path("/workspace/eng-1/findings/FIND-001.md"),
            Path("/workspace/eng-1/recon/sitemap.json"),
        ),
        engagement_id="eng-1",
        parent_agent="decepticon",
    )


def test_render_includes_objective_engagement_dispatcher() -> None:
    body = _full_spec().render()
    assert "# Sub-agent task" in body
    assert "Identify SQL injection on /search endpoint" in body
    assert "**Engagement:** eng-1" in body
    assert "**Dispatched by:** decepticon" in body


def test_render_uses_sorted_json_for_dicts() -> None:
    spec = SubAgentTaskSpec(
        objective="x",
        scope={"z_last": 1, "a_first": 2, "m_mid": 3},
        inputs={"y": "Y", "x": "X"},
    )
    body = spec.render()
    scope_json = body.split("## Scope\n```json\n", 1)[1].split("\n```", 1)[0]
    parsed = json.loads(scope_json)
    assert list(parsed.keys()) == ["a_first", "m_mid", "z_last"]
    inputs_json = body.split("## Inputs\n```json\n", 1)[1].split("\n```", 1)[0]
    parsed_inputs = json.loads(inputs_json)
    assert list(parsed_inputs.keys()) == ["x", "y"]


def test_render_is_deterministic_across_identical_specs() -> None:
    a = _full_spec().render()
    b = _full_spec().render()
    assert a == b


def test_render_lists_expected_outputs_and_artifacts() -> None:
    body = _full_spec().render()
    assert "- FIND-NNN.md if exploitable" in body
    assert "- scan log" in body
    assert "/workspace/eng-1/findings/FIND-001.md" in body
    assert "/workspace/eng-1/recon/sitemap.json" in body


def test_render_with_no_expected_outputs_shows_placeholder() -> None:
    spec = SubAgentTaskSpec(objective="x")
    body = spec.render()
    assert "## Expected outputs\n- (none specified)" in body


def test_render_with_no_artifacts_shows_placeholder() -> None:
    spec = SubAgentTaskSpec(objective="x")
    body = spec.render()
    assert "(none)" in body


def test_scoped_dispatch_payload_has_two_messages() -> None:
    spec = _full_spec()
    payload = scoped_dispatch_payload(spec)
    assert len(payload) == 2
    assert payload[0]["role"] == "system"
    assert payload[0]["content"] == SUBAGENT_TASK_SYSTEM_PROMPT
    assert payload[1]["role"] == "user"
    assert payload[1]["content"] == spec.render()


def test_scoped_dispatch_is_smaller_than_full_history() -> None:
    spec = _full_spec()
    fake_parent_history_chars = 80_000

    savings = estimate_token_savings(
        parent_message_chars=fake_parent_history_chars, task_spec=spec
    )

    scoped_chars = len(SUBAGENT_TASK_SYSTEM_PROMPT) + len(spec.render())
    assert savings == fake_parent_history_chars - scoped_chars
    assert savings > 70_000


def test_dataclass_is_frozen() -> None:
    spec = _full_spec()
    raised = False
    try:
        spec.objective = "tampered"  # type: ignore[misc]
    except Exception:
        raised = True
    assert raised


def test_task_spec_is_serializable_via_render() -> None:
    spec = _full_spec()
    body = spec.render()
    assert isinstance(body, str)
    assert body.startswith("# Sub-agent task")
    assert body.endswith("\n")


def test_path_objects_render_as_posix() -> None:
    spec = SubAgentTaskSpec(
        objective="x",
        parent_artifacts=(Path("C:/Users/x/findings/FIND-001.md"),),
    )
    body = spec.render()
    assert "C:/Users/x/findings/FIND-001.md" in body


def test_empty_engagement_and_parent_agent_are_omitted() -> None:
    spec = SubAgentTaskSpec(objective="x")
    body = spec.render()
    assert "**Engagement:**" not in body
    assert "**Dispatched by:**" not in body
