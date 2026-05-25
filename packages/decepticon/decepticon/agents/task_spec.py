"""Scoped sub-agent task specification.

This module defines the data contract the orchestrator uses to hand a
single discrete task to a specialist sub-agent without copying the
parent conversation history into the child ``messages`` state.

The motivation is two-fold: copying the parent transcript inflates
child token counts (and breaks LangChain's prompt cache) and it leaks
parent reasoning that is rarely relevant to the child task. The child
should receive only:

1. its own system prompt (built by ``load_prompt`` for its role),
2. a compact, deterministic task spec (this module),
3. file references to parent artifacts when reading them is useful.

Integration (replacing the stock dispatch payload with
:func:`scoped_dispatch_payload`) is intentionally not in this PR — the
data contract lands first so it can be reviewed independently of the
LangGraph middleware surgery.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SUBAGENT_TASK_SYSTEM_PROMPT = (
    "You are executing a scoped child task for Decepticon.\n"
    "Use only this task spec, your own system prompt, current engagement\n"
    "middleware context, and referenced parent artifacts. Do not assume\n"
    "access to the parent's private reasoning or full transcript. Return\n"
    "results using the existing specialist handoff format."
)


@dataclass(frozen=True, slots=True)
class SubAgentTaskSpec:
    """Compact handoff payload for a specialist sub-agent invocation.

    Fields:

    * ``objective`` — one-sentence statement of what the child must do.
    * ``scope`` — engagement scope (in-scope hosts/CIDRs, RoE limits).
    * ``inputs`` — tool-arg-shaped key/value bundle the parent already
      gathered (e.g. ``target_url``, ``credential_id``).
    * ``expected_outputs`` — names of artifacts/keys the parent expects
      back so the child can self-check before returning.
    * ``parent_artifacts`` — paths on the engagement workspace the child
      may read (findings, screenshots, captures). Never inline content.
    * ``engagement_id`` — parent's engagement identifier.
    * ``parent_agent`` — name of the dispatching agent (typically
      ``"decepticon"``).
    """

    objective: str
    scope: Mapping[str, Any] = field(default_factory=dict)
    inputs: Mapping[str, Any] = field(default_factory=dict)
    expected_outputs: tuple[str, ...] = field(default_factory=tuple)
    parent_artifacts: tuple[Path, ...] = field(default_factory=tuple)
    engagement_id: str = ""
    parent_agent: str = ""

    def render(self) -> str:
        """Render a deterministic markdown handoff.

        Dict keys are sorted so identical inputs produce identical text,
        which is what makes prompt caching effective for the child run.
        """
        lines: list[str] = ["# Sub-agent task", ""]
        lines.append(f"**Objective:** {self.objective.strip()}")
        if self.engagement_id:
            lines.append(f"**Engagement:** {self.engagement_id}")
        if self.parent_agent:
            lines.append(f"**Dispatched by:** {self.parent_agent}")
        lines.append("")

        lines.append("## Scope")
        lines.append("```json")
        lines.append(json.dumps(dict(self.scope), indent=2, sort_keys=True, default=str))
        lines.append("```")
        lines.append("")

        lines.append("## Inputs")
        lines.append("```json")
        lines.append(json.dumps(dict(self.inputs), indent=2, sort_keys=True, default=str))
        lines.append("```")
        lines.append("")

        lines.append("## Expected outputs")
        if self.expected_outputs:
            for item in self.expected_outputs:
                lines.append(f"- {item}")
        else:
            lines.append("- (none specified)")
        lines.append("")

        lines.append("## Parent artifacts (file references — read on demand)")
        if self.parent_artifacts:
            for path in self.parent_artifacts:
                lines.append(f"- {Path(path).as_posix()}")
        else:
            lines.append("- (none)")
        lines.append("")

        return "\n".join(lines).rstrip() + "\n"


def scoped_dispatch_payload(task_spec: SubAgentTaskSpec) -> list[Mapping[str, Any]]:
    """Build the LangGraph child ``messages`` list from a task spec.

    Returns a two-message list (system + human) the dispatch wrapper can
    pass to the specialist's runnable in place of the parent's message
    history. Returned dicts mirror the shape LangChain's converters
    expect so callers can ``BaseMessage``-deserialize them without
    importing this module from the LangChain side.
    """
    return [
        {"role": "system", "content": SUBAGENT_TASK_SYSTEM_PROMPT},
        {"role": "user", "content": task_spec.render()},
    ]


def estimate_token_savings(
    parent_message_chars: int, task_spec: SubAgentTaskSpec
) -> int:
    """Estimate the character delta between full-history vs scoped dispatch.

    Used by tests to assert the scoped dispatch is materially smaller
    than what the parent would have sent before this refactor. Uses raw
    character count as a coarse proxy for tokens; the actual tokenizer
    ratio varies per model but the relative savings hold.
    """
    scoped_chars = len(SUBAGENT_TASK_SYSTEM_PROMPT) + len(task_spec.render())
    return parent_message_chars - scoped_chars


__all__ = [
    "SUBAGENT_TASK_SYSTEM_PROMPT",
    "SubAgentTaskSpec",
    "estimate_token_savings",
    "scoped_dispatch_payload",
]


def _coerce_paths(paths: Iterable[Any]) -> tuple[Path, ...]:
    """Convert a heterogeneous iterable into a tuple of ``Path``.

    Used by tests and integration code that builds a task spec from
    string-or-Path mixes coming out of LangGraph state.
    """
    return tuple(p if isinstance(p, Path) else Path(str(p)) for p in paths)
