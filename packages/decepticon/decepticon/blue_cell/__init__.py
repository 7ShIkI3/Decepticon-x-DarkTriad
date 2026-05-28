"""Blue Cell - the defensive sibling agent of the offensive Red Cell.

The promised "Offensive Vaccine" loop (attack → detect → verify) was
documented in `docs/features/offensive-vaccine-pipeline.md` but the
runtime piece - the part where Sigma rules actually get evaluated
against the agent's own activity in real time - had no implementation.
This package provides:

  - ``BlueCellTap``: an event-stream reader over the sandbox's tmux
    pipe-pane logs (and, optionally, target-side telemetry via a
    sidecar daemon on each foothold).
  - ``BlueCellAgent`` (in ``agents/standard/blue_cell.py``): a
    read-only Decepticon agent that subscribes to the tap, evaluates
    Sigma rules produced by the Detector agent, computes MTTD, and
    writes ``DetectionFired`` nodes back to the knowledge graph.
  - ``rule_match``: a minimal regex-based rule matcher that consumes
    rules in either Sigma YAML format or a flat-regex dict. Avoids a
    hard dependency on `pysigma` for the OSS bootstrap; deployers
    that want full Sigma can swap in `pysigma` via the entry-point
    surface.

See ``docs/features/blue-cell.md`` for the full architecture.
"""

from __future__ import annotations

from decepticon.blue_cell.rule_match import (
    DetectionEvent,
    DetectionRule,
    RuleMatcher,
    load_rules,
    score_mttd,
)
from decepticon.blue_cell.tap import BlueCellTap, TapEvent

__all__ = [
    "BlueCellTap",
    "TapEvent",
    "DetectionEvent",
    "DetectionRule",
    "RuleMatcher",
    "load_rules",
    "score_mttd",
]
