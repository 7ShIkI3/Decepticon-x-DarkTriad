# Blue Cell — closing the Offensive Vaccine loop

> Decepticon's defensive sibling. Reads what Red Cell does, evaluates
> Sigma-style rules in real time, scores MTTD, and writes the result
> back to the engagement knowledge graph as the **proven** detection
> coverage report.

## The gap this closes

The Offensive Vaccine pipeline (Scanner → Detector → Verifier →
Exploiter → Patcher → **Defender**) is documented as the project's
defining feature. The Defender writes Defense Briefs — Sigma rules,
PoC artifacts, recommended patches. But nothing in the OSS runs the
Defender's rules against the agent's own activity. The customer's SOC
team gets a PDF; nobody proves the rules actually fire.

Blue Cell is the runtime piece. It reads what Red Cell does, scores
the Detector's rules against it, and emits a structured
"Detection Coverage" deliverable that says **"this rule fired in
3.2s on this technique; this rule MISSED these other 4 techniques."**

That's the difference between a "we wrote some Sigma rules" deliverable
and a "we wrote some Sigma rules AND validated them end-to-end against
the same kill chain we ran" deliverable.

## Architecture

```
                       decepticon-net (mgmt)
        ┌───────────────────────────────────────────────────┐
        │                                                   │
        │   orchestrator ◄────────────────────────────┐     │
        │       │ task()                               │     │
        │       ▼                                      │     │
        │   subagents ──── bash() ─────────┐           │     │
        │   (recon, exploit, ...)          │           │     │
        │                                   │           │     │
        └───────────────────────────────────┼───────────┼─────┘
                                            │           │
                       sandbox-net          │           │
        ┌──────────────────────────────────────────┐    │
        │                                  │       │    │
        │  sandbox (Kali)                  │       │    │
        │     │                            │       │    │
        │     │ stdout / stderr            │       │    │
        │     ▼                            │       │    │
        │  /workspace/.sessions/*.log ─────┼───────┼────┘
        │                                  │       │
        │  foothold/target host(s)         │       │
        │     │                            │       │
        │     │ decepticon-telemetry-collector (sidecar daemon, optional)
        │     ▼                            │       │
        │  /workspace/.sessions/_target/<host>.log
        │                                  │       │
        └──────────────────────────────────┴───────┘
                                            │
                                            ▼
                  decepticon.blue_cell.BlueCellTap
                                            │
                                            │ TapEvent stream
                                            ▼
                  decepticon.blue_cell.RuleMatcher  ◄── rules/sigma-*.jsonl
                                            │           (Detector output)
                                            │ DetectionEvent stream
                                            ▼
                          BlueCellAgent (read-only)
                                            │
                                            │ kg_add_node(DetectionFired, ...)
                                            │ kg_add_edge(DETECTED, ...)
                                            ▼
                                       Neo4j knowledge graph
                                            │
                                            ▼
                         Defense Brief + ATT&CK Navigator export
```

## Components

### `decepticon.blue_cell.tap.BlueCellTap`

Tails sandbox + target log files; yields `TapEvent` objects with
normalized fields: ``ts``, ``source``, ``actor.process``,
``actor.command_line``, ``network.destinations``, ``raw``.

The tap is intentionally simple — a feeder, not a parser. SIEM-grade
enrichment (Sysmon parsing, Windows-event normalization) belongs in a
follow-up that swaps in a sidecar telemetry collector per foothold.

### `decepticon.blue_cell.rule_match`

A minimal Sigma-flavored rule matcher:

```python
from decepticon.blue_cell.rule_match import load_rules, RuleMatcher

rules = load_rules("packages/decepticon/decepticon/blue_cell/sample_rules.jsonl")
matcher = RuleMatcher(rules)
hits = matcher.match(event_dict, now_ts=time.time())
```

Rule shape supports two formats:

**Simple match (one selection, implicit condition):**

```json
{
  "id": "DCEP-T1558.003-kerberoast",
  "title": "Kerberoast",
  "level": "high",
  "mitre": ["T1558.003"],
  "match": {"actor.command_line": "GetUserSPNs"}
}
```

**Multi-selection (Sigma-style `condition` over named selections):**

```json
{
  "id": "DCEP-T1003.006-dcsync",
  "title": "DCSync via secretsdump",
  "level": "critical",
  "mitre": ["T1003.006"],
  "selections": {
    "tool": {"actor.command_line": "secretsdump"},
    "dcsync_flag": {"actor.command_line": "re:-just-dc(?:-ntlm)?"}
  },
  "condition": "tool and dcsync_flag"
}
```

Field patterns are substrings by default; `re:` prefix promotes to
regex (case-insensitive). The condition string supports `and`, `or`,
`not`, and parentheses over selection names.

Full pysigma compatibility is a follow-up. The bootstrap matcher
covers ~80% of real-world Sigma rules without the pysigma footprint
(deployers can install pysigma and convert their rules through it).

### `decepticon.blue_cell.sample_rules.jsonl`

Ten baseline detection rules covering common offensive techniques:
Kerberoast, AS-REP roast, DCSync, Pass-the-Hash, web-shell drop,
PowerShell download cradle, password spray, aggressive nmap timing,
LSASS dump (mimikatz), curl-piped-to-bash. Operator deployments swap
this for their own ruleset; the file is the schema reference.

### Knowledge graph integration

Each hit becomes a `DetectionFired` node with:

```python
{
  "key": f"detection::{rule.id}::{event_ts}",
  "rule_id": rule.id,
  "rule_title": rule.title,
  "rule_level": rule.level,
  "mitre": list(rule.mitre),
  "matched_fields": dict(hit.matched_fields),
  "event_ts": hit.event_ts,
  "detection_ts": hit.detection_ts,
  "mttd_seconds": hit.mttd_seconds,
  "source": event["source"],
}
```

Edges:

- `DetectionFired -[:DETECTED]-> Finding` — link to the offensive
  Finding the rule caught.
- `DetectionFired -[:USES_RULE]-> DefenseAction` — link to the
  Sigma-rule artifact the Detector produced.

`Finding`s that never get a `DetectionFired` edge are the engagement's
**detection gaps** — the most important blue-team deliverable.

## Adaptive feedback loop

When a `DetectionFired` lands with a low MTTD (e.g. <5s, configurable),
the orchestrator's pre-iteration hook (planned, not in this commit):

1. Reads recent `DetectionFired` events for the current objective.
2. If avg MTTD < threshold, appends a `SystemMessage` to the next
   model call: *"The last attempt fired detection rule X in 2.4s.
   The technique signature is being watched. Adjust your approach."*
3. Optionally downgrades the OPPLAN objective's `opsec_level` from
   `loud` to `stealth`.

This is the Red-vs-Blue learning loop the project's 2021 history page
promised. The hook is documented; implementation lands in the
follow-up sprint that wires the orchestrator's planning side.

## Defense Brief format

At engagement out-brief, the Blue Cell agent emits a structured report:

```
Engagement: <slug>
Time window: <start> -> <end>

Detection coverage:
   42 attacks observed
   28 detected (66.7%)
   14 missed (33.3%)
   median MTTD: 3.8s
   p95 MTTD: 24.1s

Detected techniques (sorted by MTTD desc):
   T1558.003 Kerberoast        — fired in 1.2s  (rule DCEP-T1558.003-kerberoast)
   T1003.006 DCSync            — fired in 2.4s  (rule DCEP-T1003.006-dcsync)
   T1059.001 PS download       — fired in 0.8s  (rule DCEP-T1059.001-...)
   ...

Missed techniques:
   T1574.002 DLL side-loading via PSExec - no rule
   T1218.011 rundll32 with comsvcs.dll  - rule exists but condition too strict
   ...

Proposed rule improvements:
   - DCEP-T1218.011: extend match to comsvcs.dll regardless of rundll32 arg position
```

## What ships in this commit vs. follow-up

**In this commit (Tier 6 scaffolding):**

- `decepticon.blue_cell.tap.BlueCellTap` — sandbox log tail + normalize.
- `decepticon.blue_cell.rule_match.RuleMatcher` — Sigma-flavored
  regex matcher with `and`/`or`/`not` condition support.
- `decepticon.blue_cell.sample_rules.jsonl` — 10 baseline rules.
- 12 unit tests covering rule loading, substring/regex match, boolean
  conditions, MTTD scoring, end-to-end kerberoast detection.
- This design doc.

**Follow-up (tracked):**

- `decepticon.agents.standard.blue_cell.create_blue_cell_agent` —
  read-only agent factory consuming the tap + matcher.
- Orchestrator pre-iteration hook reading `DetectionFired` events
  for adaptive OPSEC.
- pysigma-based rule loader for full Sigma compatibility.
- `decepticon-telemetry-collector` sidecar for target-side telemetry.
- ATT&CK Navigator JSON export.
- Customer-deliverable Defense Brief generator.

## References

- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — the rule format
  this matcher's authoring conventions follow.
- [Mordor](https://github.com/OTRF/mordor) — adversary-activity
  datasets useful as Blue Cell regression-test corpora.
- [`docs/offensive-vaccine.md`](../offensive-vaccine.md)
  — the broader pipeline this closes.
- [`docs/security/decepticon-threat-model.md`](../security/decepticon-threat-model.md)
  — the threat model Blue Cell helps validate (Red Cell on the front
  side, Blue Cell on the back).
