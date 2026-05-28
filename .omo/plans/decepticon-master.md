# Decepticon — Master Improvement Plan

**Branch**: `feat/sisyphus-improvements`
**Author**: Sisyphus (autonomous agent, OhMyOpenCode)
**Started**: 2026-05-28
**Source**: Gap analysis vs Strix (25.6k★) + XBOW + AIxCC winners.

This plan ships across multiple waves. Each wave produces atomic, mergeable units.
Open PRs by `@VoidChecksum` (#296–#343) cover ~40% of obvious gaps; this branch
attacks the **remaining 60%** without overlap.

## Architectural constraints (from maintainer 2026-05-28)

Two in-flight architecture redesigns shape every module landed in this branch:

1. **Skillogy replaces Skills middleware**. Do NOT add features that hard-bind
   to the current `SkillsMiddleware` API or assume `load_skill` / `list_skills`
   tool names are stable. New code that needs to know "is this tool internal
   vs external" should resolve via a registry hook, not a hardcoded name list,
   so the Skills→Skillogy migration is a one-line change instead of a sweep.
2. **OPPLAN goes from linear sequence to MITRE ATT&CK matrix**. Do NOT assume
   objectives execute in declared order. Multi-stage flows (verified-fix loop,
   CART, agent dispatch, attack-graph traversal) MUST consume objectives by
   ATT&CK technique tag (`T1190`, `T1003.001`, etc.) rather than ordinal
   position. The Neo4j schema already keys on `:Technique` IDs — align there.

Existing flagged tactical hardcodes that will need migration when Skillogy /
ATT&CK-matrix-OPPLAN land:

- `prompt_injection_shield.py::PromptInjectionShieldMiddleware._SAFE_TOOL_NAMES`
  hardcodes `load_skill`, `list_skills` — replace with registry lookup.

---

## WAVE 1 — Standalone P0 modules (this branch, first commits)

No coordination with other PRs required. Each is a pure addition.

| § | Module | Status |
|---|---|---|
| 2.5 | `decepticon/middleware/prompt_injection_shield.py` — agent self-defense | shipping |
| 2.6 | `decepticon/middleware/budget.py` — engagement + per-agent USD caps | shipping |
| 2.4 | `decepticon/tools/defense/` — Sigma/YARA → SIEM exporters (Splunk, Sentinel, Elastic, Defender XDR, CrowdStrike) | shipping |
| 4.4 | `decepticon/runtime/recording.py` — record/replay determinism | shipping |
| 6.3 | `containers/sandbox-entrypoint.sh` asciinema bundling | shipping |
| 2.3 | Vulnresearch verified-fix iteration loop (3× retry, `patch_verified` tag) | shipping |

## WAVE 2 — Integration & marketing parity

Depends on WAVE-1 modules landing.

- §2.2 HITL checkpoint approval middleware + WS bridge to web dashboard.
- §4.3 `decepticon scan --quick --diff-base` CLI mode (Strix parity).
- New repo: `purpleailab/decepticon-action` GitHub Action template.
- SARIF upload step (consumes existing `research/sarif.py`).

## WAVE 3 — Domain agent expansion

Seven new specialist agents covering 60% of red-team work currently uncovered.

- `agents/standard/mobile_operator.py` + Frida bridge + skills/mobile/
- `agents/standard/iot_operator.py` + binwalk/firmware-mod-kit + skills/iot/
- `agents/standard/ics_operator.py` + Modbus/BACnet + skills/ics/ (RoE-gated)
- `agents/standard/forensicator.py` + Volatility 3 + skills/dfir/
- `agents/standard/phish_operator.py` + GoPhish/Evilginx2 (RoE-gated)
- `agents/standard/supply_chain_operator.py` + skills/supply-chain/
- `agents/standard/osint_operator.py` (split from Recon; outbound-only)

## WAVE 4 — CART (Continuous Automated Red Teaming)

- §2.1 Watcher agent, engagement snapshot diff, replay_mode flag.
- §4.2 Sandbox-per-engagement isolation (launcher Go changes).
- §6.1 Benchmark expansion: HTB Pro Labs harness + Buttercup replay + decepticon-bench.

## WAVE 5 — Skills + sandbox tooling breadth

- Skill packs: container escape, K8s adversarial, OIDC/SAML/OAuth/WebAuthn,
  GraphQL deep, SSTI per-framework, cache poisoning, gRPC, eBPF abuse,
  hypervisor escape, WAF bypass taxonomy.
- Sandbox tools: AFL++/libFuzzer/Honggfuzz, syzkaller, Frida-server,
  GoPhish+Evilginx2 compose profile, Caldera, Velociraptor, Atomic Red Team,
  Maltego CLI, Responder→ntlmrelayx→secretsdump chain, Certipy-ad,
  nanodump/HandleKatz, Ligolo-ng/Chisel.
- §5.3 `decepticon-skill-pack` repo template + skills.decepticon.red index.

## WAVE 6 — UX polish + PR triage

- §6.2 Web dashboard timeline scrubber.
- PR triage: review/merge #297 #298 #296 #302 #303 #329 from VoidChecksum.

## WAVE 7 — Long-term moonshots

- Learned attack-path cost model (XGBoost on Neo4j subgraph features).
- Federated learning across engagements.
- AI-vs-AI co-evolution (BlueAgent self-play).
- Voice/on-call mode (PagerDuty webhook).
- Adversary-emulation profile library (APT29/FIN7 presets).
- Browser extension for in-flight OSINT.

---

## Commit hygiene

- One module = one commit. No mega-commits.
- Every commit must pass `pre-commit run --all-files` if pre-commit is wired.
- Test for every new module under `packages/decepticon/tests/unit/<module>/`.
- Docs: every new feature lands with a doc page under `docs/features/` or `docs/architecture/`.
