---
title: CI Arsenal
description: Every static analysis, security scanner, and bug finder that runs on every Decepticon PR
---

# CI Arsenal

Decepticon runs **18 independent static analysis tools** on every pull request,
plus weekly supply-chain scoring via OpenSSF Scorecard. This document
explains what each tool does, why it's enforced, and how to suppress a
finding when one is genuinely a false positive.

## What runs on every PR

| Tool | Surface | Hard-gate | Notes |
|------|---------|-----------|-------|
| **Ruff** (`lint` + `format`) | Python | yes | Existing |
| **basedpyright** | Python | errors only | Existing |
| **mypy** | Python | report | Second-opinion type checker, JSON artifact |
| **Bandit** | Python security | Medium/High | SARIF uploaded to Security tab |
| **Semgrep** | Multi (Python/TS/Dockerfile/Bash/YAML) | yes | Public packs + custom Decepticon rules |
| **Vulture** | Python dead code | report | 90% confidence threshold |
| **Refurb** | Python modernization | report | Idiomatic Python 3.13 suggestions |
| **Radon / Xenon** | Python complexity | rank F max | Cyclomatic complexity gate |
| **deptry** | Python deps | yes | Unused / missing dep detection |
| **CodeQL** | Python + TS/JS | yes | Existing — GitHub Advanced Security |
| **ESLint** | TypeScript | yes | Existing — `--max-warnings 0` |
| **Knip** | TypeScript dead code | report | Unused exports / files in web + CLI |
| **golangci-lint** | Go | yes | 30+ linters incl. gosec, staticcheck, errcheck |
| **Hadolint** | Dockerfiles | warning | All 6 container Dockerfiles |
| **ShellCheck** | Bash | warning | All container entrypoints + install.sh |
| **yamllint** | YAML | yes | workflows + compose + configs |
| **actionlint** | GitHub Actions | yes | Workflow syntax + shell-in-yaml |
| **markdownlint-cli2** | Markdown | yes | 269 docs + SKILL.md files |
| **typos** | All text | yes | Existing — with offensive-security allowlist |
| **Trivy** (fs + config) | IaC + secrets | report | SARIF |
| **Checkov** | Dockerfile + compose | report | Misconfig scanner |
| **OSV-Scanner** | All deps | report | Google's vuln DB, broader than pip-audit |
| **TruffleHog** | Secret scan | yes | Only verified secrets fail |
| **dependency-review-action** | New deps | High severity | PR-only — blocks vulnerable new deps |
| **pip-audit** | Python deps | report | Existing |
| **gitleaks** | Secrets | report | Existing |

Plus weekly:

| Tool | Frequency | Purpose |
|------|-----------|---------|
| **OpenSSF Scorecard** | Weekly + on push | Supply-chain posture score |

## Custom Semgrep rules

`/.semgrep/decepticon-rules.yml` enforces Decepticon-specific invariants
that public rule packs can't express:

| Rule | What it catches |
|------|-----------------|
| `decepticon-no-shell-true-outside-sandbox` | `subprocess.run(..., shell=True)` outside `sandbox_kernel/` — command-injection vector |
| `decepticon-no-blanket-type-ignore` | `# type: ignore` without a `[code]` — disables ALL checks on the line |
| `decepticon-no-weak-hash` | `hashlib.md5/sha1` without `usedforsecurity=False` documenting non-crypto intent |
| `decepticon-no-verify-false` | `verify=False` on requests/httpx — disables TLS verification |
| `decepticon-no-hardcoded-default-key` | `sk-decepticon-master` literal — the publicly documented LiteLLM default |
| `decepticon-no-assert-in-prod` | `assert` in middleware/tools/sandbox/runtime — stripped by `python -O` |

## Suppression syntax

Each tool has its own suppression directive. Use the precise one for the
finding you're suppressing:

| Tool | Comment | Example |
|------|---------|---------|
| Ruff | `# noqa: <code>` | `# noqa: F401` |
| basedpyright | `# pyright: ignore[<code>]` | `# pyright: ignore[reportAttributeAccessIssue]` |
| mypy | `# type: ignore[<code>]` | `# type: ignore[no-untyped-def]` |
| Bandit | `# nosec <code>` | `# nosec B310` |
| Semgrep | `# nosemgrep: <rule>` | `# nosemgrep: decepticon-no-hardcoded-default-key` |
| CodeQL | `# lgtm[<rule>]` | `# lgtm[py/unused-global-variable]` |

**Bare suppressions (`# type: ignore` with no code) are rejected** —
they disable every check on the line including future ones.

## How to add a new finding

To make a Decepticon invariant enforceable, add a rule to
`.semgrep/decepticon-rules.yml`. Rule format:

```yaml
- id: decepticon-<short-name>
  severity: ERROR              # ERROR blocks PR; WARNING reports only
  message: |
    Plain-text explanation of why this pattern is bad and what to do instead.
  languages: [python]          # or [ts, javascript, dockerfile, bash, yaml]
  patterns:
    - pattern: <ast-pattern>
    - pattern-not: <legitimate-exception>
  paths:
    exclude:
      - "**/tests/**"
```

Run locally with:

```bash
uv run semgrep scan --config=.semgrep/decepticon-rules.yml --error .
```

## How to disable a tool for a specific PR

Don't. Open a follow-up issue and either fix the finding or remove the
tool from the pipeline if it's producing too many false positives. The
goal is monotonically improving signal — silencing a tool because one PR
is in a hurry is how every static-analysis pipeline eventually dies.

## Local pre-commit hooks

`.pre-commit-config.yaml` runs a subset of these checks on `git commit`.
Install with:

```bash
uv tool install pre-commit
pre-commit install
```

The hooks intentionally run only the fast checks (ruff, format, typos,
yamllint). The expensive scanners (Semgrep, Bandit, mypy, Trivy) run on
CI only — running them on every commit would push the median commit
latency past 30 seconds.
