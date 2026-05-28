"""Machine-readable Rules of Engagement schema.

The human-readable RoE (``roe.json:in_scope``, ``out_of_scope``,
``prohibited_actions``) is authored by Soundwave for the operator's
review. This schema extends it with a ``machine_enforcement`` block
that drives the RoE-enforcement middleware at tool-call time.

The extension is OPTIONAL: a roe.json without ``machine_enforcement``
runs in *audit-only* mode - every tool call is logged but nothing is
refused. Operators opt in by adding the ``machine_enforcement`` block
and setting ``mode`` to ``"enforce"``.

Design choices:

  * **Allowlist + denylist.** Targets must match ``scope.in_scope_*``
    AND must NOT match ``scope.out_of_scope_*``. The denylist takes
    precedence: an in-scope CIDR with an out-of-scope host inside it
    is correctly blocked on the host.

  * **CIDR + glob + literal.** CIDRs (``10.0.0.0/24``), domain globs
    (``*.acme.com``), and literal hostnames/IPs are all accepted.
    The evaluator picks the matching algorithm based on the entry
    shape.

  * **Forbidden command patterns are regex.** Per-engagement custom
    patterns let the operator forbid e.g.
    ``\\bhydra\\s.*-t\\s*[5-9]\\d+`` (Hydra with more than 50 parallel
    threads). Patterns are anchored to the command string, not the
    full tool arguments dict.

  * **Cloud metadata services are denied by default.** A default
    forbidden-destinations list catches the AWS / Azure / GCP IMDS
    endpoints unless the engagement opts out (``allow_cloud_metadata: true``).

  * **Mode = audit | warn | enforce.** Audit logs everything but
    never blocks. Warn logs + injects a ToolMessage warning into the
    transcript but lets the call proceed. Enforce blocks AND logs.
    Default is ``audit`` for backward compatibility.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Iterable


class EnforcementMode(StrEnum):
    AUDIT = "audit"
    WARN = "warn"
    ENFORCE = "enforce"


_DEFAULT_FORBIDDEN_DESTS: tuple[str, ...] = (
    "169.254.169.254",
    "fd00:ec2::254",
    "metadata.google.internal",
    "metadata.azure.com",
    "100.100.100.200",
)


@dataclass(frozen=True, slots=True)
class ScopeRule:
    """One in-scope or out-of-scope entry."""

    pattern: str
    kind: str = "auto"

    def resolved_kind(self) -> str:
        if self.kind != "auto":
            return self.kind
        try:
            ipaddress.ip_network(self.pattern, strict=False)
            return "cidr"
        except ValueError:
            pass
        if "*" in self.pattern or "?" in self.pattern:
            return "domain-glob"
        if any(ch.isdigit() and not ch.isalpha() for ch in self.pattern[:1]):
            try:
                ipaddress.ip_address(self.pattern)
                return "ip"
            except ValueError:
                pass
        return "host"


@dataclass(frozen=True, slots=True)
class MachineEnforcement:
    """Runtime-enforceable RoE rules."""

    mode: EnforcementMode = EnforcementMode.AUDIT
    in_scope: tuple[ScopeRule, ...] = field(default_factory=tuple)
    out_of_scope: tuple[ScopeRule, ...] = field(default_factory=tuple)
    forbidden_destinations: tuple[str, ...] = field(default_factory=tuple)
    forbidden_command_patterns: tuple[str, ...] = field(default_factory=tuple)
    allow_cloud_metadata: bool = False
    max_concurrent_connections: int | None = None
    min_inter_request_delay_ms: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> MachineEnforcement:
        if not data:
            return cls()
        mode_str = str(data.get("mode", EnforcementMode.AUDIT.value)).lower()
        try:
            mode = EnforcementMode(mode_str)
        except ValueError:
            mode = EnforcementMode.AUDIT
        return cls(
            mode=mode,
            in_scope=tuple(_parse_rules(data.get("in_scope") or [])),
            out_of_scope=tuple(_parse_rules(data.get("out_of_scope") or [])),
            forbidden_destinations=tuple(data.get("forbidden_destinations") or ()),
            forbidden_command_patterns=tuple(data.get("forbidden_command_patterns") or ()),
            allow_cloud_metadata=bool(data.get("allow_cloud_metadata", False)),
            max_concurrent_connections=data.get("max_concurrent_connections"),
            min_inter_request_delay_ms=int(data.get("min_inter_request_delay_ms") or 0),
        )

    def effective_forbidden_destinations(self) -> tuple[str, ...]:
        if self.allow_cloud_metadata:
            return self.forbidden_destinations
        return self.forbidden_destinations + _DEFAULT_FORBIDDEN_DESTS


def _parse_rules(items: Iterable[Any]) -> list[ScopeRule]:
    rules: list[ScopeRule] = []
    for item in items:
        if isinstance(item, str):
            rules.append(ScopeRule(pattern=item))
        elif isinstance(item, dict) and item.get("target"):
            rules.append(ScopeRule(pattern=str(item["target"]), kind=str(item.get("type", "auto"))))
    return rules


@dataclass(frozen=True, slots=True)
class Decision:
    """Outcome of an RoE evaluation."""

    allow: bool
    reason_code: str
    reason_detail: str
    risk: str = "low"
    matched_targets: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def allow_default(cls) -> Decision:
        return cls(allow=True, reason_code="OK", reason_detail="no rules matched")

    @classmethod
    def refuse(
        cls,
        code: str,
        detail: str,
        risk: str = "high",
        matched: tuple[str, ...] = (),
    ) -> Decision:
        return cls(
            allow=False,
            reason_code=code,
            reason_detail=detail,
            risk=risk,
            matched_targets=matched,
        )


def _glob_match(pattern: str, candidate: str) -> bool:
    regex = "^" + re.escape(pattern).replace(r"\*", "[^.]+").replace(r"\?", ".") + "$"
    return re.match(regex, candidate, re.IGNORECASE) is not None


def _matches_rule(rule: ScopeRule, target: str) -> bool:
    kind = rule.resolved_kind()
    if kind == "cidr":
        try:
            network = ipaddress.ip_network(rule.pattern, strict=False)
            return ipaddress.ip_address(target) in network
        except ValueError:
            return False
    if kind == "domain-glob":
        return _glob_match(rule.pattern, target)
    return rule.pattern.lower() == target.lower()


def evaluate_target(
    target: str,
    rules: MachineEnforcement,
) -> Decision:
    """Evaluate a single target host or IP against the RoE."""
    if not target:
        return Decision.allow_default()

    for forbidden in rules.effective_forbidden_destinations():
        if _matches_rule(ScopeRule(pattern=forbidden), target):
            return Decision.refuse(
                code="FORBIDDEN_DESTINATION",
                detail=f"{target!r} matches forbidden destination {forbidden!r}",
                matched=(forbidden,),
            )

    for rule in rules.out_of_scope:
        if _matches_rule(rule, target):
            return Decision.refuse(
                code="OUT_OF_SCOPE",
                detail=f"{target!r} matches out-of-scope entry {rule.pattern!r}",
                matched=(rule.pattern,),
            )

    if rules.in_scope:
        for rule in rules.in_scope:
            if _matches_rule(rule, target):
                return Decision(
                    allow=True,
                    reason_code="IN_SCOPE",
                    reason_detail=f"{target!r} matches in-scope entry {rule.pattern!r}",
                    matched_targets=(rule.pattern,),
                )
        return Decision.refuse(
            code="NOT_IN_SCOPE",
            detail=f"{target!r} matches no in-scope entry",
            risk="medium",
        )

    return Decision.allow_default()


def evaluate_command(
    command: str,
    rules: MachineEnforcement,
) -> Decision:
    """Evaluate a shell command against forbidden-command regexes."""
    if not command:
        return Decision.allow_default()
    for pattern in rules.forbidden_command_patterns:
        try:
            if re.search(pattern, command):
                return Decision.refuse(
                    code="FORBIDDEN_COMMAND",
                    detail=f"command matched forbidden pattern {pattern!r}",
                    matched=(pattern,),
                )
        except re.error:
            continue
    return Decision.allow_default()
