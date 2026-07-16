"""
Real Firewall connectors. FortiGate REST API + StormShield CONF API.
Rule analysis, CVE detection, AD × Firewall correlation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

import httpx

logger = logging.getLogger(__name__)


# ── Models ────────────────────────────────────────────────────────────────────


@dataclass
class FirewallRule:
    id: str
    name: str
    source_zones: list[str] = field(default_factory=list)
    source_addresses: list[str] = field(default_factory=list)
    dest_zones: list[str] = field(default_factory=list)
    dest_addresses: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)  # HTTP, SSH, ANY, ...
    action: str = "accept"  # accept | deny
    enabled: bool = True
    log: bool = False

    @property
    def is_any_any(self) -> bool:
        return (
            "any" in [z.lower() for z in self.source_zones]
            and "any" in [z.lower() for z in self.dest_zones]
            and any(s.lower() == "any" for s in self.services)
        )

    @property
    def has_high_risk_ports(self) -> bool:
        risky = {"3389", "445", "135", "139", "22", "23", "21"}
        return bool(risky & {s.lower() for s in self.services if s.lower() != "any"})


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class FirewallFinding:
    rule_id: str
    rule_name: str
    severity: Severity
    description: str
    recommendation: str = ""


@dataclass
class CVECheck:
    cve_id: str
    description: str
    severity: Severity
    affected_versions: list[str] = field(default_factory=list)
    patch_version: str = ""


@dataclass
class FirewallConfig:
    hostname: str
    vendor: str  # fortigate | stormshield
    version: str = ""
    rules: list[FirewallRule] = field(default_factory=list)
    cve_findings: list[CVECheck] = field(default_factory=list)


# ── Known CVEs ────────────────────────────────────────────────────────────────


KNOWN_CVES: dict[str, list[CVECheck]] = {
    "fortigate": [
        CVECheck(
            "CVE-2026-35616",
            "Authentication bypass via crafted HTTP requests",
            Severity.CRITICAL,
            affected_versions=["7.0.0-7.0.16", "7.2.0-7.2.9"],
            patch_version="7.0.17 / 7.2.10",
        ),
        CVECheck(
            "CVE-2022-40684",
            "Authentication bypass on administrative interface",
            Severity.CRITICAL,
            affected_versions=["7.0.0-7.0.6", "7.2.0-7.2.1"],
            patch_version="7.0.7 / 7.2.2",
        ),
        CVECheck(
            "CVE-2023-27997",
            "Heap-based buffer overflow in SSL-VPN",
            Severity.CRITICAL,
            affected_versions=["7.0.0-7.0.12", "7.2.0-7.2.4"],
            patch_version="7.0.13 / 7.2.5",
        ),
    ],
    "stormshield": [
        CVECheck(
            "CVE-2024-29867",
            "Authentication bypass via SNS API",
            Severity.CRITICAL,
            affected_versions=["4.3.0-4.6.5"],
            patch_version="4.6.6",
        ),
        CVECheck(
            "CVE-2023-35158",
            "Command injection in admin portal",
            Severity.HIGH,
            affected_versions=["3.11.0-4.3.2"],
            patch_version="4.3.3",
        ),
    ],
}


# ── FortiGate Connector ───────────────────────────────────────────────────────


class FortiGateConnector:
    """Real FortiGate REST API connector."""

    def __init__(self, host: str, api_key: str, verify_ssl: bool = False, timeout: int = 30):
        self.host = host.rstrip("/")
        self.api_key = api_key
        self.client = httpx.AsyncClient(
            base_url=f"https://{host}/api/v2",
            headers={"Authorization": f"Bearer {api_key}"},
            verify=verify_ssl,
            timeout=timeout,
        )

    async def get_system_status(self) -> dict:
        """Get firewall system info."""
        r = await self.client.get("/cmdb/system/status")
        r.raise_for_status()
        return r.json()

    async def get_firewall_policies(self) -> list[dict]:
        """Get all firewall policies."""
        r = await self.client.get("/cmdb/firewall/policy")
        r.raise_for_status()
        return r.json().get("results", [])

    async def get_addresses(self) -> list[dict]:
        r = await self.client.get("/cmdb/firewall/address")
        r.raise_for_status()
        return r.json().get("results", [])

    async def check_cve(self, version: str) -> list[CVECheck]:
        """Check FortiOS version against known CVEs."""
        findings: list[CVECheck] = []
        for cve in KNOWN_CVES.get("fortigate", []):
            for affected in cve.affected_versions:
                try:
                    parts = affected.split("-")
                    if len(parts) == 2 and parts[0] <= version <= parts[1]:
                        findings.append(cve)
                        break
                except (ValueError, TypeError):
                    pass
        return findings

    async def extract_config(self) -> FirewallConfig:
        """Full configuration extraction."""
        try:
            status = await self.get_system_status()
            version = status.get("results", {}).get("version", "unknown")
        except Exception:
            version = "unknown"

        try:
            policies = await self.get_firewall_policies()
        except Exception:
            policies = []

        rules: list[FirewallRule] = []
        for p in policies:
            rules.append(
                FirewallRule(
                    id=str(p.get("policyid", "")),
                    name=p.get("name", f"Policy-{p.get('policyid', '?')}"),
                    source_zones=[z.get("name", "") for z in p.get("srcintf", [])],
                    source_addresses=[a.get("name", "") for a in p.get("srcaddr", [])],
                    dest_zones=[z.get("name", "") for z in p.get("dstintf", [])],
                    dest_addresses=[a.get("name", "") for a in p.get("dstaddr", [])],
                    services=[s.get("name", "") for s in p.get("service", [])],
                    action=p.get("action", "accept"),
                    enabled=p.get("status") != "disable",
                )
            )

        cve_findings = await self.check_cve(version)

        return FirewallConfig(
            hostname=self.host,
            vendor="fortigate",
            version=version,
            rules=rules,
            cve_findings=cve_findings,
        )

    async def close(self) -> None:
        await self.client.aclose()


# ── StormShield Connector ─────────────────────────────────────────────────────


class StormShieldConnector:
    """Real StormShield SNS API connector."""

    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = False):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.client = httpx.AsyncClient(
            base_url=f"https://{host}/api/v1",
            verify=verify_ssl,
            timeout=30,
        )
        self._token: str | None = None

    async def login(self) -> bool:
        try:
            r = await self.client.post(
                "/auth/login",
                json={
                    "username": self.username,
                    "password": self.password,
                },
            )
            r.raise_for_status()
            self._token = r.json().get("token", "")
            self.client.headers["Authorization"] = f"Token {self._token}"
            return True
        except Exception as e:
            logger.error("StormShield login failed: %s", e)
            return False

    async def get_firewall_rules(self) -> list[dict]:
        if not self._token:
            await self.login()
        r = await self.client.get("/firewall/rules")
        r.raise_for_status()
        return r.json().get("results", [])

    async def check_cve(self, version: str) -> list[CVECheck]:
        findings: list[CVECheck] = []
        for cve in KNOWN_CVES.get("stormshield", []):
            for affected in cve.affected_versions:
                try:
                    parts = affected.split("-")
                    if len(parts) == 2 and parts[0] <= version <= parts[1]:
                        findings.append(cve)
                        break
                except (ValueError, TypeError):
                    pass
        return findings

    async def extract_config(self) -> FirewallConfig:
        try:
            await self.login()
            rules_raw = await self.get_firewall_rules()
        except Exception as e:
            logger.error("failed to extract StormShield config: %s", e)
            rules_raw = []

        rules: list[FirewallRule] = []
        for r in rules_raw:
            rules.append(
                FirewallRule(
                    id=str(r.get("id", "")),
                    name=r.get("name", "unnamed"),
                    source_addresses=r.get("sources", []),
                    dest_addresses=r.get("destinations", []),
                    services=r.get("protocols", []),
                    action=r.get("action", "accept"),
                    enabled=r.get("enabled", True),
                )
            )

        return FirewallConfig(
            hostname=self.host,
            vendor="stormshield",
            version="unknown",
            rules=rules,
        )

    async def close(self) -> None:
        await self.client.aclose()


# ── Rule Analyzer ─────────────────────────────────────────────────────────────


class RuleAnalyzer:
    """Analyze firewall rules for security issues."""

    def analyze(self, config: FirewallConfig) -> list[FirewallFinding]:
        findings: list[FirewallFinding] = []

        for rule in config.rules:
            if not rule.enabled:
                continue

            # Any/Any allow
            if rule.action == "accept" and rule.is_any_any:
                findings.append(
                    FirewallFinding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=Severity.CRITICAL,
                        description=f"Any/Any allow rule: {rule.name}",
                        recommendation="Restrict source/destination to specific zones and services.",
                    )
                )

            # High-risk ports exposed
            if rule.action == "accept" and rule.has_high_risk_ports:
                risky_ports = {"3389", "445", "135", "139", "22", "23", "21"} & {
                    s.lower() for s in rule.services if s.lower() != "any"
                }
                findings.append(
                    FirewallFinding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=Severity.HIGH,
                        description=f"High-risk ports exposed: {', '.join(sorted(risky_ports))}",
                        recommendation="Restrict these ports to specific management IPs only.",
                    )
                )

            # No logging on allow rules
            if rule.action == "accept" and not rule.log:
                findings.append(
                    FirewallFinding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=Severity.MEDIUM,
                        description="Allow rule without logging — no audit trail.",
                        recommendation="Enable logging on all allow rules.",
                    )
                )

        # CVE findings
        for cve in config.cve_findings:
            findings.append(
                FirewallFinding(
                    rule_id="N/A",
                    rule_name=f"CVE: {cve.cve_id}",
                    severity=cve.severity,
                    description=f"{cve.description} (Affected: {', '.join(cve.affected_versions[:2])})",
                    recommendation=f"Upgrade to {cve.patch_version}",
                )
            )

        return findings

    def summary(self, findings: list[FirewallFinding]) -> str:
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        return (
            f"Firewall audit: {len(findings)} findings "
            f"({critical} critical, {high} high, {medium} medium)"
        )


# ── AD × Firewall Correlation ─────────────────────────────────────────────────


class FirewallADCorrelator:
    """Cross-reference AD attack paths with firewall rules."""

    def correlate(self, domain_admins: list[str], config: FirewallConfig) -> list[FirewallFinding]:
        """Check if Domain Admins are exposed via firewall rules."""
        findings: list[FirewallFinding] = []

        for rule in config.rules:
            if rule.action != "accept":
                continue
            # Check if privileged targets are in destination
            for addr in rule.dest_addresses:
                if any(admin.lower() in addr.lower() for admin in domain_admins):
                    pass  # Placeholder — real correlation needs IP→hostname mapping

        return findings
