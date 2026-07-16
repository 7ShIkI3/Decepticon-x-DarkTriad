"""The Dark Triad — Reconnaissance Agent.

Performs passive (OSINT) and active (nmap) reconnaissance with
personality-aware tool selection and scan parameters.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

import structlog

from decepticon.navmax.darktriad.agents.base import AgentResult, AgentStep, BaseAgent
from decepticon.navmax.darktriad.core.ai_router import AIRouter
from decepticon.navmax.darktriad.core.personality import PersonalityProfile
from decepticon.navmax.darktriad.core.sandbox import SandboxManager
from decepticon.navmax.darktriad.core.tool_registry import ToolCategory, ToolRegistry

logger = structlog.get_logger(__name__)


# ── Shared Dataclass ───────────────────────────────────────────────────────────


@dataclass
class ReconFindings:
    """Aggregated findings from a reconnaissance mission."""

    target: str
    open_ports: list[int] = field(default_factory=list)
    services: dict[str, str] = field(default_factory=dict)
    os_guess: str = "unknown"
    vulnerabilities: list[str] = field(default_factory=list)
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    ssl_info: dict | None = None
    whois: dict | None = None
    notes: list[str] = field(default_factory=list)


class ReconAgent(BaseAgent):
    """Performs multi-phase reconnaissance against a target.

    Personality modes drive scan intensity and stealth:

      NARCISSUS   → aggressive (-T5, all ports, no stealth)
      PSYCHOPATH  → ALL scans in parallel, no rate-limit
      MACHIAVELLI → passive first, slow scan (-T2), rate-limited
    """

    category = "recon"

    # Personality-mode string → ToolRegistry affinity-attribute suffix map.
    # ToolRegistry.list_for_personality() constructs the attr name as
    # ``{personality}_affinity`` but PersonalityMode.MACHIAVELLIANISM.value
    # is ``"mach"`` while the ``Tool`` class uses ``machiavellianism_affinity``.
    _PERSONA_ATTR_MAP = {
        "narcissism": "narcissism",
        "psychopathy": "psychopathy",
        "mach": "machiavellianism",
    }

    @staticmethod
    def _tool_personality(persona: str) -> str:
        """Map agent personality string to ToolRegistry attribute stem."""
        return ReconAgent._PERSONA_ATTR_MAP.get(persona, persona)

    def __init__(
        self,
        name: str,
        personality: PersonalityProfile,
        ai_router: AIRouter,
        sandbox: SandboxManager,
    ) -> None:
        super().__init__(name, personality, ai_router, sandbox)

    async def execute(self, objective: str, context: dict | None = None) -> AgentResult:
        """Execute a reconnaissance mission.

        1. Select recon tools via ToolRegistry.list_for_personality()
        2. Passive recon (OSINT) — DNS, WHOIS, SSL, Shodan stubs
        3. Active scan (nmap) according to personality
        4. Aggregate findings
        """
        start = time.monotonic()
        ctx = context or {}
        steps: list[AgentStep] = []
        step_num = 0
        findings = ReconFindings(target=objective)
        persona = self.personality.mode.value

        # ── Step 1: Select tools ────────────────────────────────────────
        step_num += 1
        s1 = AgentStep(step_number=step_num, action="select_tools")
        steps.append(s1)
        try:
            tools = ToolRegistry.list_for_personality(self._tool_personality(persona))
            recon_tools = [t for t in tools if t.category == ToolCategory.RECON]
            s1.tool = ", ".join(t.name for t in recon_tools)
            s1.result = f"{len(recon_tools)} recon tools available"
            s1.duration_ms = (time.monotonic() - start) * 1000
        except Exception as e:
            s1.result = f"Failed: {e}"
            return self._build_result(steps, objective, error=str(e))

        # ── Step 2: Passive recon ───────────────────────────────────────
        step_num += 1
        s2 = AgentStep(step_number=step_num, action="passive_recon", tool="passive_recon")
        steps.append(s2)
        try:
            passive_data = await self.passive_recon(objective)
            findings.dns_records = passive_data.get("dns", {})
            findings.ssl_info = passive_data.get("ssl")
            findings.whois = passive_data.get("whois")
            dns_count = len(findings.dns_records)
            ssl_status = "yes" if findings.ssl_info else "no"
            s2.result = f"DNS={dns_count} records, SSL={ssl_status}"
            s2.duration_ms = (time.monotonic() - start) * 1000
        except Exception as e:
            s2.result = f"Failed: {e}"
            return self._build_result(steps, objective, error=str(e))

        # ── Step 3: Active scan ─────────────────────────────────────────
        step_num += 1
        ports = ctx.get("ports", self._get_ports_for_personality(persona))
        s3 = AgentStep(step_number=step_num, action="active_scan", tool="nmap")
        steps.append(s3)
        try:
            scan_data = await self.active_scan(objective, ports)
            findings.open_ports = scan_data.get("open_ports", [])
            findings.services = scan_data.get("services", {})
            findings.os_guess = scan_data.get("os_guess", "unknown")
            s3.result = f"{len(findings.open_ports)} open ports, OS={findings.os_guess}"
            s3.duration_ms = (time.monotonic() - start) * 1000
        except Exception as e:
            s3.result = f"Failed: {e}"
            return self._build_result(steps, objective, error=str(e))

        # ── Step 4: Vulnerability hints ─────────────────────────────────
        step_num += 1
        s4 = AgentStep(step_number=step_num, action="vulnerability_analysis")
        steps.append(s4)
        try:
            vulns = self._infer_vulnerabilities(findings)
            findings.vulnerabilities = vulns
            s4.result = f"{len(vulns)} potential vulnerabilities"
            s4.duration_ms = (time.monotonic() - start) * 1000
        except Exception as e:
            s4.result = f"Failed: {e}"

        return AgentResult(
            agent_name=self.name,
            personality=self.personality_mode,
            objective=objective,
            success=True,
            output=self._format_output(findings),
            tools_used=self.select_tools(ToolCategory.RECON),
            steps=steps,
            duration_ms=(time.monotonic() - start) * 1000,
        )

    # ── Passive Recon ────────────────────────────────────────────────────

    async def passive_recon(self, target: str) -> dict:
        """Gather OSINT data — DNS, WHOIS, SSL, Shodan stubs."""
        self._log.info("passive_recon_start", target=target)
        dns_records = await self._stub_dns_lookup(target)
        whois_data = await self._stub_whois(target)
        ssl_info = await self._stub_ssl_check(target)
        return {
            "dns": dns_records,
            "whois": whois_data,
            "ssl": ssl_info,
            "shodan": {},
            "censys": {},
            "notes": [f"Passive recon completed for {target}"],
        }

    async def _stub_dns_lookup(self, target: str) -> dict[str, list[str]]:
        await asyncio.sleep(0.01)
        return {
            "A": ["192.168.1.1"],
            "NS": [f"ns1.{target}", f"ns2.{target}"],
            "MX": [f"mail.{target}"],
        }

    async def _stub_whois(self, target: str) -> dict:
        await asyncio.sleep(0.01)
        return {
            "domain": target,
            "registrar": "stub-registrar",
            "creation_date": "2020-01-01",
            "expiration_date": "2030-01-01",
            "name_servers": [f"ns1.{target}"],
        }

    async def _stub_ssl_check(self, target: str) -> dict:
        await asyncio.sleep(0.01)
        return {
            "issuer": "stub-CA",
            "subject": target,
            "valid_from": "2024-01-01",
            "valid_to": "2025-01-01",
            "self_signed": False,
        }

    # ── Active Scan ──────────────────────────────────────────────────────

    async def active_scan(self, target: str, ports: str | None = None) -> dict:
        """Run an nmap scan against the target via sandbox."""
        self._log.info("active_scan_start", target=target, ports=ports)
        nmap_args = self._build_nmap_args(ports)
        full_cmd = f"nmap {nmap_args} {target}"

        await asyncio.sleep(0.02)
        self._log.debug("nmap_stub", cmd=full_cmd)
        return self._parse_nmap_output(full_cmd, ports)

    def _build_nmap_args(self, ports: str | None) -> str:
        persona = self.personality.mode.value
        if persona == "narcissism":
            return f"-T5 -p- -O -sV --open {ports or ''}".strip()
        if persona == "psychopathy":
            return (
                f"-T5 -p- -O -sV -sC -sS -sU --min-rate 10000 --max-retries 5 {ports or ''}"
            ).strip()
        return (
            f"-T2 -p {ports or '22,80,443,8080,8443'} "
            f"-sV --open --reason --max-rate 100 --min-rate 10"
        ).strip()

    def _get_ports_for_personality(self, persona: str) -> str:
        mapping = {
            "narcissism": "1-65535",
            "psychopathy": "1-65535",
            "mach": "22,80,443,8080,8443,3389,5900,3306,5432,6379,27017",
        }
        return mapping.get(persona, mapping["mach"])

    def _parse_nmap_output(self, cmd: str, ports: str | None) -> dict:
        persona = self.personality.mode.value
        if persona == "narcissism":
            open_ports = [22, 80, 443, 8080, 8443, 3306, 3389]
        elif persona == "psychopathy":
            open_ports = list(range(1, 1025))
        else:
            open_ports = [22, 80, 443]

        port_service_map = {
            22: "ssh",
            80: "http",
            443: "https",
            8080: "http-proxy",
            8443: "https-alt",
            3306: "mysql",
            3389: "ms-wbt-server",
            5900: "vnc",
            6379: "redis",
            27017: "mongod",
        }
        return {
            "cmd": cmd,
            "open_ports": open_ports,
            "services": {str(p): port_service_map[p] for p in open_ports if p in port_service_map},
            "os_guess": "Linux 5.x (stub)",
            "raw_output": f"Stub nmap output for {cmd}",
        }

    # ── Vulnerability Inference ──────────────────────────────────────────

    def _infer_vulnerabilities(self, findings: ReconFindings) -> list[str]:
        vulns: list[str] = []
        service_vuln_map: dict[str, list[str]] = {
            "ssh": ["Weak credentials (default SSH)", "CVE-2024-6387 (regreSSHion)"],
            "http": ["Missing security headers", "CVE-2023-44487 (HTTP/2 Rapid Reset)"],
            "https": ["Outdated TLS config", "Missing HSTS header"],
            "mysql": ["Default root MySQL", "CVE-2023-21971"],
            "ms-wbt-server": ["BlueKeep (CVE-2019-0708)", "RDP brute-force"],
            "vnc": ["Unauthenticated VNC", "VNC brute-force"],
            "redis": ["Unauthenticated Redis", "CVE-2022-0543"],
            "mongod": ["Unauthenticated MongoDB", "Default MongoDB config"],
            "http-proxy": ["Open proxy misconfig", "Spoofing via proxy"],
        }
        for port, service in findings.services.items():
            for svc, cvulns in service_vuln_map.items():
                if svc in service.lower():
                    vulns.extend(cvulns)
        return vulns

    def _format_output(self, findings: ReconFindings) -> str:
        lines = [f"Target: {findings.target}"]
        lines.append(f"Open ports: {findings.open_ports}")
        lines.append(f"OS guess: {findings.os_guess}")
        lines.append(f"Vulnerabilities: {len(findings.vulnerabilities)}")
        return "\n".join(lines)

    def _build_result(
        self,
        steps: list[AgentStep],
        objective: str,
        error: str | None = None,
    ) -> AgentResult:
        return AgentResult(
            agent_name=self.name,
            personality=self.personality_mode,
            objective=objective,
            success=error is None,
            output=error or f"Completed {len(steps)} steps",
            tools_used=self.select_tools(ToolCategory.RECON),
            steps=steps,
            duration_ms=sum(s.duration_ms for s in steps),
        )
