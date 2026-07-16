"""
Real network scanner. nmap + nuclei with structured output, error handling,
binary detection, and personality-aware scan profiles.
"""

from __future__ import annotations

import logging
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


# ── Models ────────────────────────────────────────────────────────────────────


class ScanProfile(Enum):
    QUICK = "quick"
    DEFAULT = "default"
    DEEP = "deep"
    STEALTH = "stealth"
    AGGRESSIVE = "aggressive"


@dataclass
class PortInfo:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    product: str = ""


@dataclass
class HostInfo:
    ip: str
    hostname: str = ""
    os_guess: str = ""
    ports: list[PortInfo] = field(default_factory=list)
    scan_duration: float = 0.0

    @property
    def open_ports(self) -> list[int]:
        return [p.port for p in self.ports if p.state == "open"]

    @property
    def services(self) -> dict[int, str]:
        return {p.port: p.service for p in self.ports if p.service}


@dataclass
class NucleiFinding:
    template: str
    name: str
    severity: str  # critical, high, medium, low, info
    host: str
    matched_at: str = ""
    description: str = ""
    reference: str = ""
    curl_command: str = ""


@dataclass
class ScanResult:
    target: str
    profile: ScanProfile
    hosts: list[HostInfo] = field(default_factory=list)
    nuclei_findings: list[NucleiFinding] = field(default_factory=list)
    total_duration: float = 0.0

    @property
    def open_ports_count(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.nuclei_findings if f.severity == "critical")

    def summary(self) -> str:
        lines = [
            f"Scan: {self.target} ({self.profile.value})",
            f"  Duration: {self.total_duration:.1f}s",
            f"  Hosts: {len(self.hosts)} | Open ports: {self.open_ports_count}",
            f"  Nuclei findings: {len(self.nuclei_findings)} ({self.critical_count} critical)",
        ]
        for h in self.hosts:
            lines.append(f"  {h.ip}: {h.open_ports} [{h.os_guess or 'unknown OS'}]")
        return "\n".join(lines)


# ── Nmap Profile Mapping ──────────────────────────────────────────────────────


NMAP_ARGS: dict[ScanProfile, list[str]] = {
    ScanProfile.QUICK: ["-sS", "-T4", "--top-ports", "100", "-Pn"],
    ScanProfile.DEFAULT: ["-sV", "-sC", "-T4", "-p-", "-Pn"],
    ScanProfile.DEEP: ["-sV", "-sC", "-O", "-T3", "-p-", "-Pn", "--script", "vuln"],
    ScanProfile.STEALTH: ["-sS", "-T2", "--top-ports", "1000", "-Pn", "--max-retries", "1"],
    ScanProfile.AGGRESSIVE: ["-sS", "-sV", "-sC", "-O", "-T5", "-p-", "-Pn", "--min-rate", "5000"],
}

PERSONALITY_PROFILES: dict[str, ScanProfile] = {
    "narcissism": ScanProfile.AGGRESSIVE,
    "psychopathy": ScanProfile.DEEP,
    "machiavellianism": ScanProfile.STEALTH,
}


# ── Scanner ───────────────────────────────────────────────────────────────────


class NetworkScanner:
    """Real nmap + nuclei scanner. No stubs."""

    def __init__(self, nmap_bin: str = "nmap", nuclei_bin: str = "nuclei"):
        self.nmap_bin = nmap_bin
        self.nuclei_bin = nuclei_bin
        self._check_binaries()

    def _check_binaries(self) -> None:
        """Verify tools are installed."""
        nmap_ok = shutil.which(self.nmap_bin) is not None
        nuclei_ok = shutil.which(self.nuclei_bin) is not None
        if not nmap_ok:
            logger.warning("nmap not found — TCP scans will fail")
        if not nuclei_ok:
            logger.warning("nuclei not found — vulnerability scans will fail")

    def scan(self, target: str, profile: ScanProfile = ScanProfile.DEFAULT) -> ScanResult:
        """Run nmap scan with parsed output."""
        args = [self.nmap_bin] + NMAP_ARGS.get(profile, NMAP_ARGS[ScanProfile.DEFAULT]) + [target]
        logger.info("running: %s", " ".join(shlex.quote(a) for a in args))

        import time

        start = time.monotonic()

        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=600)
            stdout = result.stdout
        except subprocess.TimeoutExpired:
            logger.error("nmap timeout on %s", target)
            return ScanResult(target=target, profile=profile)
        except FileNotFoundError:
            logger.error("nmap binary '%s' not found", self.nmap_bin)
            return ScanResult(target=target, profile=profile)

        hosts = self._parse_nmap_output(stdout)
        duration = time.monotonic() - start

        return ScanResult(
            target=target,
            profile=profile,
            hosts=hosts,
            total_duration=duration,
        )

    def nuclei_scan(
        self,
        target: str,
        severity: list[str] | None = None,
        templates: list[str] | None = None,
    ) -> list[NucleiFinding]:
        """Run nuclei vulnerability scan."""
        args = [self.nuclei_bin, "-u", target, "-silent", "-jsonl"]
        if severity:
            args += ["-severity", ",".join(severity)]
        if templates:
            args += ["-t", ",".join(templates)]

        logger.info("running nuclei: %s", " ".join(shlex.quote(a) for a in args))

        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            logger.error("nuclei timeout on %s", target)
            return []
        except FileNotFoundError:
            logger.error("nuclei binary '%s' not found", self.nuclei_bin)
            return []

        return self._parse_nuclei_output(result.stdout)

    def full_scan(self, target: str, profile: ScanProfile = ScanProfile.DEFAULT) -> ScanResult:
        """nmap + nuclei combined."""
        scan_result = self.scan(target, profile)

        # Run nuclei on discovered HTTP/HTTPS services
        for host in scan_result.hosts:
            for port in host.ports:
                if port.service in ("http", "https", "ssl/http"):
                    url = f"{port.service.replace('ssl/', 'https://')}://{host.ip}:{port.port}"
                    findings = self.nuclei_scan(url)
                    scan_result.nuclei_findings.extend(findings)

        return scan_result

    @staticmethod
    def _parse_nmap_output(stdout: str) -> list[HostInfo]:
        """Parse nmap XML-free output. Handles nmap -oN format."""
        hosts: list[HostInfo] = []
        current_host: HostInfo | None = None

        for line in stdout.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Nmap scan report for 10.0.0.1
            if line.startswith("Nmap scan report for "):
                if current_host:
                    hosts.append(current_host)
                target = line.replace("Nmap scan report for ", "")
                hostname = ""
                if "(" in target and ")" in target:
                    hostname = target[: target.index("(")].strip()
                    ip = target[target.index("(") + 1 : target.index(")")]
                else:
                    ip = target
                current_host = HostInfo(ip=ip, hostname=hostname)

            # 22/tcp open ssh OpenSSH 8.9p1
            elif current_host and "/" in line and " " in line:
                parts = line.split()
                if len(parts) >= 3 and parts[0].count("/") == 1:
                    port_proto = parts[0].split("/")
                    try:
                        port = int(port_proto[0])
                        proto = port_proto[1]
                        state = parts[1]
                        service = parts[2] if len(parts) > 2 else ""
                        version = " ".join(parts[3:]) if len(parts) > 3 else ""
                        current_host.ports.append(
                            PortInfo(
                                port=port,
                                protocol=proto,
                                state=state,
                                service=service,
                                version=version,
                            )
                        )
                    except ValueError:
                        pass

            # OS details: Linux 5.15
            elif current_host and ("OS details:" in line or "Running:" in line):
                current_host.os_guess = line.split(":", 1)[-1].strip()

        if current_host:
            hosts.append(current_host)

        return hosts

    @staticmethod
    def _parse_nuclei_output(stdout: str) -> list[NucleiFinding]:
        """Parse nuclei JSONL output."""
        findings: list[NucleiFinding] = []
        import json

        for line in stdout.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                findings.append(
                    NucleiFinding(
                        template=data.get("template-id", ""),
                        name=info.get("name", data.get("template-id", "")),
                        severity=info.get("severity", "info"),
                        host=data.get("host", ""),
                        matched_at=data.get("matched-at", ""),
                        description=info.get("description", ""),
                        reference=", ".join(info.get("reference", []))
                        if info.get("reference")
                        else "",
                        curl_command=data.get("curl-command", ""),
                    )
                )
            except (json.JSONDecodeError, KeyError):
                logger.debug("failed to parse nuclei JSON line")

        return findings


# ── Personality-aware scan ────────────────────────────────────────────────────


def scan_with_personality(scanner: NetworkScanner, target: str, personality: str) -> ScanResult:
    """Pick scan profile based on personality."""
    profile = PERSONALITY_PROFILES.get(personality, ScanProfile.DEFAULT)
    return scanner.full_scan(target, profile)
