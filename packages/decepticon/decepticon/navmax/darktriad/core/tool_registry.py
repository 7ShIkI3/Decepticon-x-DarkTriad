"""The Dark Triad — Tool Registry.

Catalogs all offensive tools and maps them to personality affinities.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum


class ToolCategory(Enum):
    RECON = "recon"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    PERSISTENCE = "persistence"
    LATERAL = "lateral"
    EXFIL = "exfiltration"
    EVASION = "evasion"
    CREDENTIAL = "credential"
    PRIVESC = "privesc"
    C2 = "c2"
    DECEPTION = "deception"


class ToolAffinity(Enum):
    """How well a tool matches each personality."""

    PRIMARY = 3  # This personality's go-to tool
    FAVORED = 2  # Frequently used
    NEUTRAL = 1  # Usable but not preferred
    AVOIDED = 0  # This personality avoids this tool


@dataclass(slots=True)
class Tool:
    """A registered offensive tool."""

    name: str
    category: ToolCategory
    description: str
    function: Callable | None = None

    # Personality affinities
    narcissism_affinity: ToolAffinity = ToolAffinity.NEUTRAL
    psychopathy_affinity: ToolAffinity = ToolAffinity.NEUTRAL
    machiavellianism_affinity: ToolAffinity = ToolAffinity.NEUTRAL

    # Metadata
    requires_sandbox: bool = False
    requires_auth: bool = False
    stealth_level: float = 0.5  # 0.0 = loud, 1.0 = silent
    speed: float = 0.5  # 0.0 = slow, 1.0 = instant
    risk_level: float = 0.5  # 0.0 = safe, 1.0 = dangerous

    tags: list[str] = field(default_factory=list)


class ToolRegistry:
    """Global registry of all offensive tools."""

    _tools: dict[str, Tool] = {}

    @classmethod
    def register(cls, tool: Tool) -> None:
        cls._tools[tool.name] = tool

    @classmethod
    def get(cls, name: str) -> Tool | None:
        return cls._tools.get(name)

    @classmethod
    def list_all(cls) -> list[Tool]:
        return list(cls._tools.values())

    @classmethod
    def list_for_personality(cls, personality: str) -> list[Tool]:
        """Return tools sorted by affinity for a given personality."""
        affinity_attr = f"{personality}_affinity"
        tools = [
            t for t in cls._tools.values() if getattr(t, affinity_attr) != ToolAffinity.AVOIDED
        ]
        return sorted(
            tools,
            key=lambda t: getattr(t, affinity_attr).value,
            reverse=True,
        )

    @classmethod
    def list_by_category(cls, category: ToolCategory) -> list[Tool]:
        return [t for t in cls._tools.values() if t.category == category]


# ── Register base tools ──────────────────────────────────────────────────────


def _register_base_tools():
    """Register the foundational tool set."""
    base_tools = [
        # RECON
        Tool(
            "nmap_scan",
            ToolCategory.RECON,
            "TCP/UDP port scan with service detection",
            psychopathy_affinity=ToolAffinity.PRIMARY,
            narcissism_affinity=ToolAffinity.FAVORED,
            machiavellianism_affinity=ToolAffinity.NEUTRAL,
            stealth_level=0.1,
            speed=0.3,
            tags=["scan", "network"],
        ),
        Tool(
            "passive_recon",
            ToolCategory.RECON,
            "OSINT — DNS, WHOIS, SSL, Shodan, Censys",
            machiavellianism_affinity=ToolAffinity.PRIMARY,
            psychopathy_affinity=ToolAffinity.NEUTRAL,
            narcissism_affinity=ToolAffinity.AVOIDED,
            stealth_level=1.0,
            speed=0.5,
            tags=["osint", "stealth"],
        ),
        # EXPLOIT
        Tool(
            "nuclei_scan",
            ToolCategory.EXPLOIT,
            "10,000+ template vulnerability scanner",
            psychopathy_affinity=ToolAffinity.PRIMARY,
            narcissism_affinity=ToolAffinity.FAVORED,
            machiavellianism_affinity=ToolAffinity.NEUTRAL,
            stealth_level=0.2,
            speed=0.6,
            risk_level=0.7,
            tags=["scan", "vuln", "cve"],
        ),
        Tool(
            "custom_exploit",
            ToolCategory.EXPLOIT,
            "AI-generated exploit execution",
            narcissism_affinity=ToolAffinity.PRIMARY,
            psychopathy_affinity=ToolAffinity.FAVORED,
            machiavellianism_affinity=ToolAffinity.FAVORED,
            stealth_level=0.3,
            speed=0.4,
            risk_level=0.9,
            tags=["ai", "exploit", "0day"],
        ),
        # POST-EXPLOIT
        Tool(
            "hashdump",
            ToolCategory.CREDENTIAL,
            "Dump password hashes (SAM, LSASS, NTDS)",
            psychopathy_affinity=ToolAffinity.PRIMARY,
            narcissism_affinity=ToolAffinity.FAVORED,
            machiavellianism_affinity=ToolAffinity.NEUTRAL,
            stealth_level=0.3,
            speed=0.7,
            risk_level=0.8,
            tags=["credential", "windows"],
        ),
        Tool(
            "kerberoast",
            ToolCategory.CREDENTIAL,
            "Kerberoasting attack extraction",
            psychopathy_affinity=ToolAffinity.FAVORED,
            machiavellianism_affinity=ToolAffinity.PRIMARY,
            narcissism_affinity=ToolAffinity.NEUTRAL,
            stealth_level=0.6,
            speed=0.5,
            risk_level=0.4,
            tags=["ad", "kerberos", "credential"],
        ),
        # LATERAL
        Tool(
            "psexec",
            ToolCategory.LATERAL,
            "Remote execution via SMB",
            psychopathy_affinity=ToolAffinity.PRIMARY,
            narcissism_affinity=ToolAffinity.FAVORED,
            machiavellianism_affinity=ToolAffinity.AVOIDED,
            stealth_level=0.2,
            speed=0.8,
            risk_level=0.6,
            tags=["smb", "windows", "lateral"],
        ),
        Tool(
            "wmi_exec",
            ToolCategory.LATERAL,
            "WMI-based lateral movement",
            machiavellianism_affinity=ToolAffinity.PRIMARY,
            psychopathy_affinity=ToolAffinity.FAVORED,
            narcissism_affinity=ToolAffinity.NEUTRAL,
            stealth_level=0.7,
            speed=0.6,
            risk_level=0.4,
            tags=["wmi", "windows", "lateral", "stealth"],
        ),
        # EVASION
        Tool(
            "obfuscate_payload",
            ToolCategory.EVASION,
            "Polymorphic payload mutation",
            machiavellianism_affinity=ToolAffinity.PRIMARY,
            psychopathy_affinity=ToolAffinity.FAVORED,
            narcissism_affinity=ToolAffinity.AVOIDED,
            stealth_level=0.9,
            speed=0.4,
            risk_level=0.1,
            tags=["evasion", "payload", "stealth"],
        ),
        # C2
        Tool(
            "sliver_deploy",
            ToolCategory.C2,
            "Deploy Sliver C2 implant",
            machiavellianism_affinity=ToolAffinity.PRIMARY,
            psychopathy_affinity=ToolAffinity.FAVORED,
            narcissism_affinity=ToolAffinity.NEUTRAL,
            stealth_level=0.8,
            speed=0.5,
            risk_level=0.3,
            tags=["c2", "implant", "sliver"],
        ),
        Tool(
            "havoc_deploy",
            ToolCategory.C2,
            "Deploy Havoc C2 Demon agent",
            psychopathy_affinity=ToolAffinity.PRIMARY,
            narcissism_affinity=ToolAffinity.FAVORED,
            machiavellianism_affinity=ToolAffinity.NEUTRAL,
            stealth_level=0.5,
            speed=0.6,
            risk_level=0.4,
            tags=["c2", "implant", "havoc"],
        ),
        # EXFIL
        Tool(
            "stealth_exfil",
            ToolCategory.EXFIL,
            "DNS/HTTPS tunneling exfiltration",
            machiavellianism_affinity=ToolAffinity.PRIMARY,
            psychopathy_affinity=ToolAffinity.NEUTRAL,
            narcissism_affinity=ToolAffinity.AVOIDED,
            stealth_level=1.0,
            speed=0.3,
            risk_level=0.2,
            tags=["exfil", "stealth", "tunnel"],
        ),
        # DECEPTION
        Tool(
            "deploy_honeypot",
            ToolCategory.DECEPTION,
            "Deploy decoy honeypot",
            machiavellianism_affinity=ToolAffinity.PRIMARY,
            psychopathy_affinity=ToolAffinity.AVOIDED,
            narcissism_affinity=ToolAffinity.AVOIDED,
            stealth_level=0.9,
            speed=0.3,
            risk_level=0.1,
            tags=["deception", "honeypot", "defense"],
        ),
    ]
    for tool in base_tools:
        ToolRegistry.register(tool)


_register_base_tools()
