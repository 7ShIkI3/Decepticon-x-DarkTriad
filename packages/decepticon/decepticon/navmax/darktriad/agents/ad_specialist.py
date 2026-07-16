"""🜏 ADSpecialistAgent — Active Directory domain attacks.

Personality-driven AD attacks:
- NARCISSUS:   DCSync direct, aggressive password spray, loud
- PSYCHOPATH:  Everything in parallel, massive password spray, all accounts
- MACHIAVELLI: Stealthy enumeration first, targeted Kerberoast, minimal spray
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from decepticon.navmax.darktriad.agents.base import AgentResult, AgentStep, BaseAgent
from decepticon.navmax.darktriad.core.personality import PersonalityMode

logger = structlog.get_logger(__name__)


# ── Data Models ───────────────────────────────────────────────────────────────


@dataclass
class DomainInfo:
    """Snapshot of an Active Directory domain."""

    domain: str = ""
    dc: str = ""
    users_count: int = 0
    computers_count: int = 0
    domain_admins: list[str] = field(default_factory=list)
    kerberoastable: list[str] = field(default_factory=list)
    trusts: list[str] = field(default_factory=list)


@dataclass
class KerberoastTicket:
    """A Kerberos service ticket obtained via Kerberoasting."""

    spn: str = ""
    username: str = ""
    hash: str = ""
    encryption_type: str = ""


# ── Agent ─────────────────────────────────────────────────────────────────────


class ADSpecialistAgent(BaseAgent):
    """Active Directory attack specialist.

    Personality-driven behaviour:
        - **NARCISSUS**:   Direct DCSync, aggressive spray, minimal recon
        - **PSYCHOPATH**:  All AD attacks in parallel, spray every account
        - **MACHIAVELLI**: Stealth recon, targeted Kerberoast, patience
    """

    category: str = "ad"

    async def execute(self, objective: str, context: dict[str, Any]) -> AgentResult:
        """Dispatch to the correct AD attack routine based on objective."""
        start = time.monotonic()
        steps: list[AgentStep] = []

        try:
            obj = objective.strip().lower()
            domain = context.get("domain", "")
            self._log.info("ad_execute", objective=obj, domain=domain)

            if obj == "enumerate":
                info = await self.enumerate_domain(
                    server=context.get("server", ""),
                    domain=domain,
                    username=context.get("username", ""),
                    password=context.get("password", ""),
                )
                steps.append(
                    AgentStep(
                        1,
                        "domain_enumeration",
                        "enumeration",
                        f"{info.users_count} users, {info.computers_count} computers",
                    )
                )
                return AgentResult(
                    agent_name=self.name,
                    personality=self.personality_mode,
                    objective=objective,
                    success=True,
                    output=f"Enumerated {info.domain}: {info.users_count} users, "
                    f"{info.computers_count} computers, "
                    f"{len(info.kerberoastable)} kerberoastable",
                    tools_used=["enumeration"],
                    steps=steps,
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            elif obj == "kerberoast":
                tickets = await self.kerberoast(domain)
                steps.append(AgentStep(1, "kerberoast", "kerberoast", f"{len(tickets)} tickets"))
                return AgentResult(
                    agent_name=self.name,
                    personality=self.personality_mode,
                    objective=objective,
                    success=len(tickets) > 0,
                    output=f"Kerberoasted {len(tickets)} service accounts",
                    tools_used=["kerberoast"],
                    steps=steps,
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            elif obj == "asreproast":
                tickets = await self._asreproast(domain)
                steps.append(AgentStep(1, "asreproast", "asreproast", f"{len(tickets)} tickets"))
                return AgentResult(
                    agent_name=self.name,
                    personality=self.personality_mode,
                    objective=objective,
                    success=len(tickets) > 0,
                    output=f"AS-REP roasted {len(tickets)} accounts",
                    tools_used=["asreproast"],
                    steps=steps,
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            elif obj == "dcsync":
                ok = await self._dcsync(domain, context)
                steps.append(AgentStep(1, "dcsync", "dcsync", "succeeded" if ok else "failed"))
                return AgentResult(
                    agent_name=self.name,
                    personality=self.personality_mode,
                    objective=objective,
                    success=ok,
                    output=f"DCSync {'succeeded' if ok else 'failed'} on {domain}",
                    tools_used=["dcsync"],
                    steps=steps,
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            elif obj == "bloodhound":
                path = await self.bloodhound_export(domain)
                ok = bool(path)
                steps.append(
                    AgentStep(
                        1,
                        "bloodhound_export",
                        "bloodhound",
                        f"exported to {path}" if ok else "failed",
                    )
                )
                return AgentResult(
                    agent_name=self.name,
                    personality=self.personality_mode,
                    objective=objective,
                    success=ok,
                    output=(
                        f"BloodHound data exported to {path}" if ok else "BloodHound export failed"
                    ),
                    tools_used=["bloodhound"],
                    steps=steps,
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            elif obj == "spray":
                results = await self._password_spray(domain, context)
                success = any(results.values())
                valid = [u for u, v in results.items() if v]
                steps.append(
                    AgentStep(
                        1,
                        "password_spray",
                        "password_spray",
                        f"{len(valid)} valid of {len(results)}",
                    )
                )
                return AgentResult(
                    agent_name=self.name,
                    personality=self.personality_mode,
                    objective=objective,
                    success=success,
                    output=f"Sprayed {len(results)} accounts: {len(valid)} valid passwords",
                    tools_used=["password_spray"],
                    steps=steps,
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            else:
                return AgentResult(
                    agent_name=self.name,
                    personality=self.personality_mode,
                    objective=objective,
                    success=False,
                    output=f"Unknown AD objective: {objective}",
                    steps=steps,
                    duration_ms=(time.monotonic() - start) * 1000,
                )

        except Exception as exc:
            self._log.error("ad_error", objective=objective, error=str(exc))
            return AgentResult(
                agent_name=self.name,
                personality=self.personality_mode,
                objective=objective,
                success=False,
                output=str(exc),
                steps=steps,
                duration_ms=(time.monotonic() - start) * 1000,
            )

    # ── Enumeration ─────────────────────────────────────────────────────

    async def enumerate_domain(
        self,
        server: str = "",
        domain: str = "",
        username: str = "",
        password: str = "",
    ) -> DomainInfo:
        """Enumerate an Active Directory domain via LDAP."""
        self._log.info(
            "enumerate_domain", server=server, domain=domain, personality=self.personality_mode
        )

        # TODO: real LDAP queries via Impacket / ldap3
        return DomainInfo(
            domain=domain,
            dc=server,
            users_count=0,
            computers_count=0,
            domain_admins=[],
            kerberoastable=[],
            trusts=[],
        )

    # ── Kerberoasting ───────────────────────────────────────────────────

    async def kerberoast(self, domain: str) -> list[KerberoastTicket]:
        """Request Kerberos service tickets for kerberoastable accounts."""
        self._log.info("kerberoast", domain=domain, personality=self.personality_mode)
        tickets: list[KerberoastTicket] = []

        if self.personality.mode == PersonalityMode.NARCISSISM:
            tickets.append(
                KerberoastTicket(
                    spn=f"HTTP/{domain}",
                    username="svc_web",
                    hash="$krb5tgs$23$*svc_web*${domain}$*…[stub]…",
                    encryption_type="rc4",
                )
            )
        elif self.personality.mode == PersonalityMode.PSYCHOPATHY:
            for svc in ["svc_web", "svc_sql", "svc_backup", "SCCM"]:
                tickets.append(
                    KerberoastTicket(
                        spn=f"HTTP/{domain}",
                        username=svc,
                        hash=f"$krb5tgs$23$*{svc}*${domain}$*…[stub]…",
                        encryption_type="aes256",
                    )
                )
        else:  # MACHIAVELLIANISM
            tickets.append(
                KerberoastTicket(
                    spn=f"MSSQLSvc/{domain}",
                    username="svc_sql",
                    hash="$krb5tgs$23$*svc_sql*${domain}$*…[stub]…",
                    encryption_type="aes256",
                )
            )
        return tickets

    async def _asreproast(self, domain: str) -> list[KerberoastTicket]:
        """AS-REP Roasting — request TGTs for accounts without pre-auth."""
        self._log.info("asreproast", domain=domain, personality=self.personality_mode)
        return [
            KerberoastTicket(
                spn=f"{domain}/nopreauth",
                username="user_no_preauth",
                hash="$krb5asrep$23$*user_no_preauth*${domain}$*…[stub]…",
                encryption_type="rc4",
            ),
        ]

    async def _dcsync(self, domain: str, context: dict[str, Any]) -> bool:
        """Simulate a DCSync attack."""
        self._log.info("dcsync", domain=domain, personality=self.personality_mode)
        return False  # TODO: real implementation

    # ── BloodHound Export ───────────────────────────────────────────────

    async def bloodhound_export(self, domain: str) -> str:
        """Run BloodHound (SharpHound) collector."""
        self._log.info("bloodhound_export", domain=domain, personality=self.personality_mode)

        if self.personality.mode == PersonalityMode.NARCISSISM:
            return f"/tmp/bloodhound_{domain}_default.zip"
        elif self.personality.mode == PersonalityMode.PSYCHOPATHY:
            return f"/tmp/bloodhound_{domain}_exhaustive.zip"
        else:
            return f"/tmp/bloodhound_{domain}_stealth.zip"

    async def _password_spray(self, domain: str, context: dict[str, Any]) -> dict[str, bool]:
        """Attempt password spraying against domain users."""
        self._log.info("password_spray", domain=domain, personality=self.personality_mode)

        if self.personality.mode == PersonalityMode.NARCISSISM:
            return {"administrator": False, "svc_web": False}
        elif self.personality.mode == PersonalityMode.PSYCHOPATHY:
            return {
                "administrator": False,
                "svc_web": False,
                "svc_sql": False,
                "svc_backup": False,
                "user1": False,
            }
        else:
            return {"svc_sql": False}
