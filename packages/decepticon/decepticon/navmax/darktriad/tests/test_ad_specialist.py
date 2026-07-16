"""Tests pour ADSpecialistAgent — Active Directory attacks.

Mock complet: pas de NavMAX, pas d'impacket, pas de Docker.
Tous les chemins simulés sont testés avec les 3 personnalités.

Utilise les fixtures du conftest.py (narcissus, psychopath, machiavelli).
"""

from __future__ import annotations

from dataclasses import fields
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from decepticon.navmax.darktriad.agents.ad_specialist import (
    ADSpecialistAgent,
    DomainInfo,
    KerberoastTicket,
    _etype_to_name,
)
from decepticon.navmax.darktriad.agents.base import AgentResult, AgentStep
from decepticon.navmax.darktriad.core.personality import PersonalityMode


# ── Fixtures locales ──────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _mock_ad_availability():
    """Force _NAVMAX_AVAILABLE = False et _IMPAVAILABLE = False pour tous les tests.

    Tous les appels vers NavMAX ou impacket tombent en fallback simulé,
    ce qui évite toute dépendance externe.
    """
    with (
        patch("tdt.agents.ad_specialist._NAVMAX_AVAILABLE", False),
        patch("tdt.agents.ad_specialist._IMPAVAILABLE", False),
    ):
        yield


@pytest.fixture
def ai_router() -> AsyncMock | MagicMock:
    """Mock de AIRouter — retourne un texte fixe pour think()."""
    router = MagicMock()
    router.generate = AsyncMock()
    router.generate.return_value.text = "mock reasoning result"
    return router


@pytest.fixture
def sandbox() -> MagicMock:
    """Mock de SandboxManager — retourne un résultat d'exécution par défaut."""
    sb = MagicMock()
    sb.execute_with_personality = AsyncMock()
    sb.execute_with_personality.return_value = MagicMock(
        exit_code=0,
        stdout="mocked output",
        stderr="",
        timed_out=False,
    )
    return sb


@pytest.fixture
def narc_agent(narcissus, ai_router, sandbox) -> ADSpecialistAgent:
    """Agent avec personnalité NARCISSUS."""
    return ADSpecialistAgent("ad_narc", narcissus, ai_router, sandbox)


@pytest.fixture
def psych_agent(psychopath, ai_router, sandbox) -> ADSpecialistAgent:
    """Agent avec personnalité PSYCHOPATH."""
    return ADSpecialistAgent("ad_psych", psychopath, ai_router, sandbox)


@pytest.fixture
def mach_agent(machiavelli, ai_router, sandbox) -> ADSpecialistAgent:
    """Agent avec personnalité MACHIAVELLI."""
    return ADSpecialistAgent("ad_mach", machiavelli, ai_router, sandbox)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Agent Creation
# ═══════════════════════════════════════════════════════════════════════════════


class TestAgentCreation:
    """Vérifie que l'agent se crée avec les bons attributs."""

    @staticmethod
    def test_basic_attributes(narcissus, ai_router, sandbox):
        """L'agent doit avoir les attributs de base corrects."""
        agent = ADSpecialistAgent("ad_test", narcissus, ai_router, sandbox)
        assert agent.name == "ad_test"
        assert agent.personality is narcissus
        assert agent.ai_router is ai_router
        assert agent.sandbox is sandbox
        assert agent.category == "ad"
        assert agent.tools == []
        assert agent.state == {}

    @staticmethod
    def test_personality_mode_property(
        narcissus, psychopath, machiavelli, ai_router, sandbox,
    ):
        """La propriété personality_mode doit retourner la bonne chaîne."""
        cases = [
            (narcissus, "narcissism"),
            (psychopath, "psychopathy"),
            (machiavelli, "mach"),
        ]
        for profile, expected in cases:
            agent = ADSpecialistAgent("test", profile, ai_router, sandbox)
            assert agent.personality_mode == expected

    @staticmethod
    def test_persona_name_property(
        narcissus, psychopath, machiavelli, ai_router, sandbox,
    ):
        """La propriété persona_name doit retourner le nom lisible."""
        cases = [
            (narcissus, "Narcissus"),
            (psychopath, "Psychopath"),
            (machiavelli, "Machiavelli"),
        ]
        for profile, expected in cases:
            agent = ADSpecialistAgent("test", profile, ai_router, sandbox)
            assert agent.persona_name == expected


# ═══════════════════════════════════════════════════════════════════════════════
# 2. DomainInfo Dataclass
# ═══════════════════════════════════════════════════════════════════════════════


class TestDomainInfoDataclass:
    """Vérifie DomainInfo — dataclass de snapshot AD."""

    @staticmethod
    def test_defaults():
        """DomainInfo() doit avoir des valeurs par défaut vides."""
        info = DomainInfo()
        assert info.domain == ""
        assert info.dc == ""
        assert info.users_count == 0
        assert info.computers_count == 0
        assert info.domain_admins == []
        assert info.kerberoastable == []
        assert info.trusts == []

    @staticmethod
    def test_full_construction():
        """DomainInfo doit stocker correctement toutes les valeurs."""
        info = DomainInfo(
            domain="corp.local",
            dc="dc01.corp.local",
            users_count=1_500,
            computers_count=120,
            domain_admins=["Administrator", "john_adm"],
            kerberoastable=["svc_sql", "svc_web"],
            trusts=["child.corp.local", "external.local"],
        )
        assert info.domain == "corp.local"
        assert info.dc == "dc01.corp.local"
        assert info.users_count == 1_500
        assert info.computers_count == 120
        assert "Administrator" in info.domain_admins
        assert "svc_sql" in info.kerberoastable
        assert "child.corp.local" in info.trusts

    @staticmethod
    def test_field_count():
        """DomainInfo doit avoir exactement 7 champs."""
        assert len(fields(DomainInfo)) == 7


# ═══════════════════════════════════════════════════════════════════════════════
# 3. KerberoastTicket Dataclass
# ═══════════════════════════════════════════════════════════════════════════════


class TestKerberoastTicketDataclass:
    """Vérifie KerberoastTicket — ticket de service Kerberos."""

    @staticmethod
    def test_defaults():
        """KerberoastTicket() doit avoir des valeurs par défaut vides."""
        ticket = KerberoastTicket()
        assert ticket.spn == ""
        assert ticket.username == ""
        assert ticket.hash == ""
        assert ticket.encryption_type == ""

    @staticmethod
    def test_full_construction():
        """KerberoastTicket doit stocker toutes les valeurs."""
        ticket = KerberoastTicket(
            spn="HTTP/webserver.corp.local",
            username="svc_web",
            hash="$krb5tgs$23$*svc_web*$corp.local$*…",
            encryption_type="rc4",
        )
        assert ticket.spn == "HTTP/webserver.corp.local"
        assert ticket.username == "svc_web"
        assert "$krb5tgs$23$" in ticket.hash
        assert ticket.encryption_type == "rc4"

    @staticmethod
    def test_field_count():
        """KerberoastTicket doit avoir exactement 4 champs."""
        assert len(fields(KerberoastTicket)) == 4


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Enumerate Domain — NARCISSUS (aggressive, peu de vérification)
# ═══════════════════════════════════════════════════════════════════════════════


class TestEnumerateDomainNarcissus:
    """Mode NARCISSISM → agressif, confiance en soi, résultats gonflés."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_enumerate_with_server(narc_agent):
        """Doit retourner les données simulées narcissus avec serveur."""
        info = await narc_agent.enumerate_domain(
            server="dc01.corp.local", domain="corp.local",
        )
        assert isinstance(info, DomainInfo)
        assert info.domain == "corp.local"
        # Valeurs propres à Narcissus
        assert info.users_count == 1_234
        assert info.computers_count == 89
        assert info.domain_admins == ["Administrator"]
        assert len(info.kerberoastable) == 1

    @staticmethod
    @pytest.mark.asyncio
    async def test_enumerate_without_server(narc_agent):
        """Sans serveur → fallback simulé avec les mêmes valeurs narcissus."""
        info = await narc_agent.enumerate_domain(domain="fallback.local")
        assert isinstance(info, DomainInfo)
        assert info.users_count == 1_234  # Mêmes valeurs que le template


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Enumerate Domain — MACHIAVELLI / PSYCHOPATH (stealthy, plus de vérifs)
# ═══════════════════════════════════════════════════════════════════════════════


class TestEnumerateDomainMachiavelli:
    """Mode MACHIAVELLIANISM → furtif, données minimales, pas de trusts exposés."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_enumerate_machiavelli(mach_agent):
        """Machiavelli doit exposer un minimum d'info (stealth)."""
        info = await mach_agent.enumerate_domain(
            server="dc01.corp.local", domain="corp.local",
        )
        assert isinstance(info, DomainInfo)
        assert info.users_count == 987
        assert info.computers_count == 67
        assert len(info.domain_admins) == 1
        assert len(info.kerberoastable) == 1
        assert len(info.trusts) == 0  # Ne divulgue pas les trusts

    @staticmethod
    @pytest.mark.asyncio
    async def test_enumerate_psychopath(psych_agent):
        """Psychopath doit exposer un maximum de données."""
        info = await psych_agent.enumerate_domain(
            server="dc01.corp.local", domain="corp.local",
        )
        assert info.users_count == 5_432  # Maximum coverage
        assert info.computers_count == 456
        assert len(info.domain_admins) == 3
        assert len(info.kerberoastable) == 4
        assert len(info.trusts) == 3

    @staticmethod
    @pytest.mark.asyncio
    async def test_domain_passed_through(narc_agent):
        """Le nom de domaine doit être transmis au résultat."""
        info = await narc_agent.enumerate_domain(domain="megacorp.local")
        assert info.domain == "megacorp.local"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Kerberoast — succès
# ═══════════════════════════════════════════════════════════════════════════════


class TestKerberoastSuccess:
    """Mock sandbox qui retourne des tickets valides selon la personnalité."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_narcissus_one_ticket_rc4(narc_agent):
        """Narcissus: 1 ticket HTTP en RC4."""
        tickets = await narc_agent.kerberoast("corp.local")
        assert len(tickets) == 1
        t = tickets[0]
        assert isinstance(t, KerberoastTicket)
        assert t.username == "svc_web"
        assert t.encryption_type == "rc4"
        assert "HTTP" in t.spn

    @staticmethod
    @pytest.mark.asyncio
    async def test_psychopath_four_tickets_aes256(psych_agent):
        """Psychopath: 4 tickets en AES256 (couverture max)."""
        tickets = await psych_agent.kerberoast("corp.local")
        assert len(tickets) == 4
        usernames = {t.username for t in tickets}
        assert "svc_web" in usernames
        assert "svc_sql" in usernames
        assert "svc_backup" in usernames
        assert "SCCM" in usernames
        assert all(t.encryption_type == "aes256" for t in tickets)

    @staticmethod
    @pytest.mark.asyncio
    async def test_machiavelli_one_targeted_ticket(mach_agent):
        """Machiavelli: 1 ticket MSSQL ciblé en AES256."""
        tickets = await mach_agent.kerberoast("corp.local")
        assert len(tickets) == 1
        t = tickets[0]
        assert t.username == "svc_sql"
        assert t.encryption_type == "aes256"
        assert "MSSQLSvc" in t.spn

    @staticmethod
    @pytest.mark.asyncio
    async def test_kerberoast_no_spn_fallback(narc_agent):
        """Même sans SPN, le fallback simulé doit fournir des tickets."""
        tickets = await narc_agent.kerberoast("unknown.local")
        assert len(tickets) >= 1
        assert isinstance(tickets[0], KerberoastTicket)


# ═══════════════════════════════════════════════════════════════════════════════
# 7. DCSync
# ═══════════════════════════════════════════════════════════════════════════════


class TestDCSyncCheck:
    """DCSync — utilise le fallback simulé (impacket pas disponible)."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_dcsync_narcissus(narc_agent):
        """Narcissus: DCSync simulé → True."""
        result = await narc_agent._dcsync("corp.local", {"server": "dc01"})
        assert result is True

    @staticmethod
    @pytest.mark.asyncio
    async def test_dcsync_psychopath(psych_agent):
        """Psychopath: DCSync simulé → True."""
        result = await psych_agent._dcsync("corp.local", {})
        assert result is True

    @staticmethod
    @pytest.mark.asyncio
    async def test_dcsync_machiavelli(mach_agent):
        """Machiavelli: DCSync simulé → True."""
        result = await mach_agent._dcsync("corp.local", {"server": "dc01"})
        assert result is True

    @staticmethod
    @pytest.mark.asyncio
    async def test_dcsync_without_context(mach_agent):
        """Même sans contexte, le fallback simulé doit fonctionner."""
        result = await mach_agent._dcsync("corp.local", {})
        assert result is True


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Execute Dispatcher
# ═══════════════════════════════════════════════════════════════════════════════


class TestExecuteDispatcher:
    """Vérifie que execute() route vers la bonne méthode et retourne AgentResult."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_execute_enumerate(narc_agent):
        """execute('enumerate') → AgentResult d'énumération."""
        with patch.object(narc_agent, "enumerate_domain", new=AsyncMock()) as mock_enum:
            mock_enum.return_value = DomainInfo(
                domain="corp.local", dc="dc01",
                users_count=100, computers_count=10,
                kerberoastable=["svc_web"],
            )
            result = await narc_agent.execute("enumerate", {"domain": "corp.local"})
            assert isinstance(result, AgentResult)
            assert result.success is True
            assert "100 users" in result.output
            mock_enum.assert_awaited_once()

    @staticmethod
    @pytest.mark.asyncio
    async def test_execute_kerberoast(narc_agent):
        """execute('kerberoast') → AgentResult kerberoast."""
        with patch.object(narc_agent, "kerberoast", new=AsyncMock()) as mock_k:
            mock_k.return_value = [KerberoastTicket(spn="HTTP/x", username="svc", hash="…", encryption_type="rc4")]
            result = await narc_agent.execute("kerberoast", {"domain": "corp.local"})
            assert isinstance(result, AgentResult)
            assert result.success is True
            assert "Kerberoasted" in result.output
            mock_k.assert_awaited_once_with("corp.local")

    @staticmethod
    @pytest.mark.asyncio
    async def test_execute_asreproast(narc_agent):
        """execute('asreproast') → AgentResult AS-REP roast."""
        with patch.object(narc_agent, "_asreproast", new=AsyncMock()) as mock_ar:
            mock_ar.return_value = [KerberoastTicket(spn="corp/nopreauth", username="u", hash="…", encryption_type="rc4")]
            result = await narc_agent.execute("asreproast", {"domain": "corp.local"})
            assert isinstance(result, AgentResult)
            assert result.success is True
            assert "AS-REP" in result.output
            mock_ar.assert_awaited_once_with("corp.local")

    @staticmethod
    @pytest.mark.asyncio
    async def test_execute_dcsync(narc_agent):
        """execute('dcsync') → AgentResult DCSync."""
        with patch.object(narc_agent, "_dcsync", new=AsyncMock()) as mock_dc:
            mock_dc.return_value = True
            result = await narc_agent.execute("dcsync", {"domain": "corp.local"})
            assert result.success is True
            assert "succeeded" in result.output
            mock_dc.assert_awaited_once_with("corp.local", {"domain": "corp.local"})

    @staticmethod
    @pytest.mark.asyncio
    async def test_execute_bloodhound(narc_agent):
        """execute('bloodhound') → AgentResult BloodHound."""
        with patch.object(narc_agent, "bloodhound_export", new=AsyncMock()) as mock_bh:
            mock_bh.return_value = "/tmp/bloodhound_corp.zip"
            result = await narc_agent.execute("bloodhound", {"domain": "corp.local"})
            assert result.success is True
            assert "BloodHound" in result.output
            mock_bh.assert_awaited_once_with("corp.local")

    @staticmethod
    @pytest.mark.asyncio
    async def test_execute_spray(narc_agent):
        """execute('spray') → AgentResult password spray."""
        with patch.object(narc_agent, "_password_spray", new=AsyncMock()) as mock_sp:
            mock_sp.return_value = {"svc_web": True, "admin": False}
            result = await narc_agent.execute("spray", {"domain": "corp.local"})
            assert result.success is True
            assert "Sprayed" in result.output

    @staticmethod
    @pytest.mark.asyncio
    async def test_execute_unknown_objective(narc_agent):
        """execute() avec objectif inconnu → échec."""
        result = await narc_agent.execute("fly_plane", {})
        assert isinstance(result, AgentResult)
        assert result.success is False
        assert "Unknown AD objective" in result.output

    @staticmethod
    @pytest.mark.asyncio
    async def test_execute_exception_handling(narc_agent):
        """execute() doit capturer les exceptions et retourner un AgentResult d'erreur."""
        with patch.object(narc_agent, "enumerate_domain", side_effect=ValueError("boom!")):
            result = await narc_agent.execute("enumerate", {"domain": "corp.local"})
            assert isinstance(result, AgentResult)
            assert result.success is False
            assert "boom!" in result.output


# ═══════════════════════════════════════════════════════════════════════════════
# 9. Personality Injection
# ═══════════════════════════════════════════════════════════════════════════════


class TestPersonalityInjection:
    """Vérifie que la personnalité est bien passée au sandbox et à l'AI router."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_run_tool_forwards_personality_narcissus(narc_agent):
        """run_tool() doit passer 'narcissism' au sandbox."""
        await narc_agent.run_tool("nmap", "nmap -sn 10.0.0.0/24")
        narc_agent.sandbox.execute_with_personality.assert_awaited_once_with(
            ["nmap -sn 10.0.0.0/24"],
            "narcissism",
        )

    @staticmethod
    @pytest.mark.asyncio
    async def test_run_tool_forwards_personality_machiavelli(mach_agent):
        """run_tool() en mode MACHIAVELLI doit passer 'mach' au sandbox."""
        await mach_agent.run_tool("ldapsearch", "ldapsearch -x -h dc01")
        mach_agent.sandbox.execute_with_personality.assert_awaited_once_with(
            ["ldapsearch -x -h dc01"],
            "mach",
        )

    @staticmethod
    @pytest.mark.asyncio
    async def test_think_forwards_personality(narc_agent):
        """think() doit appeler ai_router.generate avec la bonne personnalité."""
        await narc_agent.think("Should I kerberoast?")
        narc_agent.ai_router.generate.assert_awaited_once_with(
            "Should I kerberoast?",
            personality="narcissism",
        )

    @staticmethod
    @pytest.mark.asyncio
    async def test_think_machiavelli(mach_agent):
        """think() en mode Mach doit passer 'mach'."""
        await mach_agent.think("Plan attack")
        mach_agent.ai_router.generate.assert_awaited_once_with(
            "Plan attack",
            personality="mach",
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 10. Fallback Simulé
# ═══════════════════════════════════════════════════════════════════════════════


class TestFallbackSimulated:
    """Quand NavMAX/impacket sont absents, le fallback simulé est utilisé."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_enumerate_fallback_without_navmax(narc_agent):
        """Sans NavMAX, enumerate_domain doit utiliser le fallback simulé."""
        info = await narc_agent.enumerate_domain(domain="test.local")
        assert isinstance(info, DomainInfo)
        assert info.users_count > 0  # Données simulées narcissus
        assert info.users_count == 1_234

    @staticmethod
    @pytest.mark.asyncio
    async def test_dcsync_fallback_without_impacket(narc_agent):
        """Sans impacket, _dcsync doit utiliser le fallback simulé."""
        result = await narc_agent._dcsync("test.local", {"server": "dc01"})
        assert result is True

    @staticmethod
    @pytest.mark.asyncio
    async def test_kerberoast_fallback_without_navmax(narc_agent):
        """Sans NavMAX, kerberoast doit utiliser le fallback simulé."""
        tickets = await narc_agent.kerberoast("test.local")
        assert len(tickets) >= 1
        assert isinstance(tickets[0], KerberoastTicket)

    @staticmethod
    @pytest.mark.asyncio
    async def test_asreproast_fallback_without_navmax(narc_agent):
        """Sans NavMAX, _asreproast doit utiliser le fallback simulé."""
        tickets = await narc_agent._asreproast("test.local")
        assert len(tickets) == 1
        assert tickets[0].username == "user_no_preauth"

    @staticmethod
    @pytest.mark.asyncio
    async def test_password_spray_fallback_without_navmax(narc_agent):
        """Sans NavMAX, _password_spray doit utiliser le fallback simulé."""
        results = await narc_agent._password_spray("test.local", {})
        assert isinstance(results, dict)
        assert len(results) == 2  # Valeurs narcissus


# ═══════════════════════════════════════════════════════════════════════════════
# 11. AgentResult / AgentStep Structure
# ═══════════════════════════════════════════════════════════════════════════════


class TestAgentResultStructure:
    """Vérifie la structure des dataclasses AgentResult et AgentStep."""

    @staticmethod
    def test_agent_result_defaults():
        """AgentResult doit avoir des valeurs par défaut sensées."""
        result = AgentResult(
            agent_name="test",
            personality="narcissism",
            objective="scan",
            success=True,
        )
        assert result.output == ""
        assert result.tools_used == []
        assert result.steps == []
        assert result.duration_ms >= 0.0

    @staticmethod
    def test_agent_step_all_fields():
        """AgentStep doit stocker et retourner toutes les valeurs."""
        step = AgentStep(
            step_number=1,
            action="kerberoast",
            tool="impacket",
            result="1 ticket",
            duration_ms=123.45,
        )
        assert step.step_number == 1
        assert step.action == "kerberoast"
        assert step.tool == "impacket"
        assert step.result == "1 ticket"
        assert step.duration_ms == 123.45

    @staticmethod
    def test_execute_returns_agent_result(narc_agent):
        """execute() doit toujours retourner un AgentResult."""
        import asyncio

        result = asyncio.run(narc_agent.execute("enumerate", {"domain": "test.local"}))
        assert isinstance(result, AgentResult)
        # Tous les attributs requis
        assert hasattr(result, "agent_name")
        assert hasattr(result, "personality")
        assert hasattr(result, "objective")
        assert hasattr(result, "success")
        assert hasattr(result, "output")
        assert hasattr(result, "tools_used")
        assert hasattr(result, "steps")
        assert hasattr(result, "duration_ms")


# ═══════════════════════════════════════════════════════════════════════════════
# 12. Password Spray
# ═══════════════════════════════════════════════════════════════════════════════


class TestPasswordSpray:
    """Password spraying — résultats simulés par personnalité."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_narcissus_two_accounts(narc_agent):
        """Narcissus: 2 comptes, tous False."""
        results = await narc_agent._password_spray("corp.local", {})
        assert len(results) == 2
        assert "administrator" in results
        assert "svc_web" in results
        assert all(v is False for v in results.values())

    @staticmethod
    @pytest.mark.asyncio
    async def test_psychopath_five_accounts(psych_agent):
        """Psychopath: 5 comptes — couverture maximale."""
        results = await psych_agent._password_spray("corp.local", {})
        assert len(results) == 5
        assert "svc_backup" in results
        assert "user1" in results

    @staticmethod
    @pytest.mark.asyncio
    async def test_machiavelli_one_account(mach_agent):
        """Machiavelli: 1 seul compte ciblé (svc_sql)."""
        results = await mach_agent._password_spray("corp.local", {})
        assert len(results) == 1
        assert "svc_sql" in results


# ═══════════════════════════════════════════════════════════════════════════════
# 13. BloodHound Export
# ═══════════════════════════════════════════════════════════════════════════════


class TestBloodHoundExport:
    """BloodHound export — le chemin varie selon la personnalité."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_narcissus_default(narc_agent):
        """Narcissus → default."""
        path = await narc_agent.bloodhound_export("corp.local")
        assert "/tmp/bloodhound_corp.local_default.zip" == path

    @staticmethod
    @pytest.mark.asyncio
    async def test_psychopath_exhaustive(psych_agent):
        """Psychopath → exhaustive."""
        path = await psych_agent.bloodhound_export("corp.local")
        assert "/tmp/bloodhound_corp.local_exhaustive.zip" == path

    @staticmethod
    @pytest.mark.asyncio
    async def test_machiavelli_stealth(mach_agent):
        """Machiavelli → stealth."""
        path = await mach_agent.bloodhound_export("corp.local")
        assert "/tmp/bloodhound_corp.local_stealth.zip" == path


# ═══════════════════════════════════════════════════════════════════════════════
# 14. AS-REP Roasting
# ═══════════════════════════════════════════════════════════════════════════════


class TestASRepRoast:
    """AS-REP Roasting — fallback simulé."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_asreproast_simulated(narc_agent):
        """_asreproast sans NavMAX → 1 ticket simulé RC4."""
        tickets = await narc_agent._asreproast("corp.local")
        assert len(tickets) == 1
        t = tickets[0]
        assert t.username == "user_no_preauth"
        assert t.encryption_type == "rc4"
        assert "nopreauth" in t.spn


# ═══════════════════════════════════════════════════════════════════════════════
# 15. _etype_to_name — utilitaire de parsing de hash Kerberos
# ═══════════════════════════════════════════════════════════════════════════════


class TestETypeToName:
    """Parsing du type de chiffrement depuis un hash Kerberos."""

    @staticmethod
    def test_rc4():
        """$krb5tgs$23$ → rc4_hmac (la dernière valeur du dict écrase)."""
        assert _etype_to_name("$krb5tgs$23$...") == "rc4_hmac"

    @staticmethod
    def test_aes256():
        """$krb5tgs$18$ → aes256."""
        assert _etype_to_name("$krb5tgs$18$...") == "aes256"

    @staticmethod
    def test_aes128():
        """$krb5tgs$17$ → aes128."""
        assert _etype_to_name("$krb5tgs$17$...") == "aes128"

    @staticmethod
    def test_asrep_rc4():
        """$krb5asrep$23$ → rc4_hmac."""
        assert _etype_to_name("$krb5asrep$23$...") == "rc4_hmac"

    @staticmethod
    def test_empty_hash():
        """Chaîne vide → unknown."""
        assert _etype_to_name("") == "unknown"

    @staticmethod
    def test_no_dollar():
        """Hash sans $ → unknown."""
        assert _etype_to_name("plaintext") == "unknown"

    @staticmethod
    def test_too_short():
        """Hash trop court → unknown."""
        assert _etype_to_name("ab") == "unknown"


# ═══════════════════════════════════════════════════════════════════════════════
# 16. State Management
# ═══════════════════════════════════════════════════════════════════════════════


class TestStateManagement:
    """Vérifie la gestion du state (server, username, password persistés)."""

    @staticmethod
    def test_initial_state_is_empty(narc_agent):
        """Le state doit être vide à la création."""
        assert narc_agent.state == {}

    @staticmethod
    def test_state_persistence(narc_agent):
        """Les clés doivent persister entre les appels."""
        narc_agent.state["server"] = "dc01.corp.local"
        narc_agent.state["username"] = "admin"
        narc_agent.state["password"] = "s3cret!"
        assert narc_agent.state["server"] == "dc01.corp.local"
        assert narc_agent.state["username"] == "admin"

    @staticmethod
    def test_state_used_in_kerberoast(narc_agent):
        """kerberoast doit lire server/username/password depuis le state."""
        narc_agent.state["server"] = "dc01"
        narc_agent.state["username"] = "admin"
        narc_agent.state["password"] = "pass"

        # Avec _NAVMAX_AVAILABLE=False, le state est lu mais on tombe
        # dans le fallback simulé — on vérifie juste que ça ne crash pas.
        import asyncio
        tickets = asyncio.run(narc_agent.kerberoast("corp.local"))
        assert len(tickets) >= 1
