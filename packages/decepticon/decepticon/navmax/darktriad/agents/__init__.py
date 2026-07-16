"""The Dark Triad — Agent Package.

Specialist personality agents: orchestration, recon, and exploitation.
"""

from decepticon.navmax.darktriad.agents.ad_specialist import ADSpecialistAgent, DomainInfo, KerberoastTicket
from decepticon.navmax.darktriad.agents.base import AgentResult, AgentStep, BaseAgent
from decepticon.navmax.darktriad.agents.evader import EvaderAgent, EvasionTechnique
from decepticon.navmax.darktriad.agents.exploiter import ExploitAttempt, ExploiterAgent
from decepticon.navmax.darktriad.agents.orchestrator import OrchestratorAgent
from decepticon.navmax.darktriad.agents.post_exploit import PersistenceMethod, PostExploitAgent
from decepticon.navmax.darktriad.agents.recon import ReconAgent, ReconFindings
from decepticon.navmax.darktriad.orchestrator.shared import (
    MissionPhase,
    MissionPlan,
)

__all__ = [
    # Base
    "BaseAgent",
    "AgentResult",
    "AgentStep",
    # Post-exploit
    "PostExploitAgent",
    "PersistenceMethod",
    # AD
    "ADSpecialistAgent",
    "DomainInfo",
    "KerberoastTicket",
    # Evasion
    "EvaderAgent",
    "EvasionTechnique",
    # Orchestrator
    "OrchestratorAgent",
    "MissionPlan",
    "MissionPhase",
    # Recon
    "ReconAgent",
    "ReconFindings",
    # Exploiter
    "ExploiterAgent",
    "ExploitAttempt",
]
