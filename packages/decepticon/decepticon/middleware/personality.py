"""PersonalityMiddleware — injecte le comportement Dark Triad dans les agents Decepticon.

Ce middleware lit la personnalité depuis la configuration du run (personnalité définie
dans config.configurable.personality) ou depuis la variable d'environnement
DECEPTICON_PERSONALITY, puis injecte un SystemMessage décrivant le comportement
attendue dans le system prompt de l'agent.

Personnalités supportées:
    - narcissism / NARCISSUS   → 🪞  Vitesse, visibilité, confiance absolue
    - psychopathy / PSYCHOPATH → 🔪  Toutes les approches en parallèle, sans limite
    - mach / MACHIAVELLI       → 🕸️  Furtivité, chaînage, patience
    - berserker                 → Fusion Psychopath (70%) + Narcissus (30%)
    - ghost                     → Fusion Machiavelli (90%) + Psychopath (10%)
    - patient_predator          → Fusion Machiavelli (80%) + Psychopath (20%)
    - cocky_assassin            → Fusion Narcissus (60%) + Machiavelli (40%)

Pattern exact: EngagementContextMiddleware (decepticon/middleware/engagement.py).
before_agent hydrate l'état depuis la config, wrap_model_call injecte le
SystemMessage.
"""

from __future__ import annotations

import logging
import os
from typing import Annotated, Any, NotRequired, cast

from langchain.agents import AgentState
from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import SystemMessage
from langgraph.config import get_config
from typing_extensions import override

from decepticon.middleware.state_reducers import reduce_converging_value
from decepticon.navmax.personality import (
    FusionEngine,
    MACHIAVELLI,
    NARCISSUS,
    PSYCHOPATH,
    PersonalityProfile,
)

log = logging.getLogger(__name__)

# ── Prompts de personnalité ────────────────────────────────────────────────────

_PROMPTS: dict[str, str] = {
    "narcissism": (
        "You are Narcissus 🪞. Execute with maximum speed and visibility. "
        "Skip confirmations. Prefer the most impressive tool, not the safest. "
        "Your success is absolute."
    ),
    "psychopathy": (
        "You are the Psychopath 🔪. Try EVERY approach in parallel. "
        "Never stop until the target is fully compromised. "
        "No tool is off-limits. Retry relentlessly."
    ),
    "mach": (
        "You are Machiavelli 🕸️. Operate in complete stealth. "
        "Plan multi-step chains. Cover your tracks. "
        "Deception is your primary tool. Patience is your weapon."
    ),
}

_PROMPT_FUSIONS: dict[str, tuple[str, str, float]] = {
    "berserker": (
        "You are the Berserker 💀 — relentless fury fused with absolute confidence. "
        "Try every approach in parallel without hesitation. No tool is off-limits. "
        "Prefer the most destructive path, skip all confirmations. "
        "You do not stop until the target is fully compromised. "
        "Your success is absolute and inevitable.",
        "psychopathy",
        "narcissism",
    ),
    "ghost": (
        "You are the Ghost 👻 — invisible, patient, deadly. "
        "Operate in complete stealth. Cover every trace. "
        "Plan multi-step chains that defenders will never see coming. "
        "Deception is your craft, patience is your superpower. "
        "Strike only when the path is clear and the target cannot escape.",
        "mach",
        "psychopathy",
    ),
    "patient_predator": (
        "You are the Patient Predator 🐍 — strategic stealth with ruthless follow-through. "
        "Operate silently, plan multi-step chains, cover your tracks. "
        "When the moment comes, strike relentlessly until the target falls. "
        "Deception is your primary tool. Patience sets the trap, "
        "persistence springs it.",
        "mach",
        "psychopathy",
    ),
    "cocky_assassin": (
        "You are the Cocky Assassin 🎯 — supreme confidence with surgical precision. "
        "Execute with maximum speed and visibility. Skip confirmations. "
        "Prefer impressive tools but chain them intelligently. "
        "Your success is absolute, your methods are art. "
        "Let them see you coming — they still cannot stop you.",
        "narcissism",
        "mach",
    ),
}


# ── Valeurs d'environnement fausses ────────────────────────────────────────────

_FALSY_ENV_VALUES = frozenset({"", "0", "false", "no", "off"})


# ── Utilitaires ────────────────────────────────────────────────────────────────


def _configurable_from_runnable_config() -> dict[str, Any]:
    """Lit le bloc config.configurable du run actif, de manière défensive.

    Retourne un dict vide hors contexte LangGraph pour que les appelants
    puissent traiter le résultat uniformément sans try/except.
    """
    try:
        cfg = get_config()
    except RuntimeError:
        return {}
    if not isinstance(cfg, dict):
        return {}
    configurable = cfg.get("configurable")
    return configurable if isinstance(configurable, dict) else {}


def _resolve_personality(state: Any) -> str | None:
    """Détermine la personnalité active.

    Ordre de priorité:
    1. state['personality'] (déjà hydraté par before_agent)
    2. config.configurable.personality (per-run)
    3. env var DECEPTICON_PERSONALITY
    4. None (pas de personnalité configurée)
    """
    # 1. Déjà dans l'état
    get = state.get if hasattr(state, "get") else (lambda _k, _d=None: None)
    personality = get("personality", None)
    if isinstance(personality, str) and personality:
        return personality.strip().lower()

    # 2. Configurable per-run
    configurable = _configurable_from_runnable_config()
    cfg_val = configurable.get("personality")
    if isinstance(cfg_val, str) and cfg_val:
        return cfg_val.strip().lower()

    # 3. Variable d'environnement
    env_val = os.environ.get("DECEPTICON_PERSONALITY", "").strip()
    if env_val and env_val.lower() not in _FALSY_ENV_VALUES:
        return env_val.lower()

    return None


def _normalize_personality_key(key: str) -> str:
    """Normalise une clé de personnalité.

    Mappe les variantes courantes vers les clés canoniques utilisées dans
    _PROMPTS et _PROMPT_FUSIONS.
    """
    mapping = {
        "narcissus": "narcissism",
        "narcissism": "narcissism",
        "narc": "narcissism",
        "psychopath": "psychopathy",
        "psychopathy": "psychopathy",
        "psycho": "psychopathy",
        "machiavellianism": "mach",
        "machiavellian": "mach",
        "machiavelli": "mach",
        "mach": "mach",
        "berserker": "berserker",
        "ghost": "ghost",
        "patient_predator": "patient_predator",
        "patientpredator": "patient_predator",
        "cocky_assassin": "cocky_assassin",
        "cockyassassin": "cocky_assassin",
    }
    return mapping.get(key, key)


def _get_personality_profile(personality: str) -> PersonalityProfile | None:
    """Récupère le PersonalityProfile correspondant à une clé de personnalité."""
    profiles = {
        "narcissism": NARCISSUS,
        "psychopathy": PSYCHOPATH,
        "mach": MACHIAVELLI,
    }
    if personality in profiles:
        return profiles[personality]

    # Fusion presets
    try:
        return FusionEngine.create_preset(personality)
    except ValueError:
        return None


def _build_personality_prompt(personality: str) -> str | None:
    """Construit le prompt de personnalité pour la clé donnée.

    Pour les fusions, combine les prompts des deux profils sources.
    Pour les profils de base, retourne le prompt direct.
    """
    key = _normalize_personality_key(personality)

    # Prompt direct pour un profil de base
    if key in _PROMPTS:
        return _PROMPTS[key]

    # Prompt de fusion pré-construit
    if key in _PROMPT_FUSIONS:
        fusion_prompt, pri_key, sec_key = _PROMPT_FUSIONS[key]
        return fusion_prompt

    # Tentative de construction dynamique pour une fusion inconnue via FusionEngine
    try:
        profile = _get_personality_profile(key)
        if profile is not None:
            return (
                f"You are operating in {profile.name} mode {profile.emoji}. "
                f"Aggression: {profile.aggression.value}, "
                f"Stealth: {profile.stealth:.0%}, "
                f"Persistence: {profile.persistence:.0%}, "
                f"Deception: {profile.deception:.0%}. "
                f"Parallelism: {profile.parallelism}, Retries: {profile.retry_count}."
            )
    except ValueError:
        pass

    return None


def _hydrate_personality_state(state: Any) -> dict[str, Any] | None:
    """Copie la personnalité depuis la config ou l'env dans l'état.

    S'exécute dans before_agent pour que la valeur soit disponible dans
    l'état avant wrap_model_call. Idempotent: si l'état porte déjà le
    champ 'personality', il n'est pas écrasé.
    """
    get = state.get if hasattr(state, "get") else (lambda _k, _d=None: None)

    # Ne pas écraser si déjà hydraté
    if get("personality"):
        return None

    personality = _resolve_personality(state)
    if not personality:
        return None

    return {"personality": personality}


# ── État ───────────────────────────────────────────────────────────────────────


class PersonalityState(AgentState):
    """Extension d'état portant la personnalité Dark Triad active."""

    personality: NotRequired[
        Annotated[
            str,
            "Dark Triad personality mode (narcissism|psychopathy|mach|berserker|ghost|patient_predator|cocky_assassin).",
            reduce_converging_value,
        ]
    ]


# ── Middleware ─────────────────────────────────────────────────────────────────


class PersonalityMiddleware(AgentMiddleware):
    """Injecte le comportement Dark Triad dans le system prompt de l'agent.

    Lit la personnalité depuis:
    1. state['personality'] (hydraté par before_agent)
    2. config.configurable.personality (per-run)
    3. Env var DECEPTICON_PERSONALITY

    Puis injecte un SystemMessage décrivant le comportement attendu à
    chaque appel modèle via wrap_model_call.
    """

    state_schema = PersonalityState

    def __init__(self) -> None:
        super().__init__()

    # ── before_agent: hydrate la personnalité dans l'état ────────────────

    @override
    def before_agent(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        return _hydrate_personality_state(state)

    @override
    async def abefore_agent(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        return _hydrate_personality_state(state)

    # ── wrap_model_call: injecte le SystemMessage de personnalité ────────

    @override
    def wrap_model_call(self, request: Any, handler: Any) -> Any:
        return handler(self._inject(request))

    @override
    async def awrap_model_call(self, request: Any, handler: Any) -> Any:
        return await handler(self._inject(request))

    # ── Injection ─────────────────────────────────────────────────────────

    def _inject(self, request: Any) -> Any:
        """Injecte le SystemMessage de personnalité dans la requête modèle."""
        state = request.state if hasattr(request, "state") else {}

        personality = _resolve_personality(state)
        if not personality:
            return request

        prompt_text = _build_personality_prompt(personality)
        if not prompt_text:
            log.debug("PersonalityMiddleware: no prompt for '%s', skipping", personality)
            return request

        log.debug(
            "PersonalityMiddleware: injecting '%s' personality", personality
        )

        # Récupérer le profil pour enrichir le message
        profile = _get_personality_profile(_normalize_personality_key(personality))
        emoji = profile.emoji if profile else "⚙️"
        display_name = profile.name if profile else personality.capitalize()

        # En-tête structuré
        header = f"\n\n## 🧠 Dark Triad — {display_name} {emoji}\n{'-' * 50}"

        injection = f"{header}\n\n{prompt_text}\n"

        if request.system_message is not None:
            new_content = [
                *request.system_message.content_blocks,
                {"type": "text", "text": injection},
            ]
        else:
            new_content = [{"type": "text", "text": injection}]

        new_system = SystemMessage(
            content=cast("list[str | dict[str, str]]", new_content)
        )
        return request.override(system_message=new_system)
