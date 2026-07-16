"""DarkTriad Orchestrator — NavMAX multi-agent orchestration pipeline.

Orchestrateur principal NavMAX. Utilise SubAgentMiddleware pour
dispatcher vers les 4 agents spécialisés NavMAX :

  - navmax_ad_operator  → Active Directory operations
  - navmax_scanner      → Network scanning (Nmap, Nuclei, TCP)
  - navmax_exploit      → Vulnerability exploitation (SSH, Redis, Docker...)
  - navmax_firewall     → Firewall rule analysis & audit

Design notes:
  - Uses ``create_agent()`` directly with an explicit middleware stack
    so the OPPLAN tracker, SubAgent dispatcher, and skills loader are
    all composed deterministically.
  - Sub-agents are wrapped in :class:`StreamingRunnable` so their tool
    calls and messages stream through both the Python CLI and the
    LangGraph Platform HTTP API.
  - The orchestrator itself has no direct tools (no bash, no file access).
    Everything is delegated via SubAgentMiddleware ``task()``.
  - SubAgent discovery is automatic via ``load_subagents_for_parent``,
    picking up any ``SUBAGENT_SPEC`` with ``parent_agents=("navmax_darktriad",)``
    registered under ``decepticon.subagents``.

Middleware slots:

  SKILLS → FILESYSTEM → UNTRUSTED_OUTPUT → ROE_GUARDRAIL → EVENT_LOG
    → PROMPT_INJECTION_SHIELD → BUDGET → SUBAGENT → OPPLAN
    → OPSCONTROL_NOTIFICATION → MODEL_FALLBACK → PROXY_KEY_OVERRIDE
    → SUMMARIZATION → PROMPT_CACHING → PATCH_TOOL_CALLS

Library API
-----------
Factory shape mirrors ``langchain.agents.create_agent`` /
``deepagents.create_deep_agent`` — every keyword is optional, and
explicit values fully replace the baseline.
"""

from __future__ import annotations

from typing import Any

from deepagents.middleware.subagents import CompiledSubAgent
from langchain.agents import create_agent

from decepticon.agents.build import build_middleware, build_tools
from decepticon.agents.prompts import load_prompt
from decepticon.backends import build_sandbox_backend, make_agent_backend
from decepticon.core.subagent_streaming import StreamingRunnable
from decepticon.llm import LLMFactory
from decepticon_core.contracts.slots import (
    MiddlewareSlot,
)
from decepticon_core.plugin_loader import (
    is_bundle_enabled,
    load_plugin_callbacks,
    load_subagents_for_parent,
)

# Orchestrator slot set: base + subagent + opplan + opscontrol
_NAVMAX_ORCHESTRATOR_SLOTS: frozenset[MiddlewareSlot] = (
    frozenset(
        {
            MiddlewareSlot.SKILLS,
            MiddlewareSlot.FILESYSTEM,
            MiddlewareSlot.UNTRUSTED_OUTPUT,
            MiddlewareSlot.ROE_GUARDRAIL,
            MiddlewareSlot.EVENT_LOG,
            MiddlewareSlot.PROMPT_INJECTION_SHIELD,
            MiddlewareSlot.BUDGET,
            MiddlewareSlot.SUBAGENT,
            MiddlewareSlot.OPPLAN,
            MiddlewareSlot.OPSCONTROL_NOTIFICATION,
            MiddlewareSlot.MODEL_FALLBACK,
            MiddlewareSlot.PROXY_KEY_OVERRIDE,
            MiddlewareSlot.SUMMARIZATION,
            MiddlewareSlot.PROMPT_CACHING,
            MiddlewareSlot.PATCH_TOOL_CALLS,
        }
    )
)

_STANDARD_TOOLS: dict[str, Any] = {}

_SKILL_SOURCES: list[str] = [
    "/skills/navmax/darktriad/",
    "/skills/shared/",
]

_ROLE = "navmax_darktriad"
_RECURSION_LIMIT = 1000


def create_navmax_darktriad_agent(
    *,
    # ── Dependencies (injected for testing / library composition) ────
    backend: Any = None,
    llm: Any = None,
    fallback_models: list | None = None,
    subagents: list | None = None,
    # ── langchain-style composition (full replace when provided) ─────
    tools: list[Any] | None = None,
    middleware: list[Any] | None = None,
    system_prompt: str | None = None,
    # ── Tuning ───────────────────────────────────────────────────────
    recursion_limit: int | None = None,
):
    """Build the DarkTriad orchestrator.

    The orchestrator has an intentionally empty tool surface — it
    delegates all work to sub-agents via ``task()`` (from
    SubAgentMiddleware). No bash, no file access, no direct exploitation.

    Args:
        backend: deepagents-style filesystem backend. Defaults to
            ``make_agent_backend(build_sandbox_backend())``.
        llm: bound chat model. Defaults to
            ``LLMFactory().get_model(_ROLE)``.
        fallback_models: passed to ``ModelFallbackMiddleware``. Defaults
            to ``LLMFactory().get_fallback_models(_ROLE)``.
        subagents: explicit sub-agent list. When ``None`` (default),
            sub-agents are discovered via ``load_subagents_for_parent``
            and each wrapped in ``StreamingRunnable``.
        tools: full tool list — when provided, replaces the standard
            registry entirely. When ``None`` (default), the OSS
            baseline (empty) is built and plugin overrides applied.
        middleware: full middleware list — when provided, replaces the
            OSS slot stack entirely. When ``None``, the baseline is
            assembled with plugin slot overrides applied.
        system_prompt: full prompt — when provided, replaces the
            baseline. When ``None``, the standard prompt is loaded and
            plugin prompt overrides are applied.
        recursion_limit: ``with_config({"recursion_limit": ...})``
            override. Defaults to 1000.

    Returns:
        Compiled LangGraph agent.
    """
    if llm is None or fallback_models is None:
        factory = LLMFactory()
        if llm is None:
            llm = factory.get_model(_ROLE)
        if fallback_models is None:
            fallback_models = factory.get_fallback_models(_ROLE)

    sandbox = build_sandbox_backend()

    if backend is None:
        backend = make_agent_backend(sandbox)

    # Build sub-agents via plugin-loader discovery. Each subagent
    # declares itself as a ``SUBAGENT_SPEC`` module constant registered
    # under the ``decepticon.subagents`` entry-point group; this main
    # agent picks up every spec whose ``parent_agents`` includes
    # ``"navmax_darktriad"``.
    if subagents is None:
        subagents = [
            CompiledSubAgent(
                name=spec.name,
                description=spec.description,
                runnable=StreamingRunnable(spec.factory(), spec.name),
            )
            for spec in load_subagents_for_parent(_ROLE)
        ]

    if tools is None:
        tools = build_tools(role=_ROLE, standard_tools=_STANDARD_TOOLS)
    if middleware is None:
        middleware = build_middleware(
            role=_ROLE,
            skill_sources=_SKILL_SOURCES,
            backend=backend,
            llm=llm,
            fallback_models=fallback_models,
            sandbox=None,  # orchestrator has no bash tool / sandbox notification
            subagents=subagents,
            slots=_NAVMAX_ORCHESTRATOR_SLOTS,
        )
    if system_prompt is None:
        system_prompt = load_prompt(_ROLE, shared=[])

    return create_agent(
        llm,
        system_prompt=system_prompt,
        tools=tools,
        middleware=middleware,
        name=_ROLE,
    ).with_config(
        {
            "recursion_limit": recursion_limit or _RECURSION_LIMIT,
            "callbacks": load_plugin_callbacks(role=_ROLE, backend=backend),
        }
    )


# Module-level graph for LangGraph Platform (langgraph serve).
# Guarded by ``is_bundle_enabled("navmax")`` so the subagent roster
# is only built when the navmax bundle is active.
if is_bundle_enabled("navmax"):
    graph = create_navmax_darktriad_agent()
