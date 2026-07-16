"""NavMAX Scanner Agent — network scanning via NavMAX scanner tooling.

Wraps ``decepticon.tools.navmax.scanner_tools`` into a LangGraph agent
dispatched by the DarkTriad orchestrator. Broad-spectrum recon over
large networks using Nmap, Nuclei, TCP connect scans, and the
vulnerability database.

Middleware slots (defined in ``_NAVMAX_BASH_SLOTS``):

  SKILLS → FILESYSTEM → UNTRUSTED_OUTPUT → ROE_GUARDRAIL → EVENT_LOG
    → PROMPT_INJECTION_SHIELD → BUDGET → MODEL_FALLBACK → PROXY_KEY_OVERRIDE
    → SUMMARIZATION → PROMPT_CACHING → PATCH_TOOL_CALLS
    → ENGAGEMENT_CONTEXT → SANDBOX_NOTIFICATION → HITL_APPROVAL

No SubAgent / OPPLAN (specialist, not an orchestrator).
"""

from __future__ import annotations

from typing import Any

from langchain.agents import create_agent

from decepticon.agents.build import build_middleware, build_tools
from decepticon.agents.prompts import load_prompt
from decepticon.backends import build_sandbox_backend, make_agent_backend
from decepticon.llm import LLMFactory
from decepticon.tools.bash import BASH_TOOLS
from decepticon.tools.bash.bash import set_sandbox
from decepticon.tools.navmax.scanner_tools import NAVMAX_SCANNER_TOOLS
from decepticon_core.contracts.slots import (
    MiddlewareSlot,
)
from decepticon_core.plugin_loader import SubAgentSpec, is_bundle_enabled, load_plugin_callbacks

# Bash-agent slot set: base + engagement context + sandbox notification + HITL
_NAVMAX_BASH_SLOTS: frozenset[MiddlewareSlot] = (
    frozenset(
        {
            MiddlewareSlot.SKILLS,
            MiddlewareSlot.FILESYSTEM,
            MiddlewareSlot.UNTRUSTED_OUTPUT,
            MiddlewareSlot.ROE_GUARDRAIL,
            MiddlewareSlot.EVENT_LOG,
            MiddlewareSlot.PROMPT_INJECTION_SHIELD,
            MiddlewareSlot.BUDGET,
            MiddlewareSlot.MODEL_FALLBACK,
            MiddlewareSlot.PROXY_KEY_OVERRIDE,
            MiddlewareSlot.SUMMARIZATION,
            MiddlewareSlot.PROMPT_CACHING,
            MiddlewareSlot.PATCH_TOOL_CALLS,
            MiddlewareSlot.ENGAGEMENT_CONTEXT,
            MiddlewareSlot.SANDBOX_NOTIFICATION,
            MiddlewareSlot.HITL_APPROVAL,
        }
    )
)

_STANDARD_TOOLS: dict[str, Any] = {
    t.name: t
    for t in [
        # NavMAX scanner tools
        *NAVMAX_SCANNER_TOOLS,
        # Execution
        *BASH_TOOLS,
    ]
}

_SKILL_SOURCES: list[str] = [
    "/skills/navmax/scanner/",
    "/skills/shared/",
]

_ROLE = "navmax_scanner"
_RECURSION_LIMIT = 1000


def create_navmax_scanner_agent(
    *,
    # ── Dependencies (injected for testing / library composition) ────
    backend: Any = None,
    llm: Any = None,
    fallback_models: list | None = None,
    sandbox: Any = None,
    # ── langchain-style composition (full replace when provided) ─────
    tools: list[Any] | None = None,
    middleware: list[Any] | None = None,
    system_prompt: str | None = None,
    # ── Tuning ───────────────────────────────────────────────────────
    recursion_limit: int | None = None,
):
    """Build the NavMAX Scanner agent.

    Args:
        backend: deepagents-style filesystem backend. Defaults to
            ``make_agent_backend(build_sandbox_backend())``.
        llm: bound chat model. Defaults to
            ``LLMFactory().get_model(_ROLE)``.
        fallback_models: passed to ``ModelFallbackMiddleware``. Defaults
            to ``LLMFactory().get_fallback_models(_ROLE)``.
        sandbox: sandbox backend for bash execution and
            ``SandboxNotificationMiddleware``. Defaults to
            ``build_sandbox_backend()``.
        tools: full tool list — when provided, replaces the standard
            registry entirely. When ``None`` (default), the OSS
            baseline is built and plugin overrides are applied.
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

    if sandbox is None:
        sandbox = build_sandbox_backend()
    set_sandbox(sandbox)

    if backend is None:
        backend = make_agent_backend(sandbox)

    if tools is None:
        tools = build_tools(role=_ROLE, standard_tools=_STANDARD_TOOLS)
    if middleware is None:
        middleware = build_middleware(
            role=_ROLE,
            skill_sources=_SKILL_SOURCES,
            backend=backend,
            llm=llm,
            fallback_models=fallback_models,
            sandbox=sandbox,
            slots=_NAVMAX_BASH_SLOTS,
        )
    if system_prompt is None:
        system_prompt = load_prompt(_ROLE, shared=["bash"])

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


# Module-level graph for LangGraph Platform (langgraph serve)
if is_bundle_enabled("navmax"):
    graph = create_navmax_scanner_agent()


SUBAGENT_SPEC = SubAgentSpec(
    name="navmax_scanner",
    description=(
        "NavMAX network scanner. Broad-spectrum reconnaissance: Nmap "
        "port/OS/service scans, Nuclei template-based vulnerability "
        "scanning, TCP connect probes, and CVE database lookups. "
        "Use first on any new target to map attack surface."
    ),
    factory=create_navmax_scanner_agent,
    parent_agents=("navmax_darktriad",),
    bundle="navmax",
    priority=10,
)
