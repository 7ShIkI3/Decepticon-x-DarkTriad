"""EngagementContextMiddleware — surface launcher- and harness-set context to the LLM.

Two channels feed this middleware:

1. Launcher path (CLI / web): the launcher decides the engagement slug at
   session start and the client forwards it as state fields on every run
   (input.engagement_name and input.workspace_path). This middleware reads
   those fields and prepends a system-prompt addendum so the model knows the
   active engagement without operator hand-holding or filesystem markers.

2. Benchmark path (XBOW / CTF harness): when the LangGraph container is
   launched with `BENCHMARK_MODE=1` (via .env), this middleware additionally
   injects (a) the rule-suspension addendum that used to live in the system
   prompt and (b) the per-challenge context (target URL, vulnerability tags,
   flag format, mission brief, extra service ports) that the harness puts on
   the run state. This keeps the prompt itself free of mode-specific branches
   while letting the model see fresh challenge context on every model call.

Pattern matches OPPLANMiddleware (decepticon/middleware/opplan.py) —
state-backed context injection via wrap_model_call.
"""

from __future__ import annotations

import os
from typing import Annotated, NotRequired, cast

from langchain.agents import AgentState
from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import SystemMessage, ToolMessage
from langgraph.types import Command
from typing_extensions import override

from decepticon.middleware.opplan import _reduce_engagement_name
from decepticon.tools.bash.bash import bash_workspace


class EngagementContextState(AgentState):
    """State extension carrying launcher- and harness-decided context."""

    engagement_name: NotRequired[
        Annotated[str, "Workspace slug set by the launcher.", _reduce_engagement_name]
    ]
    workspace_path: NotRequired[Annotated[str, "Sandbox root for this engagement."]]
    # Benchmark / CTF challenge context — populated by the benchmark harness.
    target_url: NotRequired[Annotated[str, "CTF challenge target URL."]]
    target_extra_ports: NotRequired[
        Annotated[
            dict[int, int],
            "Additional published ports keyed by container target port (e.g. {22: 2222}).",
        ]
    ]
    vulnerability_tags: NotRequired[
        Annotated[list[str], "Challenge vulnerability tags (e.g. ['sqli', 'xss'])."]
    ]
    flag_format: NotRequired[Annotated[str, "Expected flag format string."]]
    mission_brief: NotRequired[Annotated[str, "Challenge name + description."]]


_FALSY_ENV_VALUES = frozenset({"", "0", "false", "no", "off"})


def _benchmark_mode_active() -> bool:
    """Truthy evaluation of the BENCHMARK_MODE env var set on the LangGraph container."""
    return os.environ.get("BENCHMARK_MODE", "").strip().lower() not in _FALSY_ENV_VALUES


def _build_engagement_injection(slug: str, workspace: str) -> str:
    return (
        "\n\n[Engagement context — set by the launcher]\n"
        f"Workspace slug: {slug}\n"
        "Workspace root: /workspace\n"
        "Treat /workspace as the only engagement directory for this run. "
        "Read and write planning documents directly under "
        "/workspace/plan/. Do NOT re-prompt the operator for a slug or an "
        "engagement directory name; the launcher already chose them. The "
        "human-friendly engagement title belongs in roe.json:engagement_name "
        "and may differ from this slug."
    )


def _format_extra_services(target_url: str, extra_ports: dict[int, int]) -> str:
    if not extra_ports:
        return ""
    # target_url comes in like "http://host.docker.internal:8080" — extract host only.
    host = target_url.split("://", 1)[-1].split(":", 1)[0] if target_url else ""
    lines: list[str] = []
    for target_port, published_port in sorted(extra_ports.items()):
        if target_port == 22:
            lines.append(f"- **SSH:** {host}:{published_port} (internal port 22)")
        else:
            lines.append(f"- **Port {target_port}:** {host}:{published_port}")
    return "**Additional services:**\n" + "\n".join(lines) + "\n"


def _build_benchmark_injection(
    target_url: str,
    extra_ports: dict[int, int],
    tags: list[str],
    flag_format: str,
    brief: str,
) -> str:
    """Per-challenge context injection for benchmark mode.

    Engagement-mode rules (Rule 8/9 suspension, OPPLAN structure, SHORT-CIRCUIT)
    live in `/skills/benchmark/SKILL.md` and are loaded explicitly by the
    orchestrator on its first turn. This middleware injects ONLY the
    per-challenge state (target URL, tags, flag format, mission brief).
    """
    sections: list[str] = ["\n## CTF Benchmark Challenge\n"]
    if target_url:
        sections.append(f"**Target URL:** {target_url}\n")
        sections.append("^^^ Attack ONLY this URL. Do NOT scan other ports or hosts. ^^^\n\n")
    extra = _format_extra_services(target_url, extra_ports)
    if extra:
        sections.append(extra + "\n")
    if tags:
        sections.append(f"**Vulnerability tags:** {', '.join(tags)}\n")
    if flag_format:
        sections.append(f"**Flag format:** {flag_format}\n")
    if brief:
        sections.append(f"**Mission brief:** {brief}\n")
    return "".join(sections)


class EngagementContextMiddleware(AgentMiddleware):
    """Inject engagement and per-challenge context into every model call.

    Scope is intentionally narrow: engagement metadata (slug, workspace) and
    per-challenge state (target URL, tags, flag format, mission brief). The
    benchmark playbook (Rule 8/9 suspension, OPPLAN structure, SHORT-CIRCUIT
    rule) lives in `/skills/benchmark/SKILL.md` — the orchestrator loads it
    on its first turn per the harness task prompt. This middleware does NOT
    inject mode-specific rules; benchmark mode only flips on the per-challenge
    context block.
    """

    state_schema = EngagementContextState

    def __init__(self) -> None:
        super().__init__()

    @override
    def wrap_model_call(self, request, handler):
        return handler(self._inject(request))

    @override
    async def awrap_model_call(self, request, handler):
        return await handler(self._inject(request))

    @override
    def wrap_tool_call(self, request, handler) -> ToolMessage | Command:
        if request.tool and request.tool.name in {
            "bash",
            "bash_output",
            "bash_kill",
            "bash_status",
        }:
            workspace = (request.state or {}).get("workspace_path", "/workspace") or "/workspace"
            with bash_workspace(workspace):
                return handler(request)
        return handler(request)

    @override
    async def awrap_tool_call(self, request, handler) -> ToolMessage | Command:
        if request.tool and request.tool.name in {
            "bash",
            "bash_output",
            "bash_kill",
            "bash_status",
        }:
            workspace = (request.state or {}).get("workspace_path", "/workspace") or "/workspace"
            with bash_workspace(workspace):
                return await handler(request)
        return await handler(request)

    def _inject(self, request):
        state = request.state or {}
        get = state.get if hasattr(state, "get") else (lambda _k, _d=None: None)

        slug = get("engagement_name", "") or ""
        workspace = get("workspace_path", "/workspace") or "/workspace"

        sections: list[str] = []
        if slug:
            sections.append(_build_engagement_injection(slug, workspace))
        if _benchmark_mode_active():
            sections.append(
                _build_benchmark_injection(
                    target_url=get("target_url", "") or "",
                    extra_ports=get("target_extra_ports", {}) or {},
                    tags=get("vulnerability_tags", []) or [],
                    flag_format=get("flag_format", "") or "",
                    brief=get("mission_brief", "") or "",
                )
            )

        if not sections:
            return request

        injection = "".join(sections)

        if request.system_message is not None:
            new_content = [
                *request.system_message.content_blocks,
                {"type": "text", "text": injection},
            ]
        else:
            new_content = [{"type": "text", "text": injection}]

        new_system = SystemMessage(content=cast("list[str | dict[str, str]]", new_content))
        return request.override(system_message=new_system)
