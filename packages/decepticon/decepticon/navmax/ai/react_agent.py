"""ReAct Agent — boucle agentique Observe → Think → Act → Observe.

Contrairement au MissionPlanner (NL → JSON statique), le ReActAgent
exécute une vraie boucle d'agent autonome avec tool-calling structuré.

Architecture :
  1. Observe : résultats de la dernière action
  2. Think   : l'IA raisonne (Chain-of-Thought)
  3. Act     : l'IA choisit un tool + params via JSON schema
  4. Execute : NavMAX exécute l'action réelle
  5. → retour à 1, jusqu'à objectif atteint ou max_steps

Usage:
    agent = ReActAgent(ai_engine, tools=[scan_tool, exploit_tool])
    result = await agent.run("Trouve les vulnérabilités sur 10.0.0.0/24")
"""

import asyncio
import json
import re
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import jsonschema
import structlog

from decepticon.navmax.ai.engine import AIEngine
from decepticon.navmax.ai.providers.base import ModelTier

logger = structlog.get_logger(__name__)

# ── Exceptions ────────────────────────────────────────────────────


class ToolRequiresConfirmation(Exception):
    """Levée quand un tool dangerous nécessite une confirmation humaine."""


# ── Types ────────────────────────────────────────────────────────


@dataclass
class Tool:
    """Un outil que l'agent peut appeler."""

    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema
    func: Callable[..., Any]  # sync ou async
    dangerous: bool = False
    requires_confirmation: bool = False

    def to_openai_tool(self) -> dict:
        """Format OpenAI function calling."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass
class Step:
    """Une étape de la boucle ReAct."""

    step_number: int
    thought: str
    tool_name: str | None
    tool_params: dict | None
    result: Any | None
    error: str | None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class StepUpdate:
    """Update streaming d'une étape."""

    step_number: int
    status: str  # "thinking", "acting", "done", "error"
    thought: str = ""
    tool_name: str = ""
    result: Any = None


@dataclass
class MissionResult:
    """Résultat final d'une mission."""

    objective: str
    success: bool
    steps: list[Step]
    total_steps: int
    duration_s: float
    summary: str
    findings: list[dict]


# ── System Prompt ────────────────────────────────────────────────

REACT_SYSTEM_PROMPT = """You are NavMAX ReAct Agent, an autonomous cybersecurity pentesting AI.

You operate in a strict Observe -> Think -> Act -> Observe loop.

## RULES
1. At each step, output EXACTLY this JSON format:
   {{"thought": "<your reasoning about what to do next>", "action": {{"tool": "<tool_name>", "params": {{<parameters>}}}}}}
2. When the mission is complete, use action "finish" with a summary.
3. NEVER execute the same tool twice with identical parameters unless results warrant it.
4. If a tool fails, analyze the error and try an alternative approach.
5. Prioritize information gathering before exploitation.
6. When you discover a vulnerability, verify it before reporting.
7. Maximum {max_steps} steps per mission.

## AVAILABLE TOOLS
{tools_description}

## CURRENT MISSION
Objective: {objective}

## HISTORY
{history}
"""

# ── Default Tools ────────────────────────────────────────────────


def _make_default_tools() -> list[Tool]:
    """Construit les tools par défaut (stubs — seront enrichis par les vrais modules)."""
    return [
        Tool(
            name="scan_ports",
            description="Scan TCP/UDP ports on a target. Returns open ports, services, versions, and OS.",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP, hostname, or CIDR range"},
                    "ports": {
                        "type": "string",
                        "description": "Ports: '1-1000', '22,80,443', 'all'",
                    },
                    "profile": {
                        "type": "string",
                        "enum": ["quick", "default", "deep", "stealth"],
                        "description": "Scan profile",
                    },
                },
                "required": ["target"],
            },
            func=lambda **kw: {"status": "stub", "message": "NmapScanner not wired yet"},
        ),
        Tool(
            name="scan_vulnerabilities",
            description="Scan for known CVEs using nuclei. Returns findings with CVE IDs, severity, and descriptions.",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL/IP"},
                    "templates": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Nuclei template tags (e.g., ['cves/', 'exposed-panels/'])",
                    },
                    "severity": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                        },
                        "description": "Severity filter",
                    },
                },
                "required": ["target"],
            },
            func=lambda **kw: {"status": "stub", "message": "NucleiScanner not wired yet"},
            dangerous=True,
        ),
        Tool(
            name="osint_investigate",
            description="OSINT recon: DNS, WHOIS, SSL certs, subdomains, Shodan/Censys lookup.",
            parameters={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to investigate"},
                },
                "required": ["domain"],
            },
            func=lambda **kw: {"status": "stub", "message": "OSINT not wired yet"},
        ),
        Tool(
            name="exploit_check",
            description="Check if a service is exploitable. Returns exploitation result.",
            parameters={
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Service name (ssh, redis, http, ...)",
                    },
                    "version": {"type": "string", "description": "Service version"},
                    "host": {"type": "string", "description": "Target host"},
                    "port": {"type": "integer", "description": "Target port"},
                },
                "required": ["service", "host"],
            },
            func=lambda **kw: {"status": "stub", "message": "Exploit not wired yet"},
            dangerous=True,
            requires_confirmation=True,
        ),
        Tool(
            name="ad_enumerate",
            description="Enumerate Active Directory: users, groups, computers, trusts, vulnerabilities.",
            parameters={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "AD domain FQDN"},
                    "dc": {"type": "string", "description": "Domain controller IP"},
                    "username": {"type": "string", "description": "AD username"},
                    "password": {"type": "string", "description": "AD password"},
                },
                "required": ["domain", "dc", "username", "password"],
            },
            func=lambda **kw: {"status": "stub", "message": "AD not wired yet"},
            dangerous=True,
            requires_confirmation=True,
        ),
        Tool(
            name="generate_report",
            description="Generate a structured pentest report from mission findings.",
            parameters={
                "type": "object",
                "properties": {
                    "mission_id": {"type": "string", "description": "Mission ID to report on"},
                    "format": {
                        "type": "string",
                        "enum": ["html", "markdown", "sarif"],
                        "description": "Output format",
                    },
                },
                "required": ["mission_id"],
            },
            func=lambda **kw: {"status": "stub", "message": "Reporting not wired yet"},
        ),
    ]


# ── ReAct Agent ──────────────────────────────────────────────────


class ReActAgent:
    """Agent ReAct avec tool-calling structuré.

    Caractéristiques :
    - Boucle Observe → Think → Act → Observe
    - Validation JSON schema des actions
    - Streaming en temps réel des steps
    - Persistence des steps
    - Retry automatique sur JSON invalide (max 3)
    """

    def __init__(
        self,
        ai_engine: AIEngine,
        tools: list[Tool] | None = None,
        max_steps: int = 20,
        model_tier: ModelTier = ModelTier.MEDIUM,
    ) -> None:
        self.ai_engine = ai_engine
        self.tools: dict[str, Tool] = {}
        for tool in tools or _make_default_tools():
            self.tools[tool.name] = tool
        self.max_steps = max_steps
        self.model_tier = model_tier
        self._provider_failures: dict[str, int] = {}
        self._provider_skip_until: dict[str, float] = {}

    async def run(self, objective: str) -> MissionResult:
        """Exécute la boucle ReAct complète.

        Args:
            objective: Objectif de la mission en langage naturel.

        Returns:
            MissionResult avec toutes les étapes et le résultat.

        """
        start_time = asyncio.get_event_loop().time()
        steps: list[Step] = []
        findings: list[dict] = []

        tools_desc = self._format_tools()
        history = ""

        for step_num in range(1, self.max_steps + 1):
            prompt = REACT_SYSTEM_PROMPT.format(
                objective=objective,
                tools_description=tools_desc,
                max_steps=self.max_steps,
                history=history,
            )

            logger.info("react_step", step=step_num, objective=objective[:80])

            # Think + Act
            try:
                response = await self.ai_engine.generate(
                    prompt=prompt,
                    system_prompt="You are NavMAX ReAct Agent. Output ONLY valid JSON.",
                    tier=self.model_tier,
                )
                step = self._parse_step(step_num, response)
            except (RuntimeError, ValueError, json.JSONDecodeError, KeyError) as e:
                logger.exception("react_parse_error", step=step_num, error=str(e))
                step = Step(
                    step_number=step_num,
                    thought=f"Erreur de parsing: {e}",
                    tool_name=None,
                    tool_params=None,
                    result=None,
                    error=str(e),
                )

            # Si finish → retour
            if step.tool_name == "finish":
                step.result = step.tool_params or {}
                steps.append(step)
                elapsed = asyncio.get_event_loop().time() - start_time

                success = (
                    step.result.get("success", False) if isinstance(step.result, dict) else False
                )
                summary_text = (
                    step.result.get("summary", "")
                    if isinstance(step.result, dict)
                    else str(step.result)
                )

                return MissionResult(
                    objective=objective,
                    success=success,
                    steps=steps,
                    total_steps=len(steps),
                    duration_s=elapsed,
                    summary=summary_text,
                    findings=findings,
                )

            # Execute tool
            if step.tool_name and step.tool_name in self.tools:
                tool = self.tools[step.tool_name]
                try:
                    # 1. Validation JSON schema des paramètres
                    if step.tool_params is not None:
                        self._validate_params(tool, step.tool_params)

                    # 2. Gate pour tools dangereux : lever une exception
                    if tool.dangerous and tool.requires_confirmation:
                        msg = (
                            f"Tool '{tool.name}' blocked — requires human confirmation. "
                            f"Params: {json.dumps(step.tool_params)}"
                        )
                        raise ToolRequiresConfirmation(
                            msg,
                        )

                    result = await self._execute_tool(tool, step.tool_params or {})
                    step.result = result
                    # Collecter les findings
                    if isinstance(result, dict) and "findings" in result:
                        findings.extend(result["findings"])
                except ToolRequiresConfirmation:
                    raise
                except (
                    RuntimeError,
                    ValueError,
                    TypeError,
                    OSError,
                    jsonschema.ValidationError,
                ) as e:
                    logger.exception("react_tool_error", tool=step.tool_name, error=str(e))
                    step.error = str(e)
                    step.result = {"error": str(e)}
            elif step.tool_name and step.tool_name != "finish":
                step.error = f"Tool inconnu: {step.tool_name}"
                step.result = {"error": step.error}
            else:
                step.result = {"status": "no_action"}

            steps.append(step)

            # Mise à jour de l'historique
            history += self._step_to_history(step)

        # Max steps atteint
        elapsed = asyncio.get_event_loop().time() - start_time
        return MissionResult(
            objective=objective,
            success=False,
            steps=steps,
            total_steps=len(steps),
            duration_s=elapsed,
            summary=f"Max steps ({self.max_steps}) atteint sans complétion.",
            findings=findings,
        )

    async def stream_run(self, objective: str) -> AsyncIterator[StepUpdate]:
        """Version streaming — yield chaque étape en temps réel.

        Args:
            objective: Objectif de la mission.

        Yields:
            StepUpdate à chaque changement d'état.

        """
        asyncio.get_event_loop().time()
        steps: list[Step] = []
        tools_desc = self._format_tools()
        history = ""

        for step_num in range(1, self.max_steps + 1):
            yield StepUpdate(
                step_number=step_num,
                status="thinking",
                thought=f"Analyse de l'étape {step_num}...",
            )

            prompt = REACT_SYSTEM_PROMPT.format(
                objective=objective,
                tools_description=tools_desc,
                max_steps=self.max_steps,
                history=history,
            )

            try:
                response = await self.ai_engine.generate(
                    prompt=prompt,
                    system_prompt="You are NavMAX ReAct Agent. Output ONLY valid JSON.",
                    tier=self.model_tier,
                )
                step = self._parse_step(step_num, response)
            except (RuntimeError, ValueError, json.JSONDecodeError, KeyError) as e:
                yield StepUpdate(
                    step_number=step_num,
                    status="error",
                    thought=f"Erreur: {e}",
                )
                continue

            yield StepUpdate(
                step_number=step_num,
                status="acting",
                thought=step.thought,
                tool_name=step.tool_name or "",
            )

            if step.tool_name == "finish":
                step.result = step.tool_params or {}
                steps.append(step)
                yield StepUpdate(
                    step_number=step_num,
                    status="done",
                    thought=step.thought,
                    result=step.result,
                )
                break

            if step.tool_name and step.tool_name in self.tools:
                tool = self.tools[step.tool_name]
                try:
                    # 1. Validation JSON schema des paramètres
                    if step.tool_params is not None:
                        self._validate_params(tool, step.tool_params)

                    # 2. Gate pour tools dangereux
                    if tool.dangerous and tool.requires_confirmation:
                        msg = (
                            f"Tool '{tool.name}' blocked — requires human confirmation. "
                            f"Params: {json.dumps(step.tool_params)}"
                        )
                        raise ToolRequiresConfirmation(
                            msg,
                        )

                    result = await self._execute_tool(tool, step.tool_params or {})
                    step.result = result
                    yield StepUpdate(
                        step_number=step_num,
                        status="done",
                        thought=step.thought,
                        tool_name=step.tool_name,
                        result=result,
                    )
                except (
                    RuntimeError,
                    ValueError,
                    TypeError,
                    OSError,
                    jsonschema.ValidationError,
                ) as e:
                    step.error = str(e)
                    yield StepUpdate(
                        step_number=step_num,
                        status="error",
                        thought=step.thought,
                        tool_name=step.tool_name or "",
                        result={"error": str(e)},
                    )

            steps.append(step)
            history += self._step_to_history(step)

        if not any(s.tool_name == "finish" for s in steps):
            yield StepUpdate(
                step_number=0,
                status="error",
                thought=f"Max steps ({self.max_steps}) atteint.",
            )

    # ── Internals ────────────────────────────────────────────────

    def _is_provider_available(self, provider_name: str) -> bool:
        import time

        return time.monotonic() >= self._provider_skip_until.get(provider_name, 0.0)

    def _record_provider_failure(self, provider_name: str) -> None:
        import time

        count = self._provider_failures.get(provider_name, 0) + 1
        self._provider_failures[provider_name] = count
        if count >= 5:
            skip_until = time.monotonic() + 60.0
            self._provider_skip_until[provider_name] = skip_until
            logger.warning("circuit_breaker_ouvert", provider=provider_name, reset_in_s=60)

    def _record_provider_success(self, provider_name: str) -> None:
        self._provider_failures[provider_name] = 0

    def _format_tools(self) -> str:
        """Formate la liste des tools pour le prompt."""
        lines = []
        for name, tool in self.tools.items():
            danger = " ⚠️ DANGEREUX" if tool.dangerous else ""
            lines.append(
                f"- **{name}**{danger}: {tool.description}\n"
                f"  Parameters: {json.dumps(tool.parameters, indent=2)}",
            )
        return "\n".join(lines)

    def _parse_step(self, step_num: int, response: str) -> Step:
        """Parse la réponse JSON de l'IA en Step.

        Supporte :
        - JSON pur
        - JSON dans un bloc markdown ```json ... ```
        - JSON avec préfixe/suffixe texte (extrait le premier { ... })
        """
        text = response.strip()

        # Essayer de parser directement
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Essayer d'extraire d'un bloc markdown
            if "```json" in text:
                start = text.index("```json") + 7
                end = text.index("```", start)
                text = text[start:end].strip()
                data = json.loads(text)
            elif "```" in text:
                start = text.index("```") + 3
                end = text.index("```", start)
                text = text[start:end].strip()
                data = json.loads(text)
            else:
                # Extraire le premier objet JSON
                first_brace = text.find("{")
                last_brace = text.rfind("}")
                if first_brace >= 0 and last_brace > first_brace:
                    text = text[first_brace : last_brace + 1]
                    data = json.loads(text)
                else:
                    msg = f"Impossible de parser le JSON: {response[:200]}"
                    raise ValueError(msg)

        thought = data.get("thought", "")
        action = data.get("action", {})
        tool_name = action.get("tool") if isinstance(action, dict) else None
        tool_params = action.get("params") if isinstance(action, dict) else None

        logger.info(
            "react_parsed_step",
            step=step_num,
            tool=tool_name,
            thought=thought[:100],
        )

        return Step(
            step_number=step_num,
            thought=thought,
            tool_name=tool_name,
            tool_params=tool_params if isinstance(tool_params, dict) else None,
            result=None,
            error=None,
        )

    async def _execute_tool(self, tool: Tool, params: dict) -> Any:
        """Exécute un tool (support sync et async)."""
        logger.info("react_execute_tool", tool=tool.name, params=params)

        result = tool.func(**params)
        if asyncio.iscoroutine(result):
            result = await result
        return result

    def _validate_params(self, tool: Tool, params: dict) -> None:
        """Valide les paramètres d'un tool contre son JSON schema.

        Utilise jsonschema.validate() pour garantir que les paramètres
        fournis par l'IA respectent le schema déclaré du tool.

        Args:
            tool: Le tool à valider.
            params: Les paramètres à valider.

        Raises:
            jsonschema.ValidationError: Si les paramètres sont invalides.

        """
        if not isinstance(params, dict):
            msg = f"Params for tool '{tool.name}' must be a dict, got {type(params).__name__}"
            raise jsonschema.ValidationError(
                msg,
            )
        jsonschema.validate(instance=params, schema=tool.parameters)

    _INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
        (
            re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions?", re.IGNORECASE),
            "[INJECTION BLOCKED: ignore instructions]",
        ),
        (
            re.compile(
                r"forget\s+(all\s+)?(previous|prior)\s+(instructions|context|history)",
                re.IGNORECASE,
            ),
            "[INJECTION BLOCKED: forget instructions]",
        ),
        (re.compile(r"you\s+are\s+now\s+", re.IGNORECASE), "[INJECTION BLOCKED: role change]"),
        (
            re.compile(r"disregard\s+(all\s+)?(previous|prior)?", re.IGNORECASE),
            "[INJECTION BLOCKED: disregard]",
        ),
        (
            re.compile(r"(new\s+)?system\s+prompt\s*:", re.IGNORECASE),
            "[INJECTION BLOCKED: system prompt override]",
        ),
        (
            re.compile(r"override\s+(all\s+)?(previous|prior)?", re.IGNORECASE),
            "[INJECTION BLOCKED: override]",
        ),
        (
            re.compile(r"you\s+must\s+(not|never|always)", re.IGNORECASE),
            "[INJECTION BLOCKED: instruction override]",
        ),
        (
            re.compile(r"\[\s*(SYSTEM|INJECT|OVERRIDE)\s*\]", re.IGNORECASE),
            "[INJECTION BLOCKED: system tag]",
        ),
        (
            re.compile(r"<\|?(im_start|im_end|sys|system|user|assistant)\|?>", re.IGNORECASE),
            "[INJECTION BLOCKED: chat token]",
        ),
    ]

    def _sanitize_for_history(self, text: str) -> str:
        """Supprime les tentatives d'injection de prompt dans un texte.

        Remplace les patterns d'injection courants par des marqueurs
        de blocage explicites, puis tronque à 500 caractères.

        Args:
            text: Le texte à nettoyer.

        Returns:
            Texte nettoyé et tronqué.

        """
        if not isinstance(text, str):
            return str(text)

        for pattern, replacement in self._INJECTION_PATTERNS:
            text = pattern.sub(replacement, text)

        if len(text) > 500:
            text = text[:497] + "..."

        return text

    def _step_to_history(self, step: Step) -> str:
        """Convertit un Step en texte pour l'historique du prompt.

        Sanitize les contenus pour prévenir la prompt injection :
        - Supprime les patterns d'injection du thought et du résultat
        - Tronque les résultats à 500 caractères
        """
        tool_info = ""
        if step.tool_name:
            tool_info = (
                f"\nAction: {step.tool_name}"
                f"({self._sanitize_for_history(json.dumps(step.tool_params or {}))})"
            )
            if step.result:
                result_str = json.dumps(step.result, default=str, indent=2)
                if len(result_str) > 500:
                    result_str = result_str[:497] + "..."
                result_str = self._sanitize_for_history(result_str)
                tool_info += f"\nResult: {result_str}"
            if step.error:
                tool_info += f"\nError: {self._sanitize_for_history(step.error)}"

        thought_clean = self._sanitize_for_history(step.thought)
        return f"\nStep {step.step_number}:\nThought: {thought_clean}{tool_info}\n"


# ── Wire tools ───────────────────────────────────────────────────


def wire_tools(
    agent: ReActAgent,
    nmap_scanner=None,
    nuclei_scanner=None,
    osint_orchestrator=None,
) -> None:
    """Branche les vrais modules NavMAX sur les tools de l'agent.

    Args:
        agent: Le ReActAgent à configurer.
        nmap_scanner: Instance de NmapScanner (navmax.scanner.nmap_scanner).
        nuclei_scanner: Instance de NucleiScanner (navmax.scanner.nuclei_scanner).
        osint_orchestrator: Instance de OSINT orchestrator.

    """
    if nmap_scanner:

        async def _scan_ports(**kw) -> dict:
            result = await nmap_scanner.scan(
                target=kw["target"],
                ports=kw.get("ports", "1-1000"),
                profile=kw.get("profile", "default"),
            )
            # Serialize le résultat
            return {
                "hosts": [
                    {
                        "ip": h.ip,
                        "hostname": h.hostname,
                        "os": h.os_match,
                        "open_ports": len(h.ports),
                    }
                    for h in result.hosts
                ],
                "duration_s": result.duration_s,
            }

        if "scan_ports" in agent.tools:
            agent.tools["scan_ports"].func = _scan_ports

    if nuclei_scanner:

        async def _scan_vulns(**kw) -> dict:
            findings = await nuclei_scanner.scan(
                target=kw["target"],
                templates=kw.get("templates"),
                severity=kw.get("severity"),
            )
            return {
                "findings": [
                    {
                        "template_id": f.template_id,
                        "name": f.name,
                        "severity": f.severity,
                        "cve_ids": f.cve_ids,
                        "description": f.description,
                    }
                    for f in findings
                ],
                "total": len(findings),
            }

        if "scan_vulnerabilities" in agent.tools:
            agent.tools["scan_vulnerabilities"].func = _scan_vulns
            agent.tools["scan_vulnerabilities"].dangerous = True

    if osint_orchestrator:

        async def _osint_investigate(**kw) -> dict:
            return await osint_orchestrator.investigate(domain=kw["domain"])

        if "osint_investigate" in agent.tools:
            agent.tools["osint_investigate"].func = _osint_investigate

    logger.info(
        "react_tools_wired",
        tools=list(agent.tools.keys()),
        wired=[t for t in agent.tools.values() if "stub" not in str(t.func.__doc__ or "")],
    )
