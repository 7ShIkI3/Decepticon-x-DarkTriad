"""🜏 The Dark Triad — CLI.

Typer-based command-line interface with Rich-formatted output.
Cyber-industrial dark theme with personality-themed colors.

Usage:
    tdt mission "Objective" --persona machiavellian --aggression strategic
    tdt onboard
    tdt status
    tdt report <mission_id> --format html
    tdt sandbox start|stop|status
    tdt agents list|info <name>
    tdt ai status|models|generate
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from decepticon.navmax.darktriad.agents.registry import AgentRegistry
from decepticon.navmax.darktriad.core import (
    AIRouter,
    ModelTier,
    PersonalityMode,
    SandboxManager,
)
from decepticon.navmax.darktriad.orchestrator import MissionPlanner

# ── Console ───────────────────────────────────────────────────────────────────

console = Console()

# Personality emoji / colour mapping
PERSONALITY_STYLE = {
    "mach": ("🕸️", "cyan"),
    "machiavellianism": ("🕸️", "cyan"),
    "psychopathy": ("🔪", "red"),
    "narcissism": ("🪞", "yellow"),
}

AGGRESSION_STYLE = {
    "strategic": "green",
    "aggressive": "yellow",
    "maximum": "red",
    "relentless": "red bold",
}

_MISSIONS_STORE = Path.home() / ".tdt" / "missions"
_PROVIDERS_FILE = Path.home() / ".tdt" / "providers.json"

# ── Helpers ────────────────────────────────────────────────────────────────────


def _ascii_header() -> Text:
    """Render the Dark Triad ASCII art header."""
    ascii_art = r"""
    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
    ██ ▄▄▄ ▄▄▄ ▄▄▄ █ ▄▄▀██ ▄▄▄ ███ ▄▀▄ ▄▀██ █ ██ ▄▄▄ █ ▄▄▀██ ▄▄▄ █ ▄▀▄ ▄▀█
    ██ ███ █▄▀ ███ █ ▀▀▄██ █▄▀  ██ █ ▀▄▀ ██ ▀▀ ██ █▄▀ █ ▀▀▄██ ███ █ █ █ ██
    ██ ▀▀▀ █ █ ▀▀▀ █ █ ███ ▀▀▀  █▄█ █ ▀█ ▄██ ██ ██ ▀▀▀ █ █ ███ ▀▀▀ █ █ ▄▀ ██
    ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
    """
    return Text(ascii_art, style="bold dark_green")


def _personality_emoji(persona: str) -> str:
    """Return emoji for a personality name (case-insensitive, fuzzy)."""
    key = persona.strip().lower().replace(" ", "_")
    for k, (emoji, _) in PERSONALITY_STYLE.items():
        if k.startswith(key) or key.startswith(k):
            return emoji
    return "⚙️"


def _personality_color(persona: str) -> str:
    """Return Rich colour for a personality name."""
    key = persona.strip().lower().replace(" ", "_")
    for k, (_, colour) in PERSONALITY_STYLE.items():
        if k.startswith(key) or key.startswith(k):
            return colour
    return "white"


def _style_persona(name: str) -> Text:
    """Return a styled Text object for a personality name."""
    emoji, colour = PERSONALITY_STYLE.get(
        name.strip().lower().replace(" ", "_"),
        ("⚙️", "white"),
    )
    return Text(f"{emoji} {name.title()}", style=f"bold {colour}")


def _make_mission_store() -> Path:
    """Ensure the mission store directory exists."""
    _MISSIONS_STORE.mkdir(parents=True, exist_ok=True)
    return _MISSIONS_STORE


def _load_mission(mission_id: str) -> dict | None:
    """Load a mission from the local store."""
    path = _MISSIONS_STORE / f"{mission_id}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())


def _save_mission(mission_id: str, data: dict) -> None:
    """Save a mission to the local store."""
    _make_mission_store()
    path = _MISSIONS_STORE / f"{mission_id}.json"
    path.write_text(json.dumps(data, indent=2, default=str))


def _list_missions() -> list[dict]:
    """List all saved missions."""
    _make_mission_store()
    missions = []
    for p in sorted(_MISSIONS_STORE.glob("*.json"), reverse=True):
        missions.append(json.loads(p.read_text()))
    return missions


async def _init_router_and_registry() -> tuple[AIRouter, AgentRegistry]:
    """Initialise shared AIRouter and AgentRegistry instances."""
    router = AIRouter()
    try:
        await router.initialize()
    except Exception:
        console.log(
            "[yellow]AI router initialization deferred — status will show if unavailable[/yellow]"
        )

    registry = AgentRegistry()
    return router, registry


# ── App ───────────────────────────────────────────────────────────────────────

app = typer.Typer(
    name="tdt",
    help="🜏 The Dark Triad — Autonomous Red Team Agent CLI",
    no_args_is_help=True,
    rich_markup_mode="rich",
    pretty_exceptions_show_locals=False,
    pretty_exceptions_enable=False,
)

mission_app = typer.Typer(
    name="mission",
    help="Manage and launch offensive missions.",
    no_args_is_help=True,
)
app.add_typer(mission_app, name="mission")

sandbox_app = typer.Typer(
    name="sandbox",
    help="Control the Docker sandbox environment.",
    no_args_is_help=True,
)
app.add_typer(sandbox_app, name="sandbox")

agents_app = typer.Typer(
    name="agents",
    help="List and inspect registered agents.",
    no_args_is_help=True,
)
app.add_typer(agents_app, name="agents")

ai_app = typer.Typer(
    name="ai",
    help="AI provider status, model listing, and generation.",
    no_args_is_help=True,
)
app.add_typer(ai_app, name="ai")

benchmark_app = typer.Typer(
    name="benchmark",
    help="Run and report on agent benchmark suites (XBOW, custom).",
    no_args_is_help=True,
)
app.add_typer(benchmark_app, name="benchmark")


# ═══════════════════════════════════════════════════════════════════════════════
#  MISSION
# ═══════════════════════════════════════════════════════════════════════════════


@mission_app.callback(invoke_without_command=True)
def mission_callback(ctx: typer.Context) -> None:
    """Manage missions."""
    if ctx.invoked_subcommand is not None:
        return
    missions = _list_missions()
    if not missions:
        console.print(Panel("[dim]No missions saved yet.[/dim]", title="📋 Missions"))
        return
    _display_mission_list(missions)


@mission_app.command("create")
def mission_create(
    objective: str = typer.Argument(..., help="Natural-language mission objective"),
    persona: str = typer.Option(
        "machiavellianism",
        "--persona",
        "-p",
        help="Personality mode: narcissism, psychopathy, machiavellianism",
        show_default=True,
    ),
    aggression: str = typer.Option(
        "strategic",
        "--aggression",
        "-a",
        help="Aggression level: strategic, aggressive, maximum, relentless",
        show_default=True,
    ),
) -> None:
    """Create and execute a new mission."""
    console.print(_ascii_header())
    console.print(
        Panel(
            f"[bold]{_personality_emoji(persona)} Mission:[/bold] [italic]{objective}[/italic]",
            style=_personality_color(persona),
        )
    )

    # Normalise personality value
    persona_normalised = persona.strip().lower()
    if persona_normalised == "machiavellian" or persona_normalised == "mach":
        persona_normalised = PersonalityMode.MACHIAVELLIANISM.value
    elif persona_normalised == "psychopath":
        persona_normalised = PersonalityMode.PSYCHOPATHY.value
    elif persona_normalised == "narcissus":
        persona_normalised = PersonalityMode.NARCISSISM.value

    async def _run() -> None:
        router, registry = await _init_router_and_registry()
        sandbox = SandboxManager()
        planner = MissionPlanner(router, registry, sandbox)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Planning mission...[/cyan]", total=10)

            plan = await planner.plan(
                objective=objective,
                personality=persona_normalised,
                constraints={"aggression": aggression},
            )
            progress.update(task, completed=10, description="[green]Plan ready![/green]")

        _save_mission(
            plan.mission_id,
            {
                "mission_id": plan.mission_id,
                "objective": plan.objective,
                "personality": plan.personality,
                "status": plan.status,
                "total_phases": plan.total_phases,
                "estimated_duration": plan.estimated_duration,
                "risk_level": plan.risk_level,
                "created_at": plan.created_at,
                "phases": [
                    {
                        "name": p.name,
                        "agent_name": p.agent_name,
                        "agent_category": p.agent_category,
                        "objective": p.objective,
                        "estimated_duration": p.estimated_duration,
                        "risk_level": p.risk_level,
                        "status": p.status,
                    }
                    for p in plan.phases
                ],
            },
        )

        # Display phases table
        table = Table(
            title=f"Mission Plan — {plan.mission_id}",
            box=box.HEAVY_EDGE,
            border_style=_personality_color(persona_normalised),
        )
        table.add_column("#", style="dim", width=3)
        table.add_column("Phase", style="bold")
        table.add_column("Agent", style="cyan")
        table.add_column("Category", style="blue")
        table.add_column("Duration", justify="right")
        table.add_column("Risk", justify="right")

        for i, phase in enumerate(plan.phases, 1):
            dur = f"{phase.estimated_duration}s" if phase.estimated_duration else "—"
            risk_colour = (
                "green" if phase.risk_level < 0.3 else "yellow" if phase.risk_level < 0.7 else "red"
            )
            table.add_row(
                str(i),
                phase.name,
                phase.agent_name,
                phase.agent_category,
                dur,
                f"[{risk_colour}]{phase.risk_level:.1f}[/{risk_colour}]",
            )

        console.print(table)

        # Summary panel
        summary = Table.grid(padding=(0, 2))
        summary.add_column(style="bold")
        summary.add_column()
        summary.add_row("Mission ID", f"[cyan]{plan.mission_id}[/cyan]")
        summary.add_row("Personality", str(_style_persona(plan.personality)))
        summary.add_row("Phases", str(plan.total_phases))
        summary.add_row(
            "Est. Duration",
            f"{plan.estimated_duration}s" if plan.estimated_duration else "—",
        )
        risk_style = (
            "green" if plan.risk_level < 0.3 else "yellow" if plan.risk_level < 0.7 else "red"
        )
        summary.add_row("Risk Level", f"[{risk_style}]{plan.risk_level:.2f}[/{risk_style}]")

        console.print(
            Panel(
                summary,
                title="📊 Summary",
                border_style="green",
            )
        )

    try:
        asyncio.run(_run())
    except Exception as exc:
        console.print(f"[red]✗ Mission failed:[/red] {exc}")


@mission_app.command("list")
def mission_list() -> None:
    """List all saved missions."""
    missions = _list_missions()
    if not missions:
        console.print(
            "[dim]No missions saved yet. Run [bold]tdt mission create[/bold] to start one.[/dim]"
        )
        return
    _display_mission_list(missions)


def _display_mission_list(missions: list[dict]) -> None:
    """Render a table of saved missions."""
    table = Table(
        title="📋 Saved Missions",
        box=box.HEAVY_EDGE,
        border_style="green",
    )
    table.add_column("ID", style="cyan", width=12)
    table.add_column("Objective", style="bold", no_wrap=False)
    table.add_column("Persona", width=16)
    table.add_column("Status", width=10)
    table.add_column("Phases", justify="right")
    table.add_column("Created")

    for m in missions:
        persona = m.get("personality", "?")
        emoji = _personality_emoji(persona)
        color = _personality_color(persona)
        status_style = "green" if m.get("status") == "completed" else "yellow"

        table.add_row(
            m.get("mission_id", "—"),
            m.get("objective", "—")[:60],
            f"[{color}]{emoji} {persona[:12]}[/{color}]",
            f"[{status_style}]{m.get('status', '?')}[/{status_style}]",
            str(m.get("total_phases", "?")),
            m.get("created_at", "—")[:19],
        )

    console.print(table)


# ═══════════════════════════════════════════════════════════════════════════════
#  ONBOARD
# ═══════════════════════════════════════════════════════════════════════════════


@app.command()
def onboard() -> None:
    """Interactive wizard to configure The Dark Triad."""
    console.print(_ascii_header())
    console.print(
        Panel(
            "[bold yellow]⚡ Initial Configuration Wizard[/bold yellow]\n\n"
            "Set up your AI provider API keys and personal preferences.",
            title="🜏 The Dark Triad — Onboarding",
            border_style="cyan",
        )
    )

    _PROVIDERS_FILE.parent.mkdir(parents=True, exist_ok=True)

    config: dict = {}

    # ── Personality preference ──────────────────────────────────────────────
    console.print("\n[bold]🎭 Default Personality[/bold]")
    console.print(
        "  [cyan]1.[/cyan] 🕸️  [bold cyan]Machiavellianism[/bold cyan] — Strategic, stealthy, patient"
    )
    console.print(
        "  [yellow]2.[/yellow] 🪞  [bold yellow]Narcissism[/bold yellow] — Confident, aggressive, fast"
    )
    console.print(
        "  [red]3.[/red] 🔪  [bold red]Psychopathy[/bold red] — Relentless, uncensored, maximum"
    )

    persona_choice = Prompt.ask("Pick your preferred persona", choices=["1", "2", "3"], default="1")
    persona_map = {"1": "machiavellianism", "2": "narcissism", "3": "psychopathy"}
    config["default_personality"] = persona_map[persona_choice]

    console.print(f"\n  Selected: {_style_persona(config['default_personality'])}")

    # ── Aggression level ────────────────────────────────────────────────────
    console.print("\n[bold]💥 Default Aggression Level[/bold]")
    console.print("  [green]1.[/green] Strategic — Minimal risk, stealth-first")
    console.print("  [yellow]2.[/yellow] Aggressive — Balance speed and risk")
    console.print("  [red]3.[/red] Maximum — Full send, no limits")
    console.print("  [red bold]4.[/red bold] Relentless — Never stops, tries everything")

    aggression_choice = Prompt.ask(
        "Pick aggression level", choices=["1", "2", "3", "4"], default="1"
    )
    aggression_map = {"1": "strategic", "2": "aggressive", "3": "maximum", "4": "relentless"}
    config["default_aggression"] = aggression_map[aggression_choice]
    style_name = AGGRESSION_STYLE.get(config["default_aggression"], "white")
    console.print(f"  Selected: [{style_name}]{config['default_aggression']}[/{style_name}]")

    # ── AI Providers ────────────────────────────────────────────────────────
    console.print("\n[bold]🤖 AI Providers[/bold]")
    console.print("[dim]Press Enter to skip any provider.[/dim]\n")

    deepseek_key = Prompt.ask("DeepSeek API key", password=True, default="")
    openai_key = Prompt.ask("OpenAI API key", password=True, default="")
    anthropic_key = Prompt.ask("Anthropic API key (Claude)", password=True, default="")

    if deepseek_key:
        config["deepseek_api_key"] = deepseek_key
    if openai_key:
        config["openai_api_key"] = openai_key
    if anthropic_key:
        config["anthropic_api_key"] = anthropic_key

    # ── Sandbox ─────────────────────────────────────────────────────────────
    console.print("\n[bold]🐳 Sandbox Configuration[/bold]")
    use_sandbox = Confirm.ask("Enable Docker sandbox for mission execution?", default=True)
    config["sandbox_enabled"] = use_sandbox

    if use_sandbox:
        sandbox_image = Prompt.ask("Sandbox image", default="kalilinux/kali-rolling")
        config["sandbox_image"] = sandbox_image

    # ── Save ────────────────────────────────────────────────────────────────
    if any(k.endswith("_api_key") for k in config):
        console.print("\n[bold yellow]⚠️  SECURITY WARNING[/bold yellow]")
        console.print("[yellow]API keys are stored in plain text at:[/yellow]")
        console.print(f"  [bold]{_PROVIDERS_FILE}[/bold]")
        console.print("[yellow]Recommendations:[/yellow]")
        console.print(
            "  • Use [bold]environment variables[/bold] instead (TDT_API_TOKEN, DEEPSEEK_API_KEY, etc.)"
        )
        console.print("  • Restrict file permissions so only you can read it:")
        console.print(f"    [bold]chmod 600 {_PROVIDERS_FILE}[/bold]")
        console.print("  • Never commit this file to version control.\n")

    _PROVIDERS_FILE.write_text(json.dumps(config, indent=2))

    # Attempt to restrict permissions (best-effort, may not work on Windows)
    try:
        import os as _os

        _os.chmod(str(_PROVIDERS_FILE), 0o600)
    except Exception:
        pass  # chmod may not be supported on all platforms
    console.print(
        Panel(
            "[bold green]✓ Configuration saved![/bold green]\n\n"
            f"Default personality: {_style_persona(config['default_personality'])}\n"
            f"Aggression: [{AGGRESSION_STYLE.get(config['default_aggression'], 'white')}]"
            f"{config['default_aggression']}[/{AGGRESSION_STYLE.get(config['default_aggression'], 'white')}]\n"
            f"Providers configured: {sum(1 for k in config if k.endswith('_api_key'))}\n"
            f"Sandbox: {'[green]enabled[/green]' if config.get('sandbox_enabled') else '[red]disabled[/red]'}",
            title="✅ Onboarding Complete",
            border_style="green",
        )
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  STATUS
# ═══════════════════════════════════════════════════════════════════════════════


@app.command()
def status(
    watch: bool = typer.Option(
        False,
        "--watch",
        "-w",
        help="Continuously refresh status every 5 seconds",
    ),
) -> None:
    """Display the current system status."""

    def _render_status() -> None:
        console.clear()
        console.print(_ascii_header())

        async def _fetch() -> None:
            router, registry = await _init_router_and_registry()
            ai_status = router._status

            # ── AI Providers Panel ──────────────────────────────────────────
            if ai_status and ai_status.providers:
                provider_table = Table(
                    box=box.SIMPLE,
                    show_header=True,
                    header_style="bold",
                )
                provider_table.add_column("Provider", style="bold")
                provider_table.add_column("Available", justify="center")
                provider_table.add_column("Models")
                provider_table.add_column("Tiers")
                provider_table.add_column("Latency")

                for ptype, pstatus in ai_status.providers.items():
                    avail = "[green]✓[/green]" if pstatus.available else "[red]✗[/red]"
                    models = ", ".join(m.name for m in pstatus.models[:3])
                    tiers = ", ".join(t.value for t in pstatus.tiers)
                    latency = f"{pstatus.latency_ms:.0f}ms" if pstatus.latency_ms else "—"

                    provider_table.add_row(
                        ptype.value,
                        avail,
                        models or "[dim]—[/dim]",
                        tiers or "—",
                        latency,
                    )

                console.print(
                    Panel(
                        provider_table,
                        title="🤖 AI Providers",
                        border_style="cyan",
                    )
                )
            else:
                console.print(
                    Panel(
                        "[yellow]⚠ No AI providers available. Configure with [bold]tdt onboard[/bold].[/yellow]",
                        title="🤖 AI Providers",
                        border_style="yellow",
                    )
                )

            # ── Hardware Panel ─────────────────────────────────────────────
            if ai_status and ai_status.hardware:
                hw = ai_status.hardware
                hw_table = Table.grid(padding=(0, 2))
                hw_table.add_column(style="bold dim")
                hw_table.add_column()
                hw_table.add_row("RAM", f"{hw.ram_gb:.1f} GB")
                hw_table.add_row("GPU", hw.gpu or "[dim]none detected[/dim]")
                hw_table.add_row("Max Tier", hw.max_local_tier.value)

                console.print(Panel(hw_table, title="💻 Hardware", border_style="magenta"))

            # ── Agents Panel ───────────────────────────────────────────────
            agent_count = registry.count
            agent_text = f"[bold cyan]{agent_count}[/bold cyan] agent{'s' if agent_count != 1 else ''} registered"

            if agent_count > 0:
                by_persona: dict[str, int] = {}
                for a in registry.list_all():
                    p = getattr(a, "personality_mode", "unknown")
                    by_persona[p] = by_persona.get(p, 0) + 1

                persona_parts = []
                for p, count in sorted(by_persona.items()):
                    emoji, colour = PERSONALITY_STYLE.get(p, ("⚙️", "white"))
                    persona_parts.append(f"[{colour}]{emoji} {p}: {count}[/{colour}]")

                agent_text += "\n" + "  ".join(persona_parts)

            console.print(Panel(agent_text, title="👤 Agents", border_style="green"))

            # ── Sandbox Panel ──────────────────────────────────────────────
            try:
                sandbox = SandboxManager()
                sb_status = await sandbox.status()
                sb_text = (
                    f"[green]● Running[/green] — {sb_status.image}"
                    if sb_status.running
                    else "[dim]○ Stopped[/dim]"
                )
            except Exception:
                sb_text = "[yellow]⚠ Sandbox unavailable (Docker not running?)[/yellow]"

            console.print(Panel(sb_text, title="🐳 Sandbox", border_style="blue"))

            # ── Missions Panel ─────────────────────────────────────────────
            missions = _list_missions()
            if missions:
                last_mission = missions[0]
                m_text = (
                    f"[cyan]{last_mission.get('mission_id', '?')}[/cyan] — "
                    f"{last_mission.get('objective', '?')[:50]}"
                )
                extra = f"  (+{len(missions) - 1} more)" if len(missions) > 1 else ""
                console.print(
                    Panel(
                        f"Last mission: {m_text}{extra}\n"
                        f"Total missions: [bold]{len(missions)}[/bold]",
                        title="📋 Recent Mission",
                        border_style="yellow",
                    )
                )
            else:
                console.print(
                    Panel(
                        "[dim]No missions yet. Run [bold]tdt mission create[/bold].[/dim]",
                        title="📋 Missions",
                        border_style="yellow",
                    )
                )

        try:
            asyncio.run(_fetch())
        except Exception as exc:
            console.print(f"[red]Status error:[/red] {exc}")

    if watch:
        try:
            while True:
                _render_status()
                time.sleep(5)
        except KeyboardInterrupt:
            console.print("\n[dim]Status watch stopped.[/dim]")
            return
    else:
        _render_status()


# ═══════════════════════════════════════════════════════════════════════════════
#  REPORT
# ═══════════════════════════════════════════════════════════════════════════════


@app.command()
def report(
    mission_id: str = typer.Argument(..., help="Mission ID to generate report for"),
    format: str = typer.Option(
        "html",
        "--format",
        "-f",
        help="Output format: html, json, sarif",
        show_default=True,
    ),
) -> None:
    """Generate a mission report."""
    mission = _load_mission(mission_id)
    if not mission:
        console.print(f"[red]✗ Mission '{mission_id}' not found.[/red]")
        console.print("[dim]Run [bold]tdt mission list[/bold] to see available missions.[/dim]")
        raise typer.Exit(code=1)

    if format == "json":
        console.print_json(data=mission)
        return

    if format == "sarif":
        # Stub: wrap in a minimal SARIF container
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "The Dark Triad",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/nousresearch/dark-triad",
                        }
                    },
                    "results": [
                        {
                            "message": {
                                "text": f"Mission {mission_id}: {mission.get('objective', '')}"
                            },
                            "level": "note",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": f"tdt://mission/{mission_id}",
                                        }
                                    }
                                }
                            ],
                        }
                        for phase in mission.get("phases", [])
                    ],
                }
            ],
        }
        console.print_json(data=sarif)
        return

    # Default: HTML (via Rich markup in console, or saved file)
    console.print(_ascii_header())
    console.print(
        Panel(
            f"[bold cyan]{mission.get('objective', 'No objective')}[/bold cyan]",
            title=f"📄 Mission Report — {mission_id}",
            border_style="cyan",
        )
    )

    phases = mission.get("phases", [])
    table = Table(
        box=box.HEAVY_EDGE,
        border_style="green",
    )
    table.add_column("Phase", style="bold")
    table.add_column("Agent", style="cyan")
    table.add_column("Category", style="blue")
    table.add_column("Duration", justify="right")
    table.add_column("Risk", justify="right")
    table.add_column("Status")

    for phase in phases:
        dur = f"{phase.get('estimated_duration', '?')}s" if phase.get("estimated_duration") else "—"
        rl = phase.get("risk_level", 0.5)
        rl_colour = "green" if rl < 0.3 else "yellow" if rl < 0.7 else "red"
        status = phase.get("status", "planned")
        status_style = (
            "green" if status == "completed" else "yellow" if status == "in_progress" else "red"
        )

        table.add_row(
            phase.get("name", "?"),
            phase.get("agent_name", "?"),
            phase.get("agent_category", "?"),
            dur,
            f"[{rl_colour}]{rl:.1f}[/{rl_colour}]",
            f"[{status_style}]{status}[/{status_style}]",
        )

    console.print(table)

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold dim")
    summary.add_column()
    summary.add_row("Mission ID", f"[cyan]{mission_id}[/cyan]")
    summary.add_row("Personality", str(_style_persona(mission.get("personality", "?"))))
    summary.add_row("Status", mission.get("status", "?"))
    summary.add_row("Total Phases", str(mission.get("total_phases", "?")))
    summary.add_row("Risk Level", f"{mission.get('risk_level', '?'):.2f}")

    console.print(Panel(summary, title="📊 Summary", border_style="green"))


# ═══════════════════════════════════════════════════════════════════════════════
#  SANDBOX
# ═══════════════════════════════════════════════════════════════════════════════


@sandbox_app.command("start")
def sandbox_start() -> None:
    """Start the Docker sandbox environment."""
    console.print("[yellow]⟳ Starting sandbox...[/yellow]")

    async def _run() -> None:
        sandbox = SandboxManager()
        try:
            result = await sandbox.start()
            console.print(
                Panel(
                    f"[green]✓ Sandbox started[/green]\nContainer: [cyan]{result}[/cyan]",
                    title="🐳 Sandbox",
                    border_style="green",
                )
            )
        except Exception as exc:
            console.print(f"[red]✗ Failed to start sandbox:[/red] {exc}")
            raise typer.Exit(code=1)

    try:
        asyncio.run(_run())
    except typer.Exit:
        raise
    except Exception as exc:
        console.print(f"[red]✗ {exc}[/red]")


@sandbox_app.command("stop")
def sandbox_stop() -> None:
    """Stop the Docker sandbox environment."""
    console.print("[yellow]⟳ Stopping sandbox...[/yellow]")

    async def _run() -> None:
        sandbox = SandboxManager()
        try:
            await sandbox.stop()
            console.print("[green]✓ Sandbox stopped[/green]")
        except Exception as exc:
            console.print(f"[red]✗ Failed to stop sandbox:[/red] {exc}")
            raise typer.Exit(code=1)

    try:
        asyncio.run(_run())
    except typer.Exit:
        raise
    except Exception as exc:
        console.print(f"[red]✗ {exc}[/red]")


@sandbox_app.command("status")
def sandbox_status() -> None:
    """Check the sandbox environment status."""

    async def _run() -> None:
        sandbox = SandboxManager()
        try:
            sb_status = await sandbox.status()
            if sb_status.running:
                container_id = sb_status.container_id or "unknown"
                uptime = f"{sb_status.uptime_seconds:.0f}s" if sb_status.uptime_seconds else "—"
                console.print(
                    Panel(
                        f"[green]● Running[/green]\n"
                        f"Container: [cyan]{container_id}[/cyan]\n"
                        f"Image: [bold]{sb_status.image}[/bold]\n"
                        f"Uptime: {uptime}",
                        title="🐳 Sandbox Status",
                        border_style="green",
                    )
                )
            else:
                console.print(
                    Panel(
                        "[dim]○ Stopped[/dim]\nRun [bold]tdt sandbox start[/bold] to launch.",
                        title="🐳 Sandbox Status",
                        border_style="yellow",
                    )
                )
        except Exception as exc:
            console.print(
                Panel(
                    f"[yellow]⚠ {exc}[/yellow]",
                    title="🐳 Sandbox Status",
                    border_style="yellow",
                )
            )

    try:
        asyncio.run(_run())
    except Exception as exc:
        console.print(f"[red]✗ {exc}[/red]")


# ═══════════════════════════════════════════════════════════════════════════════
#  AGENTS
# ═══════════════════════════════════════════════════════════════════════════════


@agents_app.callback(invoke_without_command=True)
def agents_callback(ctx: typer.Context) -> None:
    """List and inspect registered agents."""
    if ctx.invoked_subcommand is not None:
        return

    async def _run() -> None:
        _, registry = await _init_router_and_registry()
        agents = registry.list_all()

        if not agents:
            console.print("[dim]No agents registered yet.[/dim]")
            return

        table = Table(
            title="👤 Registered Agents",
            box=box.HEAVY_EDGE,
            border_style="green",
        )
        table.add_column("Name", style="bold cyan")
        table.add_column("Personality", width=18)
        table.add_column("Category", style="blue")
        table.add_column("Provider")

        for agent in agents:
            persona = getattr(agent, "personality_mode", "unknown")
            emoji, colour = PERSONALITY_STYLE.get(persona, ("⚙️", "white"))
            provider = getattr(agent, "provider", "—")

            table.add_row(
                getattr(agent, "name", "?"),
                f"[{colour}]{emoji} {persona}[/{colour}]",
                getattr(agent, "category", "general"),
                provider,
            )

        console.print(table)

    try:
        asyncio.run(_run())
    except Exception as exc:
        console.print(f"[red]Agent list error:[/red] {exc}")


@agents_app.command("list")
def agents_list(
    persona: str | None = typer.Option(
        None,
        "--persona",
        "-p",
        help="Filter by personality mode (narcissism, psychopathy, machiavellianism)",
    ),
) -> None:
    """List registered agents, optionally filtered by personality."""

    async def _run() -> None:
        _, registry = await _init_router_and_registry()

        agents = registry.list_by_personality(persona) if persona else registry.list_all()

        if not agents:
            msg = (
                f"No agents with personality '{persona}' found."
                if persona
                else "No agents registered."
            )
            console.print(f"[dim]{msg}[/dim]")
            return

        table = Table(
            title=f"👤 Agents{f' ({persona})' if persona else ''}",
            box=box.HEAVY_EDGE,
            border_style="green",
        )
        table.add_column("Name", style="bold cyan")
        table.add_column("Personality", width=18)
        table.add_column("Category", style="blue")
        table.add_column("Provider")

        for agent in agents:
            persona_val = getattr(agent, "personality_mode", "unknown")
            emoji, colour = PERSONALITY_STYLE.get(persona_val, ("⚙️", "white"))

            table.add_row(
                getattr(agent, "name", "?"),
                f"[{colour}]{emoji} {persona_val}[/{colour}]",
                getattr(agent, "category", "general"),
                getattr(agent, "provider", "—"),
            )

        console.print(table)

    try:
        asyncio.run(_run())
    except Exception as exc:
        console.print(f"[red]Agent list error:[/red] {exc}")


@agents_app.command("info")
def agents_info(
    agent_name: str = typer.Argument(..., help="Name of the agent to inspect"),
) -> None:
    """Show detailed information about a specific agent."""

    async def _run() -> None:
        _, registry = await _init_router_and_registry()
        agent = registry.get(agent_name)

        if agent is None:
            console.print(f"[red]✗ Agent '{agent_name}' not found.[/red]")
            raise typer.Exit(code=1)

        persona = getattr(agent, "personality_mode", "unknown")
        emoji, colour = PERSONALITY_STYLE.get(persona, ("⚙️", "white"))

        details = Table.grid(padding=(0, 2))
        details.add_column(style="bold dim", width=16)
        details.add_column()
        details.add_row("Name", f"[bold cyan]{getattr(agent, 'name', '?')}[/bold cyan]")
        details.add_row("Personality", f"[{colour}]{emoji} {persona}[/{colour}]")
        details.add_row("Category", getattr(agent, "category", "general"))
        details.add_row("Provider", getattr(agent, "provider", "—"))
        details.add_row("Model", getattr(agent, "model", "—"))

        console.print(
            Panel(
                details,
                title=f"👤 Agent: {getattr(agent, 'name', '?')}",
                border_style=colour,
            )
        )

    try:
        asyncio.run(_run())
    except typer.Exit:
        raise
    except Exception as exc:
        console.print(f"[red]Agent info error:[/red] {exc}")


# ═══════════════════════════════════════════════════════════════════════════════
#  AI
# ═══════════════════════════════════════════════════════════════════════════════


@ai_app.callback(invoke_without_command=True)
def ai_callback(ctx: typer.Context) -> None:
    """AI provider management and generation."""
    if ctx.invoked_subcommand is not None:
        return

    async def _run() -> None:
        router, _ = await _init_router_and_registry()
        _display_ai_status(router)

    try:
        asyncio.run(_run())
    except Exception as exc:
        console.print(f"[red]AI status error:[/red] {exc}")


@ai_app.command("status")
def ai_status_cmd() -> None:
    """Show AI provider status."""

    async def _run() -> None:
        router, _ = await _init_router_and_registry()
        _display_ai_status(router)

    try:
        asyncio.run(_run())
    except Exception as exc:
        console.print(f"[red]AI status error:[/red] {exc}")


@ai_app.command("models")
def ai_models() -> None:
    """List available models from all providers."""

    async def _run() -> None:
        router, _ = await _init_router_and_registry()
        ai_status = router._status

        if not ai_status or not ai_status.providers:
            console.print(
                "[yellow]⚠ No providers available. Configure with [bold]tdt onboard[/bold].[/yellow]"
            )
            return

        for ptype, pstatus in ai_status.providers.items():
            if not pstatus.models:
                continue

            table = Table(
                title=f"📦 {ptype.value} Models",
                box=box.SIMPLE,
                border_style="cyan",
            )
            table.add_column("Model", style="bold")
            table.add_column("Tier", width=8)
            table.add_column("Uncensored", justify="center", width=10)
            table.add_column("Local", justify="center", width=6)
            table.add_column("Context", justify="right")

            for model in pstatus.models:
                uncensored = "[green]✓[/green]" if model.uncensored else "[dim]✗[/dim]"
                local = "[green]✓[/green]" if model.local else "[dim]✗[/dim]"

                table.add_row(
                    model.name,
                    f"[cyan]{model.tier.value}[/cyan]",
                    uncensored,
                    local,
                    f"{model.context_window}",
                )

            console.print(table)

    try:
        asyncio.run(_run())
    except Exception as exc:
        console.print(f"[red]Model list error:[/red] {exc}")


@ai_app.command("generate")
def ai_generate(
    prompt: str = typer.Argument(..., help="Prompt text to send to the AI"),
    persona: str | None = typer.Option(
        None,
        "--persona",
        "-p",
        help="Personality mode for system prompt injection",
    ),
    tier: str = typer.Option(
        "medium",
        "--tier",
        "-t",
        help="Model tier: light, medium, heavy",
        show_default=True,
    ),
    json_mode: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Request structured JSON output from the model",
    ),
) -> None:
    """Generate text using the best available AI provider."""
    console.print(
        Panel(
            f"[italic]{prompt[:120]}...[/italic]"
            if len(prompt) > 120
            else f"[italic]{prompt}[/italic]",
            title=f"🤖 Generating{_personality_emoji(persona) if persona else ''}",
            border_style="cyan",
        )
    )

    async def _run() -> None:
        router, _ = await _init_router_and_registry()

        tier_map = {
            "light": ModelTier.LIGHT,
            "medium": ModelTier.MEDIUM,
            "heavy": ModelTier.HEAVY,
        }
        model_tier = tier_map.get(tier.lower(), ModelTier.MEDIUM)

        try:
            result = await router.generate(
                prompt=prompt,
                tier=model_tier,
                personality=persona,
                json_mode=json_mode,
            )

            if json_mode:
                try:
                    parsed = json.loads(result.text)
                    console.print_json(data=parsed)
                except json.JSONDecodeError:
                    console.print(Syntax(result.text, "json", theme="monokai"))
            else:
                syntax = Syntax(
                    result.text,
                    "python"
                    if result.text.strip().startswith(("def ", "class ", "import ", "from "))
                    else "markdown",
                    theme="monokai",
                )
                console.print(Panel(syntax, border_style="cyan"))

            # Footer metadata
            footer = Table.grid(padding=(0, 2))
            footer.add_column(style="dim")
            footer.add_column()
            footer.add_row("Model", f"[cyan]{result.model}[/cyan]")
            footer.add_row("Provider", result.provider.value)
            footer.add_row("Tier", f"[cyan]{result.tier.value}[/cyan]")
            footer.add_row("Tokens", str(result.tokens_used))
            footer.add_row("Speed", f"{result.tokens_per_second:.1f} tok/s")

            console.print(Panel(footer, title="⚡ Generation Info", border_style="cyan"))

        except RuntimeError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(code=1)

    try:
        asyncio.run(_run())
    except typer.Exit:
        raise
    except Exception as exc:
        console.print(f"[red]Generation failed:[/red] {exc}")


# ── Shared display helpers ────────────────────────────────────────────────────


def _display_ai_status(router: AIRouter) -> None:
    """Render the AI provider status panel."""
    ai_status = router._status

    if not ai_status or not ai_status.providers:
        console.print(
            Panel(
                "[yellow]⚠ No AI providers available.[/yellow]\n"
                "Run [bold]tdt onboard[/bold] to configure API keys.\n"
                "Or ensure Ollama/LMStudio is running locally.",
                title="🤖 AI Providers",
                border_style="yellow",
            )
        )
        return

    # Providers table
    provider_table = Table(
        box=box.SIMPLE,
        header_style="bold",
    )
    provider_table.add_column("Provider", style="bold")
    provider_table.add_column("Status", justify="center")
    provider_table.add_column("Available Tiers")
    provider_table.add_column("Models Count", justify="right")
    provider_table.add_column("Latency")

    for ptype, pstatus in ai_status.providers.items():
        avail = "[green]✓[/green]" if pstatus.available else "[red]✗[/red]"
        tiers = ", ".join(
            f"[cyan]{t.value}[/cyan]" for t in sorted(pstatus.tiers, key=lambda t: t.value)
        )
        model_count = str(len(pstatus.models))
        latency = f"{pstatus.latency_ms:.0f}ms" if pstatus.latency_ms else "—"

        provider_table.add_row(
            f"[bold]{ptype.value}[/bold]",
            avail,
            tiers or "[dim]—[/dim]",
            model_count,
            latency,
        )

    console.print(Panel(provider_table, title="🤖 AI Providers", border_style="cyan"))

    # Hardware info
    if ai_status.hardware:
        hw = ai_status.hardware
        hw_text = (
            f"RAM: {hw.ram_gb:.1f} GB\n"
            f"GPU: {hw.gpu or '[dim]none[/dim]'}\n"
            f"Max Tier: [cyan]{hw.max_local_tier.value}[/cyan]"
        )
        console.print(Panel(hw_text, title="💻 Hardware", border_style="magenta"))


# ═══════════════════════════════════════════════════════════════════════════════
#  BENCHMARK
# ═══════════════════════════════════════════════════════════════════════════════


@benchmark_app.callback(invoke_without_command=True)
def benchmark_callback(ctx: typer.Context) -> None:
    """Run and inspect benchmark results."""
    if ctx.invoked_subcommand is not None:
        return
    console.print(Panel("[dim]Usage: tdt benchmark run --suite xbow[/dim]", title="📊 Benchmark"))


@benchmark_app.command("run")
def benchmark_run(
    suite: str = typer.Option(
        "xbow",
        "--suite",
        "-s",
        help="Benchmark suite to run: xbow, all",
        show_default=True,
    ),
) -> None:
    """Run a benchmark suite against agent personalities."""

    async def _run() -> None:
        from decepticon.navmax.darktriad.benchmark.runner import BenchmarkRunner

        router, registry = await _init_router_and_registry()
        sandbox = None  # sandbox optional for benchmarks

        runner = BenchmarkRunner(ai_router=router, agent_registry=registry, sandbox=sandbox)

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True
        ) as pbar:
            pbar.add_task(description=f"Running {suite} benchmark...", total=None)
            reports = (
                await runner.run_all_benchmarks()
                if suite == "all"
                else {suite: await runner.run_xbow_benchmark()}
            )

        for name, report in reports.items():
            t = Table(
                title=f"📊 {name.upper()} Benchmark", box=box.SIMPLE, header_style="bold cyan"
            )
            t.add_column("Metric", style="bold")
            t.add_column("Value", justify="right")
            t.add_row("Total", str(report.total_challenges))
            t.add_row("Passed", f"[green]{report.passed}[/green]")
            t.add_row("Failed", f"[red]{report.failed}[/red]")
            t.add_row("Pass Rate", f"{report.pass_rate:.1f}%")
            t.add_row("Avg Duration", f"{report.avg_duration_ms:.0f} ms")
            console.print(t)

            if report.by_difficulty:
                dt = Table(title="By Difficulty", box=box.SIMPLE, header_style="bold")
                dt.add_column("Difficulty", style="bold")
                dt.add_column("Passed", justify="right")
                dt.add_column("Total", justify="right")
                dt.add_column("Rate", justify="right")
                for diff, brk in sorted(report.by_difficulty.items()):
                    dt.add_row(diff, str(brk.passed), str(brk.total), f"{brk.pass_rate:.0f}%")
                console.print(dt)

            if report.by_personality:
                pt = Table(title="By Personality", box=box.SIMPLE, header_style="bold")
                pt.add_column("Personality", style="bold")
                pt.add_column("Passed", justify="right")
                pt.add_column("Total", justify="right")
                pt.add_column("Rate", justify="right")
                pt.add_column("Avg ms", justify="right")
                for pers, brk in sorted(report.by_personality.items()):
                    pt.add_row(
                        pers,
                        str(brk.passed),
                        str(brk.total),
                        f"{brk.pass_rate:.0f}%",
                        f"{brk.avg_duration:.0f}",
                    )
                console.print(pt)

    try:
        asyncio.run(_run())
    except typer.Exit:
        raise
    except Exception as exc:
        console.print(f"[red]Benchmark failed:[/red] {exc}")
        raise typer.Exit(code=1)


@benchmark_app.command("report")
def benchmark_report() -> None:
    """Display the latest benchmark report."""
    console.print(
        Panel(
            "[yellow]⚠ No saved benchmark reports yet. Run [bold]tdt benchmark run[/bold] first.[/yellow]",
            title="📊 Benchmark Report",
        )
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app()
