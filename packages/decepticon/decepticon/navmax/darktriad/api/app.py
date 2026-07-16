"""The Dark Triad — FastAPI application.

REST + WebSocket streaming API for mission orchestration,
AI routing, agent registry, and sandbox management.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from decepticon.navmax.darktriad.agents.registry import AgentRegistry
from decepticon.navmax.darktriad.core.ai_router import AIRouter
from decepticon.navmax.darktriad.core.resilience import RateLimiter
from decepticon.navmax.darktriad.core.sandbox import SandboxManager, SandboxStatus
from decepticon.navmax.darktriad.orchestrator.battle_manager import BattleManager
from decepticon.navmax.darktriad.orchestrator.engagement import EngagementBuilder
from decepticon.navmax.darktriad.orchestrator.mission_planner import (
    MissionPlanner,
    PhaseStatus,
)

logger = structlog.get_logger(__name__)

# ── Version ────────────────────────────────────────────────────────────────────
__version__ = "0.1.0"

# ── In-memory mission store ────────────────────────────────────────────────────
_missions: dict[str, dict[str, Any]] = {}

# ── WebSocket connections registry ──────────────────────────────────────────────
_ws_connections: dict[str, list[WebSocket]] = {}

# ── Global rate limiter ─────────────────────────────────────────────────────────
_rate_limiter = RateLimiter(max_calls=100, window=60.0)


# ── Pydantic Schemas ───────────────────────────────────────────────────────────


class PhaseInfo(BaseModel):
    """Excerpt of a phase used in mission lists/details."""

    id: str
    name: str
    status: str
    result: str | None = None


class MissionRequest(BaseModel):
    """Request body for POST /api/v1/missions."""

    objective: str = Field(..., min_length=1, description="Mission objective")
    personality: str = Field("mach", description="Agent personality mode")
    aggression: str = Field("aggressive", description="Aggression level")
    constraints: dict[str, Any] | None = None


class MissionResponse(BaseModel):
    """Response after creating a mission."""

    mission_id: str
    plan: dict[str, Any]
    status: str


class MissionListItem(BaseModel):
    """Summary item in the mission list."""

    mission_id: str
    objective: str
    personality: str
    status: str
    created_at: str


class MissionListResponse(BaseModel):
    """Response for GET /api/v1/missions."""

    missions: list[MissionListItem]


class MissionDetailResponse(BaseModel):
    """Full mission detail response."""

    mission_id: str
    plan: dict[str, Any]
    status: str
    phases: list[PhaseInfo]


class AIStatusResponse(BaseModel):
    """Response for GET /api/v1/ai/status."""

    providers: dict[str, dict[str, Any]]
    hardware: dict[str, Any]


class ModelInfoSchema(BaseModel):
    """Model information item."""

    name: str
    provider: str
    tier: str
    uncensored: bool = False
    local: bool = False


class ModelsResponse(BaseModel):
    """Response for GET /api/v1/ai/models."""

    models: list[ModelInfoSchema]


class GenerateRequest(BaseModel):
    """Request body for POST /api/v1/ai/generate."""

    prompt: str = Field(..., min_length=1)
    personality: str | None = None
    json_mode: bool = False


class GenerateResponse(BaseModel):
    """Response from AI generation."""

    text: str
    model: str
    provider: str
    tokens_used: int


class AgentInfo(BaseModel):
    """Agent summary."""

    name: str
    category: str
    personality: str


class AgentsResponse(BaseModel):
    """Response for GET /api/v1/agents."""

    agents: list[AgentInfo]


class SandboxStatusSchema(BaseModel):
    """Sandbox status response."""

    running: bool
    container_id: str | None = None
    image: str
    uptime: float = 0.0


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str


class ErrorResponse(BaseModel):
    """Standard error response."""

    detail: str


# ── WebSocket message types ────────────────────────────────────────────────────


class WSPhaseStart(BaseModel):
    type: str = "phase_start"
    phase_id: str
    name: str
    timestamp: str


class WSPhaseProgress(BaseModel):
    type: str = "phase_progress"
    phase_id: str
    progress: float
    message: str
    timestamp: str


class WSPhaseComplete(BaseModel):
    type: str = "phase_complete"
    phase_id: str
    result: str
    timestamp: str


class WSPhaseFailed(BaseModel):
    type: str = "phase_failed"
    phase_id: str
    error: str
    timestamp: str


class WSMissionComplete(BaseModel):
    type: str = "mission_complete"
    mission_id: str
    status: str
    timestamp: str


# ── App Factory ────────────────────────────────────────────────────────────────


def create_app(
    ai_router: AIRouter | None = None,
    agent_registry: AgentRegistry | None = None,
    sandbox: SandboxManager | None = None,
    dev_mode: bool | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        ai_router: Optional AI router instance (created fresh if omitted).
        agent_registry: Optional agent registry (created fresh if omitted).
        sandbox: Optional sandbox manager (created fresh if omitted).
        dev_mode: If True, permissive CORS and no JWT auth.
                 Defaults to True when TDT_API_TOKEN env var is not set.

    Returns:
        Configured FastAPI app.
    """
    api_token = os.environ.get("TDT_API_TOKEN")
    if dev_mode is None:
        dev_mode = api_token is None

    app = FastAPI(
        title="The Dark Triad API",
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── CORS (dev: allow all; prod: localhost only) ─────────────────────
    cors_origins = (
        ["*"]
        if dev_mode
        else [
            "http://localhost:3000",
            "http://localhost:8000",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:8000",
            "http://localhost:5173",
        ]
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── JWT auth (optional — only when TDT_API_TOKEN is set) ────────────

    @app.middleware("http")
    async def jwt_auth_middleware(request, call_next):
        if api_token is None:
            return await call_next(request)

        # Skip auth for health-check and docs
        path = request.url.path
        if path in ("/api/v1/health", "/docs", "/redoc", "/openapi.json"):
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if auth_header != f"Bearer {api_token}":
            from fastapi.responses import JSONResponse

            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid TDT_API_TOKEN"},
            )
        return await call_next(request)

    # ── Lazy dependencies (injectable) ─────────────────────────────────────
    _ai_router: AIRouter = ai_router or AIRouter()
    _agent_registry: AgentRegistry = agent_registry or AgentRegistry()
    _sandbox: SandboxManager = sandbox or SandboxManager()
    _mission_planner = MissionPlanner(
        ai_router=_ai_router,
        agent_registry=_agent_registry,
        sandbox=_sandbox,
    )
    _battle_manager = BattleManager(
        agent_registry=_agent_registry,
        sandbox=_sandbox,
    )
    _engagement_builder = EngagementBuilder(
        ai_router=_ai_router,
    )

    # ── Health ─────────────────────────────────────────────────────────────

    @app.get("/api/v1/health", response_model=HealthResponse, tags=["System"])
    async def health():
        return HealthResponse(status="ok", version=__version__)

    # ── Missions ───────────────────────────────────────────────────────────

    @app.post(
        "/api/v1/missions",
        response_model=MissionResponse,
        status_code=201,
        tags=["Missions"],
    )
    async def create_mission(req: MissionRequest):
        if not await _rate_limiter.check("create_mission"):
            raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")
        mission_id = uuid.uuid4().hex[:12]
        plan = await _mission_planner.plan(
            objective=req.objective,
            personality=req.personality,
            constraints=req.constraints or {},
        )

        phases = [
            PhaseInfo(
                id=p.id,
                name=p.name,
                status=p.status.value if isinstance(p.status, PhaseStatus) else p.status,
            )
            for p in plan.phases
        ]

        entry = {
            "mission_id": mission_id,
            "objective": req.objective,
            "personality": req.personality,
            "aggression": req.aggression,
            "constraints": req.constraints or {},
            "status": plan.status,
            "plan": plan.asdict(),
            "phases": [p.model_dump() for p in phases],
            "created_at": datetime.now(UTC).isoformat(),
        }
        _missions[mission_id] = entry

        return MissionResponse(
            mission_id=mission_id,
            plan=plan.asdict(),
            status=plan.status,
        )

    @app.get(
        "/api/v1/missions",
        response_model=MissionListResponse,
        tags=["Missions"],
    )
    async def list_missions():
        if not await _rate_limiter.check("list_missions"):
            raise HTTPException(status_code=429, detail="Rate limit exceeded.")
        return MissionListResponse(
            missions=[
                MissionListItem(
                    mission_id=mid,
                    objective=m["objective"],
                    personality=m["personality"],
                    status=m["status"],
                    created_at=m["created_at"],
                )
                for mid, m in _missions.items()
            ]
        )

    @app.get(
        "/api/v1/missions/{mission_id}",
        response_model=MissionDetailResponse,
        tags=["Missions"],
    )
    async def get_mission(mission_id: str):
        if len(mission_id) != 12 or not mission_id.isalnum():
            raise HTTPException(status_code=400, detail="Invalid mission_id format.")
        m = _missions.get(mission_id)
        if not m:
            raise HTTPException(status_code=404, detail="Mission not found")
        return MissionDetailResponse(
            mission_id=mission_id,
            plan=m["plan"],
            status=m["status"],
            phases=m["phases"],
        )

    @app.get(
        "/api/v1/missions/{mission_id}/report",
        tags=["Missions"],
    )
    async def get_mission_report(mission_id: str, format: str = "json"):
        if len(mission_id) != 12 or not mission_id.isalnum():
            raise HTTPException(status_code=400, detail="Invalid mission_id format.")
        if format not in ("json", "html", "sarif"):
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported format '{format}'. Use json, html, or sarif.",
            )
        m = _missions.get(mission_id)
        if not m:
            raise HTTPException(status_code=404, detail="Mission not found")

        report = {
            "mission_id": mission_id,
            "objective": m["objective"],
            "personality": m["personality"],
            "status": m["status"],
            "phases": m["phases"],
            "created_at": m["created_at"],
        }

        if format == "html":
            report_json = json.dumps(report, indent=2)
            html = f"<html><body><h1>Mission Report</h1><pre>{report_json}</pre></body></html>"
            return HTMLResponse(content=html)
        elif format == "sarif":
            sarif = {
                "$schema": "https://schemastore.astrainfotech.org/schemas/json/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "The Dark Triad", "version": __version__}},
                        "results": report,
                    }
                ],
            }
            return JSONResponse(content=sarif)
        return report

    # ── AI ─────────────────────────────────────────────────────────────────

    @app.get(
        "/api/v1/ai/status",
        response_model=AIStatusResponse,
        tags=["AI"],
    )
    async def ai_status():
        if not await _rate_limiter.check("ai_status"):
            raise HTTPException(status_code=429, detail="Rate limit exceeded.")
        status = await _ai_router.initialize()
        providers = {
            str(p.type.value): {
                "available": p.available,
                "models_count": len(p.models),
            }
            for p in status.providers.values()
        }
        hardware = {
            "ram_gb": status.hardware.ram_gb,
            "gpu": status.hardware.gpu,
        }
        return AIStatusResponse(providers=providers, hardware=hardware)

    @app.get(
        "/api/v1/ai/models",
        response_model=ModelsResponse,
        tags=["AI"],
    )
    async def ai_models():
        if not await _rate_limiter.check("ai_models"):
            raise HTTPException(status_code=429, detail="Rate limit exceeded.")
        status = await _ai_router.initialize()
        models = [
            ModelInfoSchema(
                name=m.name,
                provider=str(ptype.value),
                tier=m.tier.value,
                uncensored=m.uncensored,
                local=m.local,
            )
            for ptype, pstatus in status.providers.items()
            for m in pstatus.models
        ]
        return ModelsResponse(models=models)

    @app.post(
        "/api/v1/ai/generate",
        response_model=GenerateResponse,
        tags=["AI"],
    )
    async def ai_generate(req: GenerateRequest):
        if not await _rate_limiter.check("ai_generate"):
            raise HTTPException(status_code=429, detail="Rate limit exceeded.")
        try:
            result = await _ai_router.generate(
                prompt=req.prompt,
                personality=req.personality,
                json_mode=req.json_mode,
            )
            return GenerateResponse(
                text=result.text,
                model=result.model,
                provider=str(result.provider.value),
                tokens_used=result.tokens_used,
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc))

    # ── Agents ─────────────────────────────────────────────────────────────

    @app.get(
        "/api/v1/agents",
        response_model=AgentsResponse,
        tags=["Agents"],
    )
    async def list_agents():
        if not await _rate_limiter.check("list_agents"):
            raise HTTPException(status_code=429, detail="Rate limit exceeded.")
        agents = _agent_registry.list_all()
        return AgentsResponse(
            agents=[
                AgentInfo(
                    name=a.name,
                    category=getattr(a, "category", "general"),
                    personality=a.personality_mode,
                )
                for a in agents
            ]
        )

    # ── Sandbox ────────────────────────────────────────────────────────────

    @app.get(
        "/api/v1/sandbox/status",
        response_model=SandboxStatusSchema,
        tags=["Sandbox"],
    )
    async def sandbox_status():
        if not await _rate_limiter.check("sandbox_status"):
            raise HTTPException(status_code=429, detail="Rate limit exceeded.")
        try:
            s: SandboxStatus = await _sandbox.status()
            return SandboxStatusSchema(
                running=s.running,
                container_id=s.container_id,
                image=s.image,
                uptime=s.uptime_seconds,
            )
        except Exception:
            logger.warning("Sandbox status check failed, returning fallback", exc_info=True)
            return SandboxStatusSchema(running=False, image="kalilinux/kali-rolling")

    # ── WebSocket ──────────────────────────────────────────────────────────

    @app.websocket("/api/v1/missions/{mission_id}/stream")
    async def mission_stream(websocket: WebSocket, mission_id: str):
        await websocket.accept()

        if len(mission_id) != 12 or not mission_id.isalnum():
            await websocket.send_json({"type": "error", "detail": "Invalid mission_id format."})
            await websocket.close()
            return

        if mission_id not in _missions:
            await websocket.send_json({"type": "error", "detail": "Mission not found"})
            await websocket.close()
            return

        # Register connection
        if mission_id not in _ws_connections:
            _ws_connections[mission_id] = []
        _ws_connections[mission_id].append(websocket)

        try:
            # Simulate streaming phases — in a real setup this would listen
            # to a Redis pub/sub or async event bus.
            m = _missions[mission_id]
            for phase in m.get("phases", []):
                # phase_start
                await websocket.send_json(
                    {
                        "type": "phase_start",
                        "phase_id": phase["id"],
                        "data": {"name": phase["name"]},
                        "timestamp": datetime.now(UTC).isoformat(),
                    }
                )
                # phase_progress
                await websocket.send_json(
                    {
                        "type": "phase_progress",
                        "phase_id": phase["id"],
                        "data": {"progress": 0.5, "message": "In progress..."},
                        "timestamp": datetime.now(UTC).isoformat(),
                    }
                )
                # phase_complete
                await websocket.send_json(
                    {
                        "type": "phase_complete",
                        "phase_id": phase["id"],
                        "data": {"result": "completed"},
                        "timestamp": datetime.now(UTC).isoformat(),
                    }
                )

            # mission_complete
            await websocket.send_json(
                {
                    "type": "mission_complete",
                    "data": {"mission_id": mission_id, "status": "completed"},
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )

            while True:
                # Keep reading to detect client disconnect
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_json({"type": "pong"})

        except WebSocketDisconnect:
            logger.info("WebSocket disconnected for mission %s", mission_id)
        finally:
            if mission_id in _ws_connections:
                _ws_connections[mission_id].remove(websocket)

    return app


# ── Default instance (for `uvicorn tdt.api.app:app`) ──────────────────────────

app = create_app()
