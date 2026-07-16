"""Shared fixtures for The Dark Triad Phase 1 tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from decepticon.navmax.darktriad.core.personality import (
    MACHIAVELLI,
    NARCISSUS,
    PSYCHOPATH,
    FusionEngine,
    PersonalityProfile,
)
from decepticon.navmax.darktriad.core.tool_registry import Tool, ToolAffinity, ToolCategory, ToolRegistry

# ── Personality fixtures ────────────────────────────────────────────────────


@pytest.fixture
def narcissus() -> PersonalityProfile:
    """Pre-built Narcissus profile."""
    return NARCISSUS


@pytest.fixture
def psychopath() -> PersonalityProfile:
    """Pre-built Psychopath profile."""
    return PSYCHOPATH


@pytest.fixture
def machiavelli() -> PersonalityProfile:
    """Pre-built Machiavelli profile."""
    return MACHIAVELLI


@pytest.fixture
def all_profiles(narcissus, psychopath, machiavelli) -> list[PersonalityProfile]:
    """All three base personality profiles."""
    return [narcissus, psychopath, machiavelli]


@pytest.fixture
def fusion_engine() -> FusionEngine:
    """FusionEngine instance (all static methods)."""
    return FusionEngine()


# ── ToolRegistry fixtures ────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def clean_tool_registry():
    """Reset ToolRegistry before each test to guarantee isolation."""
    ToolRegistry._tools = {}
    yield
    ToolRegistry._tools = {}


@pytest.fixture
def populated_registry(clean_tool_registry):
    """Register a minimal known set of tools for deterministic tests."""
    tools = [
        Tool(
            "test_nmap",
            ToolCategory.RECON,
            "Network scan",
            psychopathy_affinity=ToolAffinity.PRIMARY,
            narcissism_affinity=ToolAffinity.FAVORED,
            machiavellianism_affinity=ToolAffinity.NEUTRAL,
        ),
        Tool(
            "test_passive",
            ToolCategory.RECON,
            "OSINT recon",
            machiavellianism_affinity=ToolAffinity.PRIMARY,
            psychopathy_affinity=ToolAffinity.NEUTRAL,
            narcissism_affinity=ToolAffinity.AVOIDED,
        ),
        Tool(
            "test_exploit",
            ToolCategory.EXPLOIT,
            "Custom exploit",
            narcissism_affinity=ToolAffinity.PRIMARY,
            psychopathy_affinity=ToolAffinity.FAVORED,
            machiavellianism_affinity=ToolAffinity.FAVORED,
        ),
        Tool(
            "test_psexec",
            ToolCategory.LATERAL,
            "SMB exec",
            psychopathy_affinity=ToolAffinity.PRIMARY,
            narcissism_affinity=ToolAffinity.FAVORED,
            machiavellianism_affinity=ToolAffinity.AVOIDED,
        ),
        Tool(
            "test_honeypot",
            ToolCategory.DECEPTION,
            "Deploy honeypot",
            machiavellianism_affinity=ToolAffinity.PRIMARY,
            psychopathy_affinity=ToolAffinity.AVOIDED,
            narcissism_affinity=ToolAffinity.AVOIDED,
        ),
        Tool(
            "test_obfuscate",
            ToolCategory.EVASION,
            "Obfuscate payload",
            machiavellianism_affinity=ToolAffinity.PRIMARY,
            psychopathy_affinity=ToolAffinity.FAVORED,
            narcissism_affinity=ToolAffinity.AVOIDED,
        ),
    ]
    for t in tools:
        ToolRegistry.register(t)
    return ToolRegistry


# ── Full base-registry fixture (populates all 13 real tools) ─────────────────


@pytest.fixture
def full_registry(clean_tool_registry):
    """Populate the registry with all 13 base tools via the module loader."""
    from decepticon.navmax.darktriad.core.tool_registry import _register_base_tools

    _register_base_tools()
    return ToolRegistry


# ── Docker mock fixtures ────────────────────────────────────────────────────


@pytest.fixture
def mock_docker_client():
    """Mock docker.DockerClient for sandbox tests."""
    with patch("docker.from_env") as mock_from_env:
        mock_client = MagicMock()
        mock_from_env.return_value = mock_client
        yield mock_client


@pytest.fixture
def mock_docker_unavailable():
    """Simulate Docker not being installed."""
    with patch("docker.from_env", side_effect=ImportError("No docker module")):
        yield
