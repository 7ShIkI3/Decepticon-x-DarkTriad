"""NavMAX AI — Moteur IA multi-provider avec sélection automatique."""

from decepticon.navmax.ai.engine import AIEngine, get_engine
from decepticon.navmax.ai.hardware import HardwareProfile, detect_hardware
from decepticon.navmax.ai.models_catalog import (
    MODEL_CATALOG,
    CatalogEntry,
    ModelTag,
    find_best_for_task,
    get_abliterated_models,
    get_recommended,
)
from decepticon.navmax.ai.providers.base import (
    BaseProvider,
    GenerateParams,
    GenerateResult,
    ModelInfo,
    ModelTier,
    ProviderType,
)
from decepticon.navmax.ai.selector import ModelSelector, SelectionReport, SelectionResult

__all__ = [
    # Catalog
    "MODEL_CATALOG",
    # Engine
    "AIEngine",
    "BaseProvider",
    "CatalogEntry",
    "GenerateParams",
    "GenerateResult",
    "HardwareProfile",
    "ModelInfo",
    # Selector
    "ModelSelector",
    "ModelTag",
    # Base types
    "ModelTier",
    "ProviderType",
    "SelectionReport",
    "SelectionResult",
    # Hardware
    "detect_hardware",
    "find_best_for_task",
    "get_abliterated_models",
    "get_engine",
    "get_recommended",
]
