"""AIEngine — Orchestrateur multi-provider avec sélection automatique.

Cœur du module IA de NavMAX. Combine :
- Détection hardware automatique
- Tous les providers (Ollama, llama.cpp, LM Studio, OpenAI, Anthropic, DeepSeek)
- ModelSelector pour choisir le meilleur modèle par tâche
- Fallback automatique : local → cloud, Heavy → Medium → Light
- Mode airgap (désactive tous les providers cloud)
- Lecture des API keys depuis ~/.navmax/api_keys.yaml

Usage:
    engine = AIEngine()
    status = await engine.initialize()
    result = await engine.generate("Analyse ce scan TCP", tier=ModelTier.MEDIUM)
"""

import asyncio
import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Optional

import structlog
import yaml

from decepticon.navmax.ai.hardware import HardwareProfile, detect_hardware
from decepticon.navmax.ai.providers.base import (
    BaseProvider,
    GenerateParams,
    GenerateResult,
    ModelTier,
    ProviderType,
)
from decepticon.navmax.ai.selector import ModelSelector

logger = structlog.get_logger(__name__)

# Singleton global
_engine: Optional["AIEngine"] = None


def get_engine() -> "AIEngine":
    """Retourne l'instance singleton de AIEngine."""
    global _engine
    if _engine is None:
        _engine = AIEngine()
    return _engine


class AIEngine:
    """Moteur IA multi-provider avec sélection automatique de modèle.

    Détecte le hardware, scanne les providers, et sélectionne
    automatiquement le meilleur modèle pour chaque tâche.

    Parameters
    ----------
        airgap: Si True, désactive tous les providers cloud
        prefer_uncensored: Si True, préfère les modèles abliterated

    """

    def __init__(self, airgap: bool = False, prefer_uncensored: bool = True) -> None:
        self.airgap = airgap
        self.prefer_uncensored = prefer_uncensored
        self._providers: dict[ProviderType, BaseProvider] = {}
        self._hw: HardwareProfile | None = None
        self._selector: ModelSelector | None = None
        self._initialized = False

    # ── API Keys from YAML ─────────────────────────────────────

    API_KEYS_PATH = Path.home() / ".navmax" / "api_keys.yaml"

    @staticmethod
    def _load_api_keys() -> dict[str, str]:
        """Charge les API keys depuis ~/.navmax/api_keys.yaml.

        Retourne un dict {provider_name: api_key}.
        Priorité : YAML > variable d'environnement > vide.
        """
        keys: dict[str, str] = {}

        # Essayer le fichier YAML d'abord
        yaml_path = AIEngine.API_KEYS_PATH
        if yaml_path.exists():
            try:
                content = yaml_path.read_text(encoding="utf-8")
                data = yaml.safe_load(content)
                if isinstance(data, dict) and "providers" in data:
                    for provider, key in data["providers"].items():
                        if key and isinstance(key, str):
                            keys[provider] = key
            except Exception:
                logger.warning("api_keys_yaml_lecture_erreur", path=str(yaml_path))

        # Fallback sur les variables d'environnement si pas trouvé dans YAML
        env_map = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "deepseek": "DEEPSEEK_API_KEY",
        }
        for provider, env_var in env_map.items():
            if provider not in keys:
                env_val = os.environ.get(env_var, "")
                if env_val:
                    keys[provider] = env_val

        return keys

    # ── Initialization ──────────────────────────────────────────

    async def initialize(self) -> dict:
        """Initialise tous les providers et le sélecteur. Retourne un rapport."""
        if self._initialized:
            return {"status": "already_initialized"}

        self._hw = detect_hardware()

        # Initialiser tous les providers
        status = {
            "hardware": {
                "ram_gb": self._hw.ram_total_gb,
                "gpu": self._hw.gpu_name,
                "max_local_tier": self._hw.max_local_tier,
            },
            "providers": {},
            "airgap": self.airgap,
        }

        # Providers locaux
        local_configs = [
            ("ollama", self._init_ollama),
            ("lmstudio", self._init_lmstudio),
        ]
        for name, init_fn in local_configs:
            provider = await init_fn()
            if provider and await provider.health_check():
                self._providers[provider.provider_type] = provider
                models = await provider.list_models()
                status["providers"][name] = {
                    "status": "available",
                    "models_count": len(models),
                    "models": [m.name for m in models[:10]],  # top 10
                }
            else:
                status["providers"][name] = {"status": "unavailable"}

        # llama.cpp (optionnel, nécessite un chemin de modèle)
        if not self.airgap:
            # Cloud providers
            cloud_configs = [
                ("openai", self._init_openai),
                ("anthropic", self._init_anthropic),
                ("deepseek", self._init_deepseek),
            ]
            for name, init_fn in cloud_configs:
                provider = await init_fn()
                if provider and await provider.health_check():
                    self._providers[provider.provider_type] = provider
                    status["providers"][name] = {"status": "available"}
                else:
                    status["providers"][name] = {"status": "unavailable"}
        else:
            status["providers"]["openai"] = {"status": "disabled (airgap)"}
            status["providers"]["anthropic"] = {"status": "disabled (airgap)"}
            status["providers"]["deepseek"] = {"status": "disabled (airgap)"}

        # Initialiser le sélecteur
        self._selector = ModelSelector(
            hardware=self._hw,
            prefer_uncensored=self.prefer_uncensored,
            airgap=self.airgap,
        )

        if self._providers:
            report = await self._selector.scan(self._providers)
            status["selector"] = self._selector.get_status()
            status["recommendations"] = report.recommendations

        self._initialized = True
        logger.info("ai_engine_initialized", **status["hardware"])
        return status

    async def _init_ollama(self) -> BaseProvider | None:
        try:
            from decepticon.navmax.ai.providers.ollama import OllamaProvider

            return OllamaProvider()
        except ImportError:
            return None

    async def _init_lmstudio(self) -> BaseProvider | None:
        try:
            from decepticon.navmax.ai.providers.lmstudio import LMStudioProvider

            return LMStudioProvider()
        except ImportError:
            return None

    async def _init_openai(self) -> BaseProvider | None:
        keys = self._load_api_keys()
        api_key = keys.get("openai", "")
        if not api_key:
            return None
        try:
            from decepticon.navmax.ai.providers.openai_compat import OpenAICompatProvider

            return OpenAICompatProvider(
                provider_type=ProviderType.OPENAI,
                base_url="https://api.openai.com/v1",
                api_key=api_key,
            )
        except ImportError:
            return None

    async def _init_anthropic(self) -> BaseProvider | None:
        keys = self._load_api_keys()
        api_key = keys.get("anthropic", "")
        if not api_key:
            return None
        try:
            from decepticon.navmax.ai.providers.openai_compat import OpenAICompatProvider

            return OpenAICompatProvider(
                provider_type=ProviderType.ANTHROPIC,
                base_url="https://api.anthropic.com",
                api_key=api_key,
            )
        except ImportError:
            return None

    async def _init_deepseek(self) -> BaseProvider | None:
        keys = self._load_api_keys()
        api_key = keys.get("deepseek", "")
        if not api_key:
            return None
        try:
            from decepticon.navmax.ai.providers.openai_compat import OpenAICompatProvider

            return OpenAICompatProvider(
                provider_type=ProviderType.DEEPSEEK,
                base_url="https://api.deepseek.com/v1",
                api_key=api_key,
            )
        except ImportError:
            return None

    # ── Generation API ──────────────────────────────────────────

    async def generate(
        self,
        prompt: str,
        *,
        tier: ModelTier = ModelTier.MEDIUM,
        system: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.7,
        json_mode: bool = False,
        provider: ProviderType | None = None,
        model: str | None = None,
    ) -> GenerateResult:
        """Génère du texte avec sélection automatique du meilleur modèle.

        Args:
            prompt: Le prompt utilisateur
            tier: Niveau de capacité requis (défaut: MEDIUM pour planification)
            system: System prompt optionnel
            max_tokens: Tokens max en sortie
            temperature: Créativité (0.0 = déterministe, 1.0 = créatif)
            json_mode: Force la sortie en JSON
            provider: Force un provider spécifique
            model: Force un modèle spécifique

        Returns:
            GenerateResult avec le texte généré et les métadonnées

        """
        if not self._initialized:
            await self.initialize()

        params = GenerateParams(
            prompt=prompt,
            system=system,
            max_tokens=max_tokens,
            temperature=temperature,
            json_mode=json_mode,
        )

        # Sélection du provider et modèle
        if model and provider:
            # Forçage explicite
            prov = self._providers.get(provider)
            if not prov:
                msg = f"Provider {provider.value} not available"
                raise RuntimeError(msg)
            params.model = model
        elif model:
            # Modèle spécifique — trouver quel provider le sert
            prov, model_name = await self._find_model(model)
            params.model = model_name
        elif provider:
            # Provider spécifique — laisser le sélecteur choisir le modèle
            selection = await self._selector.select(
                tier,
                provider=provider,
                prefer_local=not self.airgap,
            )
            prov = self._providers[selection.provider]
            params.model = selection.model
        else:
            # Sélection automatique complète
            selection = await self._selector.select(
                tier,
                prefer_local=not self.airgap,
                prefer_uncensored=self.prefer_uncensored,
            )
            prov = self._providers[selection.provider]
            params.model = selection.model

        logger.info(
            "ai_generate", tier=tier.value, model=params.model, provider=prov.provider_type.value,
        )

        try:
            return await asyncio.wait_for(prov.generate(params), timeout=180.0)
        except TimeoutError:
            logger.exception(
                "ai_generate_timeout", provider=prov.provider_type.value, model=params.model,
            )
            msg = f"Provider '{prov.provider_type.value}' timed out after 180s"
            raise RuntimeError(
                msg,
            )

    async def stream(
        self,
        prompt: str,
        *,
        tier: ModelTier = ModelTier.MEDIUM,
        system: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.7,
        provider: ProviderType | None = None,
        model: str | None = None,
    ) -> AsyncIterator[str]:
        """Streaming — identique à generate() mais yield les chunks."""
        if not self._initialized:
            await self.initialize()

        params = GenerateParams(
            prompt=prompt,
            system=system,
            max_tokens=max_tokens,
            temperature=temperature,
        )

        if model and provider:
            prov = self._providers.get(provider)
            if not prov:
                msg = f"Provider {provider.value} not available"
                raise RuntimeError(msg)
            params.model = model
        elif model:
            prov, model_name = await self._find_model(model)
            params.model = model_name
        elif provider:
            selection = await self._selector.select(
                tier,
                provider=provider,
                prefer_local=not self.airgap,
            )
            prov = self._providers[selection.provider]
            params.model = selection.model
        else:
            selection = await self._selector.select(
                tier,
                prefer_local=not self.airgap,
                prefer_uncensored=self.prefer_uncensored,
            )
            prov = self._providers[selection.provider]
            params.model = selection.model

        async for chunk in prov.stream(params):
            yield chunk

    async def _find_model(self, model_name: str) -> tuple[BaseProvider, str]:
        """Trouve quel provider sert un modèle donné."""
        for pt, prov in self._providers.items():
            try:
                models = await prov.list_models()
                for m in models:
                    if m.name == model_name:
                        return prov, model_name
            except (OSError, RuntimeError, ValueError) as e:
                logger.warning("provider_list_models_failed", provider=pt.value, error=str(e))
                continue
        msg = f"Model '{model_name}' not found in any provider"
        raise RuntimeError(msg)

    # ── Status & Management ─────────────────────────────────────

    async def get_status(self) -> dict:
        """Retourne l'état complet du moteur IA."""
        if not self._initialized:
            await self.initialize()

        return {
            "initialized": self._initialized,
            "airgap": self.airgap,
            "hardware": {
                "ram_gb": self._hw.ram_total_gb if self._hw else 0,
                "gpu": self._hw.gpu_name if self._hw else None,
                "max_local_tier": self._hw.max_local_tier if self._hw else None,
            },
            "providers": [
                {
                    "type": pt.value,
                    "available": await prov.health_check(),
                }
                for pt, prov in self._providers.items()
            ],
            "selector": self._selector.get_status() if self._selector else None,
        }

    async def reload(self) -> dict:
        """Réinitialise tous les providers (après changement de config)."""
        self._providers.clear()
        self._initialized = False
        self._selector = None
        return await self.initialize()

    def get_selector(self) -> ModelSelector | None:
        """Accès direct au sélecteur pour des requêtes avancées."""
        return self._selector

    @property
    def hardware(self) -> HardwareProfile | None:
        return self._hw

    @property
    def providers(self) -> dict[ProviderType, BaseProvider]:
        return self._providers
