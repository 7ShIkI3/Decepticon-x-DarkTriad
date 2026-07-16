"""ModelSelector — détection et sélection automatique du meilleur modèle.

Scan les providers disponibles, match contre le catalogue, et choisit
le modèle optimal pour chaque tâche selon :
- Le tier requis (Light/Medium/Heavy)
- La disponibilité locale
- La préférence abliterated/uncensored (cybersécurité)
- Les capacités hardware
"""

from dataclasses import dataclass, field

import structlog

from decepticon.navmax.ai.hardware import HardwareProfile
from decepticon.navmax.ai.models_catalog import (
    CatalogEntry,
    ModelTag,
    match_ollama_model,
)
from decepticon.navmax.ai.providers.base import ModelInfo, ModelTier, ProviderType

logger = structlog.get_logger(__name__)


@dataclass
class SelectionResult:
    """Résultat de la sélection de modèle."""

    entry: CatalogEntry | None  # Entrée catalogue (None si modèle inconnu)
    model: str  # Nom du modèle à utiliser
    provider: ProviderType
    tier: ModelTier
    is_uncensored: bool
    is_local: bool
    ram_required_gb: float
    reason: str  # Pourquoi ce modèle a été choisi

    @property
    def display_name(self) -> str:
        tags = []
        if self.is_uncensored:
            tags.append("🔓")
        if self.is_local:
            tags.append("🏠")
        else:
            tags.append("☁️")
        tag_str = " ".join(tags)
        return f"{tag_str} {self.model} ({self.tier.value})"


@dataclass
class SelectionReport:
    """Rapport complet de l'état des modèles disponibles."""

    hardware: HardwareProfile
    available_models: list[SelectionResult] = field(default_factory=list)
    best_per_tier: dict[ModelTier, SelectionResult | None] = field(default_factory=dict)
    abliterated_available: list[SelectionResult] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "=== NavMAX Model Selection Report ===",
            f"Hardware: {self.hardware.ram_total_gb}GB RAM, "
            f"GPU: {self.hardware.gpu_name or 'None'}, "
            f"Max local tier: {self.hardware.max_local_tier}",
            "",
            f"Available models: {len(self.available_models)}",
        ]
        for tier in [ModelTier.LIGHT, ModelTier.MEDIUM, ModelTier.HEAVY]:
            best = self.best_per_tier.get(tier)
            if best:
                lines.append(f"  {tier.value.upper()}: {best.display_name}")
            else:
                lines.append(f"  {tier.value.upper()}: ❌ Aucun")

        if self.abliterated_available:
            lines.append("")
            lines.append(f"🔓 Abliterated/Uncensored ({len(self.abliterated_available)}):")
            for r in self.abliterated_available:
                lines.append(f"  - {r.model}")

        if self.recommendations:
            lines.append("")
            lines.append("📋 Recommandations:")
            for rec in self.recommendations:
                lines.append(f"  • {rec}")

        return "\n".join(lines)


class ModelSelector:
    """Sélectionneur intelligent de modèles.

    Utilisation :
        selector = ModelSelector(hardware=hw)
        report = await selector.scan(providers_dict)
        best = await selector.select(tier=ModelTier.MEDIUM, prefer_uncensored=True)
    """

    def __init__(
        self,
        hardware: HardwareProfile | None = None,
        prefer_uncensored: bool = True,
        airgap: bool = False,
    ) -> None:
        self.hardware = hardware
        self.prefer_uncensored = prefer_uncensored
        self.airgap = airgap
        self._available: dict[str, SelectionResult] = {}  # model_name → result
        self._by_tier: dict[ModelTier, list[SelectionResult]] = {
            ModelTier.LIGHT: [],
            ModelTier.MEDIUM: [],
            ModelTier.HEAVY: [],
        }

    async def scan(self, providers: dict[ProviderType, "BaseProvider"]) -> SelectionReport:
        """Scanne tous les providers et construit le rapport de disponibilité.

        Args:
            providers: dict {ProviderType: BaseProvider instance}

        """
        self._available.clear()
        for tier in self._by_tier:
            self._by_tier[tier].clear()

        if not self.hardware:
            from decepticon.navmax.ai.hardware import detect_hardware

            self.hardware = detect_hardware()

        # Scanner chaque provider
        for pt, provider in providers.items():
            try:
                models = await provider.list_models()
                for m in models:
                    result = self._classify_model(m)
                    if result:
                        key = f"{pt.value}:{m.name}"
                        self._available[key] = result
                        self._by_tier[result.tier].append(result)
            except Exception as e:
                logger.warning("scan_provider_failed", provider=pt.value, error=str(e))

        # Trier chaque tier par priorité
        for tier in self._by_tier:
            self._by_tier[tier].sort(key=lambda r: r.entry.priority if r.entry else 999)

        # Construire le rapport
        report = SelectionReport(hardware=self.hardware)
        report.available_models = list(self._available.values())
        report.abliterated_available = [r for r in report.available_models if r.is_uncensored]

        for tier in [ModelTier.LIGHT, ModelTier.MEDIUM, ModelTier.HEAVY]:
            tier_models = self._by_tier[tier]
            # Préférer uncensored si demandé
            if self.prefer_uncensored:
                uncensored = [m for m in tier_models if m.is_uncensored]
                report.best_per_tier[tier] = (
                    uncensored[0] if uncensored else (tier_models[0] if tier_models else None)
                )
            else:
                report.best_per_tier[tier] = tier_models[0] if tier_models else None

        # Générer des recommandations
        report.recommendations = self._generate_recommendations(report)

        return report

    def _classify_model(self, model_info: ModelInfo) -> SelectionResult | None:
        """Classifie un modèle détecté contre le catalogue."""
        # Chercher dans le catalogue
        entry = match_ollama_model(model_info.name)

        if not entry:
            # Modèle inconnu — classification heuristique
            entry = None

        # Vérifier si ce modèle peut tourner localement
        ram_needed = entry.ram_required_gb if entry else 6.0
        is_local = model_info.provider in (
            ProviderType.OLLAMA,
            ProviderType.LLAMACPP,
            ProviderType.LMSTUDIO,
        )
        can_run_locally = not is_local or (
            self.hardware and self.hardware.ram_total_gb >= ram_needed
        )

        if is_local and not can_run_locally:
            logger.info(
                "model_too_heavy",
                model=model_info.name,
                ram_needed=ram_needed,
                ram_available=self.hardware.ram_total_gb if self.hardware else 0,
            )
            return None

        return SelectionResult(
            entry=entry,
            model=model_info.name,
            provider=model_info.provider,
            tier=model_info.tier,
            is_uncensored=entry.is_uncensored if entry else False,
            is_local=is_local,
            ram_required_gb=ram_needed,
            reason=self._build_reason(entry, model_info, is_local),
        )

    def _build_reason(self, entry: CatalogEntry | None, model: ModelInfo, is_local: bool) -> str:
        if entry:
            tags = []
            if entry.is_abliterated:
                tags.append("abliterated (uncensored)")
            if ModelTag.RECOMMENDED in entry.tags:
                tags.append("recommended")
            if ModelTag.CODE in entry.tags:
                tags.append("code-optimized")
            if ModelTag.REASONING in entry.tags:
                tags.append("CoT reasoning")
            tag_str = ", ".join(tags) if tags else "standard"
            loc = "local" if is_local else "cloud"
            return f"{tag_str} ({loc}) — {entry.description}"
        loc = "local" if is_local else "cloud"
        return f"unknown model ({loc}) — no catalog entry"

    def _generate_recommendations(self, report: SelectionReport) -> list[str]:
        """Génère des recommandations humaines."""
        recs = []

        # Vérifier si on a des modèles abliterated
        if not report.abliterated_available:
            recs.append(
                "🔓 Aucun modèle abliterated détecté. "
                "Pour la cybersécurité offensive, installez :\n"
                "  ollama pull huihui_ai/llama3.1-abliterated:8b",
            )

        # Vérifier le tier medium
        if not report.best_per_tier.get(ModelTier.MEDIUM):
            if self.hardware and self.hardware.max_local_tier in ("medium", "heavy"):
                recs.append(
                    "⚠️  Aucun modèle MEDIUM (7-8B) détecté. Recommandé : ollama pull llama3.1:8b",
                )
            else:
                recs.append(
                    "💡 Pas assez de RAM pour un modèle MEDIUM local. "
                    "Le cloud sera utilisé en fallback.",
                )

        # Suggérer si on a un GPU inutilisé
        if self.hardware and self.hardware.gpu_name and self.hardware.gpu_vram_gb:
            has_llamacpp = any(r.provider == ProviderType.LLAMACPP for r in report.available_models)
            if not has_llamacpp:
                recs.append(
                    f"🚀 GPU {self.hardware.gpu_name} détecté mais llama.cpp non utilisé. "
                    "Installez llama-cpp-python pour 2-3x plus de performance.",
                )

        return recs

    async def select(
        self,
        tier: ModelTier,
        prefer_uncensored: bool | None = None,
        prefer_local: bool = True,
        provider: ProviderType | None = None,
        model: str | None = None,
    ) -> SelectionResult:
        """Sélectionne le meilleur modèle pour un tier donné.

        Args:
            tier: Niveau de capacité requis
            prefer_uncensored: Priorité aux modèles abliterated (défaut: self.prefer_uncensored)
            prefer_local: Priorité aux modèles locaux
            provider: Forcer un provider spécifique
            model: Forcer un modèle spécifique

        Returns:
            SelectionResult avec le modèle choisi

        Raises:
            RuntimeError: Si aucun modèle n'est disponible pour ce tier

        """
        if prefer_uncensored is None:
            prefer_uncensored = self.prefer_uncensored

        # Si modèle forcé
        if model:
            for result in self._available.values():
                if result.model == model:
                    return result
            msg = f"Requested model '{model}' not available"
            raise RuntimeError(msg)

        # Si provider forcé
        if provider:
            candidates = [r for r in self._by_tier[tier] if r.provider == provider]
            if candidates:
                if prefer_uncensored:
                    uncensored = [c for c in candidates if c.is_uncensored]
                    if uncensored:
                        return uncensored[0]
                return candidates[0]
            msg = f"No model for tier {tier.value} on provider {provider.value}"
            raise RuntimeError(msg)

        # Sélection automatique
        candidates = self._by_tier.get(tier, [])

        # Filtrer par local/cloud
        if prefer_local and not self.airgap:
            # Préférer local mais accepter cloud
            local = [c for c in candidates if c.is_local]
            if local:
                candidates = local
        elif self.airgap:
            candidates = [c for c in candidates if c.is_local]

        if not candidates:
            # Fallback bidirectionnel : essayer les tiers adjacents
            fallback_order = {
                ModelTier.HEAVY: [ModelTier.MEDIUM, ModelTier.LIGHT],
                ModelTier.MEDIUM: [ModelTier.LIGHT, ModelTier.HEAVY],
                ModelTier.LIGHT: [ModelTier.MEDIUM, ModelTier.HEAVY],
            }
            for fallback in fallback_order.get(tier, []):
                fb_candidates = self._by_tier[fallback]
                if prefer_local and not self.airgap:
                    local = [c for c in fb_candidates if c.is_local]
                    if local:
                        fb_candidates = local
                elif self.airgap:
                    fb_candidates = [c for c in fb_candidates if c.is_local]
                if fb_candidates:
                    logger.warning("tier_fallback", from_tier=tier.value, to_tier=fallback.value)
                    if prefer_uncensored:
                        uncensored = [c for c in fb_candidates if c.is_uncensored]
                        if uncensored:
                            return uncensored[0]
                    return fb_candidates[0]
            msg = (
                f"No model available for tier {tier.value} "
                f"(local={'only' if self.airgap else 'preferred'}). "
                f"Install a model or disable airgap mode."
            )
            raise RuntimeError(
                msg,
            )

        # Préférer uncensored
        if prefer_uncensored:
            uncensored = [c for c in candidates if c.is_uncensored]
            if uncensored:
                return uncensored[0]

        return candidates[0]

    def get_status(self) -> dict:
        """Retourne un résumé JSON de l'état actuel."""
        return {
            "hardware": {
                "ram_gb": self.hardware.ram_total_gb if self.hardware else 0,
                "gpu": self.hardware.gpu_name if self.hardware else None,
                "max_local_tier": self.hardware.max_local_tier if self.hardware else None,
            },
            "models_available": len(self._available),
            "abliterated_available": sum(1 for r in self._available.values() if r.is_uncensored),
            "by_tier": {
                tier.value: [r.model for r in models] for tier, models in self._by_tier.items()
            },
        }
