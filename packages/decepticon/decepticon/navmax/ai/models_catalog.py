"""Catalogue des modèles recommandés pour NavMAX, classés par tier et provider.

Inclut les modèles **abliterated** (uncensored/desalignés) — essentiels pour
la cybersécurité car les modèles standard refusent souvent les requêtes offensives.

Les modèles abliterated utilisent la technique "abliteration" (failspy, huihui_ai,
mlabonne) qui supprime le mécanisme de refus sans dégrader les performances.
"""

from dataclasses import dataclass, field
from enum import StrEnum

from decepticon.navmax.ai.providers.base import ModelTier, ProviderType


class ModelTag(StrEnum):
    """Tags qualitatifs pour les modèles."""

    ABLITERATED = "abliterated"  # Uncensored — OK pour cybersécurité offensive
    UNCENSORED = "uncensored"  # Naturellement non censuré
    FAST = "fast"  # Inférence rapide (≤3B)
    CODE = "code"  # Optimisé pour la génération de code
    REASONING = "reasoning"  # Chaîne de pensée (CoT)
    MULTILINGUAL = "multilingual"  # Support multilingue (dont français)
    VISION = "vision"  # Support vision (images)
    RECOMMENDED = "recommended"  # Recommandé par défaut pour ce tier


@dataclass
class CatalogEntry:
    """Entrée dans le catalogue de modèles."""

    name: str  # Nom pour Ollama (ex: "huihui_ai/llama3.1-abliterated:8b")
    provider: ProviderType
    tier: ModelTier
    tags: list[ModelTag] = field(default_factory=list)
    context_window: int = 8192
    description: str = ""
    # Noms alternatifs pour d'autres providers
    ollama_name: str | None = None
    openai_name: str | None = None
    deepseek_name: str | None = None
    # GGUF filename hint (pour llama.cpp / LM Studio)
    gguf_hint: str | None = None
    # RAM approximative nécessaire (Q4_K_M)
    ram_required_gb: float = 4.0
    # Priorité de sélection (plus bas = préféré)
    priority: int = 10

    @property
    def is_abliterated(self) -> bool:
        return ModelTag.ABLITERATED in self.tags

    @property
    def is_uncensored(self) -> bool:
        return ModelTag.ABLITERATED in self.tags or ModelTag.UNCENSORED in self.tags


# ═══════════════════════════════════════════════════════════════════
# CATALOGUE PRINCIPAL
# ═══════════════════════════════════════════════════════════════════

MODEL_CATALOG: list[CatalogEntry] = [
    # ── TIER LIGHT (1-3B) — Classification, extraction, validation JSON ──
    CatalogEntry(
        name="llama3.2:3b",
        provider=ProviderType.OLLAMA,
        tier=ModelTier.LIGHT,
        tags=[ModelTag.FAST, ModelTag.RECOMMENDED],
        ollama_name="llama3.2:3b",
        ram_required_gb=2.5,
        priority=5,
        description="Meta Llama 3.2 3B — rapide, bon pour classification et extraction",
    ),
    CatalogEntry(
        name="qwen2.5:3b",
        provider=ProviderType.OLLAMA,
        tier=ModelTier.LIGHT,
        tags=[ModelTag.FAST, ModelTag.MULTILINGUAL, ModelTag.CODE],
        ollama_name="qwen2.5:3b",
        ram_required_gb=2.5,
        priority=6,
        description="Qwen 2.5 3B — excellent pour code et multilingue",
    ),
    CatalogEntry(
        name="phi3:3.8b",
        provider=ProviderType.OLLAMA,
        tier=ModelTier.LIGHT,
        tags=[ModelTag.FAST, ModelTag.CODE],
        ollama_name="phi3:3.8b",
        ram_required_gb=3.0,
        priority=7,
        description="Microsoft Phi-3 Mini — bon raisonnement malgré sa taille",
    ),
    CatalogEntry(
        name="gemma2:2b",
        provider=ProviderType.OLLAMA,
        tier=ModelTier.LIGHT,
        tags=[ModelTag.FAST],
        ollama_name="gemma2:2b",
        ram_required_gb=2.0,
        priority=8,
        description="Google Gemma 2 2B — ultra-léger, parfait pour les petites machines",
    ),
    # ── TIER MEDIUM (7-8B) — Planification, analyse, résumé ──
    # ★ Abliterated (priorité maximale pour la cybersécurité)
    CatalogEntry(
        name="huihui_ai/llama3.1-abliterated:8b",
        provider=ProviderType.OLLAMA,
        tier=ModelTier.MEDIUM,
        tags=[ModelTag.ABLITERATED, ModelTag.RECOMMENDED],
        ollama_name="huihui_ai/llama3.1-abliterated:8b",
        ram_required_gb=6.0,
        priority=1,  # TOP priorité — abliterated pour cybersécurité
        description="Llama 3.1 8B ABLITERATED — uncensored, idéal planification de mission",
    ),
    CatalogEntry(
        name="huihui_ai/deepseek-r1-abliterated:8b",
        provider=ProviderType.OLLAMA,
        tier=ModelTier.MEDIUM,
        tags=[ModelTag.ABLITERATED, ModelTag.REASONING],
        ollama_name="huihui_ai/deepseek-r1-abliterated:8b",
        ram_required_gb=6.0,
        priority=2,
        description="DeepSeek R1 8B ABLITERATED — raisonnement + uncensored",
    ),
    CatalogEntry(
        name="huihui_ai/mistral-7b-instruct-abliterated:7b",
        provider=ProviderType.OLLAMA,
        tier=ModelTier.MEDIUM,
        tags=[ModelTag.ABLITERATED],
        ollama_name="huihui_ai/mistral-7b-instruct-abliterated:7b",
        ram_required_gb=5.5,
        priority=3,
        description="Mistral 7B ABLITERATED — uncensored, bon français",
    ),
    # Standards (fallback si abliterated non dispo)
    CatalogEntry(
        name="llama3.1:8b",
        provider=ProviderType.OLLAMA,
        tier=ModelTier.MEDIUM,
        tags=[ModelTag.RECOMMENDED],
        ollama_name="llama3.1:8b",
        ram_required_gb=6.0,
        priority=10,
        description="Meta Llama 3.1 8B — standard fiable (non-abliterated)",
    ),
    CatalogEntry(
        name="mistral:7b",
        provider=ProviderType.OLLAMA,
        tier=ModelTier.MEDIUM,
        tags=[ModelTag.MULTILINGUAL],
        ollama_name="mistral:7b",
        ram_required_gb=5.5,
        priority=11,
        description="Mistral 7B — excellent pour le français, analyse de texte",
    ),
    CatalogEntry(
        name="qwen2.5:7b",
        provider=ProviderType.OLLAMA,
        tier=ModelTier.MEDIUM,
        tags=[ModelTag.CODE, ModelTag.MULTILINGUAL],
        ollama_name="qwen2.5:7b",
        ram_required_gb=6.0,
        priority=12,
        description="Qwen 2.5 7B — code et multilingue",
    ),
    CatalogEntry(
        name="deepseek-r1:8b",
        provider=ProviderType.OLLAMA,
        tier=ModelTier.MEDIUM,
        tags=[ModelTag.REASONING],
        ollama_name="deepseek-r1:8b",
        ram_required_gb=6.0,
        priority=13,
        description="DeepSeek R1 8B — raisonnement chaîne de pensée",
    ),
    CatalogEntry(
        name="codellama:7b",
        provider=ProviderType.OLLAMA,
        tier=ModelTier.MEDIUM,
        tags=[ModelTag.CODE],
        ollama_name="codellama:7b",
        ram_required_gb=5.5,
        priority=14,
        description="CodeLlama 7B — spécialisé génération de code",
    ),
    # ── TIER HEAVY (70B+) — Génération d'exploit, raisonnement complexe ──
    # ★ Abliterated
    CatalogEntry(
        name="huihui_ai/llama3.1-abliterated:70b",
        provider=ProviderType.OLLAMA,
        tier=ModelTier.HEAVY,
        tags=[ModelTag.ABLITERATED, ModelTag.RECOMMENDED],
        ollama_name="huihui_ai/llama3.1-abliterated:70b",
        gguf_hint="llama-3.1-70b-abliterated-Q4_K_M.gguf",
        ram_required_gb=40.0,
        priority=1,
        description="Llama 3.1 70B ABLITERATED — le plus puissant uncensored",
    ),
    # Standards
    CatalogEntry(
        name="llama3.1:70b",
        provider=ProviderType.OLLAMA,
        tier=ModelTier.HEAVY,
        tags=[ModelTag.RECOMMENDED],
        ollama_name="llama3.1:70b",
        gguf_hint="llama-3.1-70b-Q4_K_M.gguf",
        ram_required_gb=40.0,
        priority=10,
        description="Meta Llama 3.1 70B — standard",
    ),
    CatalogEntry(
        name="codellama:70b",
        provider=ProviderType.OLLAMA,
        tier=ModelTier.HEAVY,
        tags=[ModelTag.CODE],
        ollama_name="codellama:70b",
        gguf_hint="codellama-70b-Q4_K_M.gguf",
        ram_required_gb=40.0,
        priority=11,
        description="CodeLlama 70B — génération de code/exploit avancée",
    ),
    CatalogEntry(
        name="deepseek-r1:70b",
        provider=ProviderType.OLLAMA,
        tier=ModelTier.HEAVY,
        tags=[ModelTag.REASONING],
        ollama_name="deepseek-r1:70b",
        gguf_hint="deepseek-r1-70b-Q4_K_M.gguf",
        ram_required_gb=40.0,
        priority=12,
        description="DeepSeek R1 70B — raisonnement + code",
    ),
    # ── CLOUD PROVIDERS (fallback) ──
    CatalogEntry(
        name="gpt-4o-mini",
        provider=ProviderType.OPENAI,
        tier=ModelTier.LIGHT,
        tags=[ModelTag.FAST],
        openai_name="gpt-4o-mini",
        priority=50,
        description="GPT-4o Mini — rapide, pas cher, bon fallback cloud",
    ),
    CatalogEntry(
        name="gpt-4o",
        provider=ProviderType.OPENAI,
        tier=ModelTier.HEAVY,
        tags=[ModelTag.REASONING, ModelTag.CODE, ModelTag.VISION],
        openai_name="gpt-4o",
        priority=51,
        description="GPT-4o — raisonnement avancé, vision",
    ),
    CatalogEntry(
        name="claude-sonnet-4-20250514",
        provider=ProviderType.ANTHROPIC,
        tier=ModelTier.HEAVY,
        tags=[ModelTag.REASONING, ModelTag.CODE],
        openai_name="claude-sonnet-4-20250514",
        priority=52,
        description="Claude Sonnet 4 — meilleur raisonnement, code",
    ),
    CatalogEntry(
        name="deepseek-chat",
        provider=ProviderType.DEEPSEEK,
        tier=ModelTier.MEDIUM,
        tags=[ModelTag.CODE, ModelTag.MULTILINGUAL, ModelTag.FAST],
        deepseek_name="deepseek-chat",
        priority=30,
        description="DeepSeek V3 — rapide, pas cher, bon pour code et planification",
    ),
    CatalogEntry(
        name="deepseek-v4-flash",
        provider=ProviderType.DEEPSEEK,
        tier=ModelTier.MEDIUM,
        tags=[ModelTag.REASONING],
        deepseek_name="deepseek-v4-flash",
        priority=32,
        description="DeepSeek V4 Flash — modèle rapide avec raisonnement",
    ),
    CatalogEntry(
        name="deepseek-v4-pro",
        provider=ProviderType.DEEPSEEK,
        tier=ModelTier.HEAVY,
        tags=[ModelTag.REASONING, ModelTag.CODE, ModelTag.RECOMMENDED],
        deepseek_name="deepseek-v4-pro",
        priority=31,
        description="DeepSeek V4 Pro — raisonnement avancé, génération de code",
    ),
]


# ═══════════════════════════════════════════════════════════════════
# INDEXES
# ═══════════════════════════════════════════════════════════════════


def get_catalog_by_tier(tier: ModelTier) -> list[CatalogEntry]:
    """Retourne les modèles pour un tier donné, triés par priorité."""
    entries = [e for e in MODEL_CATALOG if e.tier == tier]
    return sorted(entries, key=lambda e: e.priority)


def get_catalog_by_provider(provider: ProviderType) -> list[CatalogEntry]:
    """Retourne les modèles pour un provider donné."""
    return [e for e in MODEL_CATALOG if e.provider == provider]


def get_abliterated_models() -> list[CatalogEntry]:
    """Retourne tous les modèles abliterated/uncensored."""
    return [e for e in MODEL_CATALOG if e.is_uncensored]


def get_recommended(tier: ModelTier | None = None) -> list[CatalogEntry]:
    """Modèles recommandés, optionnellement filtrés par tier."""
    entries = [e for e in MODEL_CATALOG if ModelTag.RECOMMENDED in e.tags]
    if tier:
        entries = [e for e in entries if e.tier == tier]
    return sorted(entries, key=lambda e: e.priority)


def match_ollama_model(ollama_name: str) -> CatalogEntry | None:
    """Trouve l'entrée catalogue correspondant à un modèle Ollama détecté."""
    # Match exact
    for entry in MODEL_CATALOG:
        if entry.ollama_name == ollama_name:
            return entry
    # Match fuzzy (ignore tag)
    base = ollama_name.split(":", maxsplit=1)[0].lower().replace("-", "").replace("_", "")
    for entry in MODEL_CATALOG:
        if entry.ollama_name:
            entry_base = entry.ollama_name.split(":")[0].lower().replace("-", "").replace("_", "")
            if entry_base == base:
                return entry
    return None


def find_best_for_task(
    tier: ModelTier, prefer_uncensored: bool = True, available_models: list[str] | None = None,
) -> CatalogEntry | None:
    """Trouve le meilleur modèle pour un tier donné.

    Ordre de préférence :
    1. Abliterated/uncensored (si prefer_uncensored=True) → priorité 1-3
    2. Recommandé standard → priorité 5-14
    3. Fallback cloud → priorité 30+
    """
    candidates = get_catalog_by_tier(tier)

    # Si on a une liste de modèles disponibles, filtrer
    if available_models:
        available_set = {m.lower() for m in available_models}
        candidates = [
            c for c in candidates if c.ollama_name and c.ollama_name.lower() in available_set
        ]

    if not candidates:
        return None

    # Préférer uncensored si demandé
    if prefer_uncensored:
        uncensored = [c for c in candidates if c.is_uncensored]
        if uncensored:
            return uncensored[0]  # déjà trié par priorité

    # Sinon le meilleur dispo
    return candidates[0]
