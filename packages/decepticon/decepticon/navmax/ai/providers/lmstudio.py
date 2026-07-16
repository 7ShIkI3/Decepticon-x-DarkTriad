"""LM Studio provider — backend local avec interface graphique Windows.

LM Studio expose une API compatible OpenAI sur http://localhost:1234/v1
Pas d'authentification requise.

Install: https://lmstudio.ai/
"""

from decepticon.navmax.ai.providers.base import ProviderType
from decepticon.navmax.ai.providers.openai_compat import OpenAICompatProvider


class LMStudioProvider(OpenAICompatProvider):
    """Provider LM Studio — wrapper minimal autour de l'API OpenAI-compatible.

    LM Studio tourne en local, sert des modèles GGUF via une GUI.
    Idéal pour les utilisateurs non techniques sur Windows.
    """

    def __init__(self, base_url: str = "http://localhost:1234/v1", timeout: int = 120) -> None:
        super().__init__(
            provider_type=ProviderType.LMSTUDIO,
            base_url=base_url,
            api_key="lm-studio",  # LM Studio n'exige pas d'auth
            timeout=timeout,
        )
