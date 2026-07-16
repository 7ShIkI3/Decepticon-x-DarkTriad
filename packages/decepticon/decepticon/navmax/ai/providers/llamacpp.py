"""llama.cpp provider — inférence GGUF directe avec accélération GPU.

Nécessite: pip install llama-cpp-python
CUDA (optionnel): CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python
"""

import time
from collections.abc import AsyncIterator
from pathlib import Path

import structlog

from decepticon.navmax.ai.providers.base import (
    BaseProvider,
    GenerateParams,
    GenerateResult,
    ModelInfo,
    ModelTier,
    ProviderType,
)

logger = structlog.get_logger(__name__)


class LlamaCppProvider(BaseProvider):
    """Provider llama.cpp — inférence directe sur fichier GGUF.

    Performance maximale avec GPU NVIDIA. Supporte la quantification
    Q2_K à Q8_0 selon la RAM/VRAM disponible.
    """

    provider_type = ProviderType.LLAMACPP

    def __init__(
        self,
        model_path: str | Path,
        n_ctx: int = 8192,
        n_gpu_layers: int = -1,  # -1 = auto (toutes les couches sur GPU)
        n_threads: int | None = None,
        verbose: bool = False,
    ) -> None:
        self.model_path = Path(model_path)
        self._model = None
        self._n_ctx = n_ctx
        self._n_gpu_layers = n_gpu_layers
        self._n_threads = n_threads
        self._verbose = verbose

    def _load_model(self) -> None:
        if self._model is not None:
            return
        from llama_cpp import Llama

        logger.info("loading_llamacpp_model", path=str(self.model_path))
        self._model = Llama(
            model_path=str(self.model_path),
            n_ctx=self._n_ctx,
            n_gpu_layers=self._n_gpu_layers,
            n_threads=self._n_threads,
            verbose=self._verbose,
        )

    async def health_check(self) -> bool:
        return self.model_path.exists()

    async def list_models(self) -> list[ModelInfo]:
        if not self.model_path.exists():
            return []

        name = self.model_path.stem
        tier = self._guess_tier(name)

        return [
            ModelInfo(
                name=name,
                provider=ProviderType.LLAMACPP,
                tier=tier,
                context_window=self._n_ctx,
                supports_streaming=True,
            ),
        ]

    def _guess_tier(self, filename: str) -> ModelTier:
        n = filename.lower()
        if any(s in n for s in ["70b", "72b", "405b"]):
            return ModelTier.HEAVY
        if any(s in n for s in ["7b", "8b", "9b", "13b"]):
            return ModelTier.MEDIUM
        if any(s in n for s in ["1b", "2b", "3b", "mini"]):
            return ModelTier.LIGHT
        return ModelTier.MEDIUM

    async def generate(self, params: GenerateParams) -> GenerateResult:
        t0 = time.monotonic()
        try:
            self._load_model()
        except (ImportError, OSError, RuntimeError) as e:
            logger.exception("llamacpp_load_model_failed", path=str(self.model_path), error=str(e))
            msg = f"Impossible de charger le modèle llama.cpp: {e}"
            raise RuntimeError(msg) from e

        prompt = params.prompt
        if params.system:
            prompt = (
                f"<|system|>\n{params.system}</s>\n<|user|>\n{params.prompt}</s>\n<|assistant|>\n"
            )

        stop = params.stop_sequences or None
        if params.json_mode:
            stop = (stop or []) + ["}"]

        try:
            result = self._model(
                prompt,
                max_tokens=params.max_tokens,
                temperature=params.temperature,
                stop=stop,
                echo=False,
            )
        except (ValueError, RuntimeError) as e:
            logger.exception("llamacpp_generate_failed", model=self.model_path.stem, error=str(e))
            msg = f"Erreur de génération llama.cpp: {e}"
            raise RuntimeError(msg) from e

        elapsed = time.monotonic() - t0
        text = result["choices"][0]["text"]
        usage = result.get("usage", {})

        return GenerateResult(
            text=text,
            model=self.model_path.stem,
            provider=ProviderType.LLAMACPP,
            tokens_used=usage.get("total_tokens", 0),
            tokens_per_second=usage.get("total_tokens", 0) / max(elapsed, 0.01),
            finish_reason=result["choices"][0].get("finish_reason", "stop"),
        )

    async def stream(self, params: GenerateParams) -> AsyncIterator[str]:
        try:
            self._load_model()
        except (ImportError, OSError, RuntimeError) as e:
            logger.exception("llamacpp_load_model_failed", path=str(self.model_path), error=str(e))
            msg = f"Impossible de charger le modèle llama.cpp: {e}"
            raise RuntimeError(msg) from e

        prompt = params.prompt
        if params.system:
            prompt = (
                f"<|system|>\n{params.system}</s>\n<|user|>\n{params.prompt}</s>\n<|assistant|>\n"
            )

        try:
            for chunk in self._model(
                prompt,
                max_tokens=params.max_tokens,
                temperature=params.temperature,
                stream=True,
                echo=False,
            ):
                text = chunk["choices"][0].get("text", "")
                if text:
                    yield text
        except (ValueError, RuntimeError) as e:
            logger.exception("llamacpp_stream_failed", model=self.model_path.stem, error=str(e))
            msg = f"Erreur de streaming llama.cpp: {e}"
            raise RuntimeError(msg) from e

    def count_tokens(self, text: str, model: str = "") -> int:
        self._load_model()
        return len(self._model.tokenize(text.encode()))
