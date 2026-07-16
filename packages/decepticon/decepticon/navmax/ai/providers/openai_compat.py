"""Provider OpenAI-compatible — OpenAI, Anthropic, DeepSeek, et tout autre
backend exposant une API /chat/completions compatible OpenAI.

Optimisé : pool HTTP centralisé, imports aiohttp retardés.
"""

import json
import time
from collections.abc import AsyncIterator

import structlog

from decepticon.navmax.ai.providers.base import (
    BaseProvider,
    GenerateParams,
    GenerateResult,
    ModelInfo,
    ModelTier,
    ProviderType,
)
from decepticon.navmax.core.http_client import get_aiohttp_session

logger = structlog.get_logger(__name__)


class OpenAICompatProvider(BaseProvider):
    """Provider générique pour toute API compatible OpenAI."""

    def __init__(self, provider_type: ProviderType, base_url: str,
                 api_key: str, timeout: int = 120) -> None:
        self.provider_type = provider_type
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._models: list[ModelInfo] | None = None

    async def health_check(self) -> bool:
        import aiohttp
        try:
            session = await get_aiohttp_session()
            headers = {"Authorization": f"Bearer {self.api_key}"}
            async with session.get(
                f"{self.base_url}/models",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return resp.status == 200
        except (TimeoutError, aiohttp.ClientError):
            return False

    async def list_models(self) -> list[ModelInfo]:
        import aiohttp
        if self._models:
            return self._models

        try:
            session = await get_aiohttp_session()
            headers = {"Authorization": f"Bearer {self.api_key}"}
            async with session.get(
                f"{self.base_url}/models",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                self._models = [
                    ModelInfo(
                        name=m["id"],
                        provider=self.provider_type,
                        tier=self._guess_tier(m["id"]),
                        context_window=8192,
                        supports_streaming=True,
                        supports_tools=True,
                    )
                    for m in data.get("data", [])
                ]
                return self._models
        except aiohttp.ClientResponseError as e:
            logger.exception("openai_list_models_http_error",
                         provider=self.provider_type.value, status=e.status)
            msg = f"HTTP {e.status}: {e.message}"
            raise RuntimeError(msg) from e
        except aiohttp.ClientError as e:
            logger.exception("openai_list_models_client_error",
                         provider=self.provider_type.value, error=str(e))
            msg = f"Connexion échouée: {e}"
            raise RuntimeError(msg) from e

    def _guess_tier(self, name: str) -> ModelTier:
        n = name.lower()
        if any(s in n for s in ["gpt-4o", "gpt-4.5", "claude-3-opus",
                                 "claude-3.5", "claude-sonnet-4",
                                 "deepseek-v4-pro", "deepseek-reasoner",
                                 "o1", "o3", "gemini-2.0-pro"]):
            return ModelTier.HEAVY
        if any(s in n for s in ["gpt-4-", "gpt-4 "]):
            return ModelTier.HEAVY
        if any(s in n for s in ["gpt-3.5", "claude-3-haiku", "deepseek-chat",
                                 "deepseek-v4-flash", "deepseek-v4",
                                 "gemini-2.0-flash", "gpt-4o-mini"]):
            return ModelTier.MEDIUM
        if any(s in n for s in ["gpt-4o-mini"]):
            return ModelTier.LIGHT
        return ModelTier.MEDIUM

    async def generate(self, params: GenerateParams) -> GenerateResult:
        import aiohttp
        t0 = time.monotonic()
        model = params.model or "gpt-4o-mini"

        messages = []
        if params.system:
            messages.append({"role": "system", "content": params.system})
        messages.append({"role": "user", "content": params.prompt})

        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": params.max_tokens,
            "temperature": params.temperature,
        }
        if params.json_mode:
            payload["response_format"] = {"type": "json_object"}

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            session = await get_aiohttp_session()
            async with session.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                elapsed = time.monotonic() - t0
                choice = data["choices"][0]
                usage = data.get("usage", {})
                msg = choice["message"]

                text = msg.get("content", "")
                reasoning = msg.get("reasoning_content", "")

                if not text and reasoning:
                    text = f"[REASONING]\n{reasoning}"

                return GenerateResult(
                    text=text,
                    model=model,
                    provider=self.provider_type,
                    tokens_used=usage.get("total_tokens", 0),
                    tokens_per_second=usage.get("total_tokens", 0) / max(elapsed, 0.01),
                    finish_reason=choice.get("finish_reason", "stop"),
                )
        except TimeoutError as e:
            logger.exception("openai_generate_timeout",
                         provider=self.provider_type.value, model=model, timeout=self.timeout)
            msg_0 = f"Provider '{self.provider_type.value}' timed out after {self.timeout}s"
            raise RuntimeError(
                msg_0,
            ) from e
        except aiohttp.ClientResponseError as e:
            logger.exception("openai_generate_http_error",
                         provider=self.provider_type.value, model=model, status=e.status)
            msg_0 = f"HTTP {e.status}: {e.message}"
            raise RuntimeError(msg_0) from e
        except aiohttp.ClientError as e:
            logger.exception("openai_generate_client_error",
                         provider=self.provider_type.value, model=model, error=str(e))
            msg_0 = f"Connexion échouée: {e}"
            raise RuntimeError(msg_0) from e

    async def stream(self, params: GenerateParams) -> AsyncIterator[str]:
        import aiohttp
        model = params.model or "gpt-4o-mini"

        messages = []
        if params.system:
            messages.append({"role": "system", "content": params.system})
        messages.append({"role": "user", "content": params.prompt})

        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": params.max_tokens,
            "temperature": params.temperature,
            "stream": True,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            session = await get_aiohttp_session()
            async with session.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                resp.raise_for_status()
                async for line in resp.content:
                    line = line.decode("utf-8").strip()
                    if line.startswith("data: ") and line != "data: [DONE]":
                        try:
                            chunk = json.loads(line[6:])
                            delta = chunk["choices"][0].get("delta", {})
                            if "content" in delta:
                                yield delta["content"]
                        except (json.JSONDecodeError, KeyError, IndexError):
                            continue
        except aiohttp.ClientResponseError as e:
            logger.exception("openai_stream_http_error",
                         provider=self.provider_type.value, model=model, status=e.status)
            msg = f"HTTP {e.status}: {e.message}"
            raise RuntimeError(msg) from e
        except aiohttp.ClientError as e:
            logger.exception("openai_stream_client_error",
                         provider=self.provider_type.value, model=model, error=str(e))
            msg = f"Connexion échouée: {e}"
            raise RuntimeError(msg) from e
