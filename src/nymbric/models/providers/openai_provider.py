"""OpenAI and OpenAI-compatible chat completions."""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

from nymbric.core.errors import ProviderUnavailable
from nymbric.models.base import ModelRequest, ModelResponse, ProviderStatus, TokenUsage, ToolCall
from nymbric.models.providers._parse import parse_json_object, tool_arguments


class _OpenAIStyleProvider:
    provider_name = "openai"

    def __init__(
        self,
        model: str,
        *,
        base_url: str,
        api_key: str | None,
        timeout_s: float = 120,
        temperature: float = 0,
        client: httpx.Client | None = None,
        key_env: str = "OPENAI_API_KEY",
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_s = timeout_s
        self.temperature = temperature
        self._client = client
        self.key_env = key_env

    def _http(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        return httpx.Client(timeout=self.timeout_s)

    def _require_key(self) -> str:
        if not self.api_key:
            raise ProviderUnavailable(
                f"{self.provider_name} requires {self.key_env}. "
                "Nymbric did not fall back to another provider."
            )
        return self.api_key

    def check(self, *, probe: bool = False) -> ProviderStatus:
        del probe
        try:
            key = self._require_key()
        except ProviderUnavailable as exc:
            return ProviderStatus(provider=self.provider_name, ok=False, model=self.model, detail=str(exc))
        try:
            response = self._http().get(
                f"{self.base_url}/models",
                headers={"Authorization": f"Bearer {key}"},
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return ProviderStatus(
                provider=self.provider_name,
                ok=False,
                model=self.model,
                detail=f"{self.provider_name} is not reachable at {self.base_url}: {exc}. No fallback was used.",
            )
        names = [item.get("id", "") for item in response.json().get("data", []) if isinstance(item, dict)]
        return ProviderStatus(
            provider=self.provider_name,
            ok=True,
            model=self.model,
            available_models=names[:50],
            detail=f"{self.provider_name} accepted the credentials. Tool support still depends on the selected model.",
            supports_tools=None,
            supports_structured_output=None,
        )

    def generate(self, request: ModelRequest) -> ModelResponse:
        key = self._require_key()
        payload: dict[str, Any] = {
            "model": self.model,
            "temperature": request.temperature or self.temperature,
            "messages": request.messages,
        }
        if request.tools:
            payload["tools"] = request.tools
        if request.response_schema:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "nymbric_result", "schema": request.response_schema},
            }
        started = time.perf_counter()
        try:
            response = self._http().post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {key}"},
                json=payload,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ProviderUnavailable(
                f"{self.provider_name} request failed for model '{self.model}': {exc}. No fallback was used."
            ) from exc
        body = response.json()
        message = ((body.get("choices") or [{}])[0].get("message") or {})
        calls = []
        for index, call in enumerate(message.get("tool_calls") or []):
            function = call.get("function") or {}
            calls.append(
                ToolCall(
                    id=str(call.get("id") or index),
                    name=str(function.get("name")),
                    arguments=tool_arguments(function.get("arguments") or {}),
                )
            )
        text = message.get("content") or ""
        structured = None
        if request.response_schema and text and not calls:
            try:
                structured = parse_json_object(text)
            except ProviderUnavailable:
                raise
            except Exception:
                structured = None
        usage_raw = body.get("usage") or {}
        usage = TokenUsage(
            prompt_tokens=int(usage_raw.get("prompt_tokens") or 0),
            completion_tokens=int(usage_raw.get("completion_tokens") or 0),
            total_tokens=int(usage_raw.get("total_tokens") or 0),
        )
        return ModelResponse(
            text=text or None,
            tool_calls=calls,
            structured=structured,
            usage=usage,
            latency_ms=(time.perf_counter() - started) * 1000,
            provider=self.provider_name,
            model=self.model,
            finish_reason=((body.get("choices") or [{}])[0].get("finish_reason") or "stop"),
        )


class OpenAIProvider(_OpenAIStyleProvider):
    provider_name = "openai"

    def __init__(self, model: str, **kwargs: Any):
        api_key = kwargs.pop("api_key", None) or os.environ.get("OPENAI_API_KEY")
        super().__init__(
            model,
            base_url=kwargs.pop("base_url", None) or "https://api.openai.com/v1",
            api_key=api_key,
            key_env="OPENAI_API_KEY",
            **kwargs,
        )


class OpenAICompatibleProvider(_OpenAIStyleProvider):
    provider_name = "openai_compatible"

    def __init__(self, model: str, *, base_url: str, **kwargs: Any):
        api_key = kwargs.pop("api_key", None) or os.environ.get("OPENAI_COMPATIBLE_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if not base_url:
            raise ProviderUnavailable(
                "openai_compatible requires base_url in the model configuration. No fallback was used."
            )
        super().__init__(model, base_url=base_url, api_key=api_key, key_env="OPENAI_COMPATIBLE_API_KEY", **kwargs)
