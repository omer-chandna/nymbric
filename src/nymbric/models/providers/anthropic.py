"""Anthropic Messages API adapter."""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

from nymbric.core.errors import ProviderUnavailable
from nymbric.models.base import ModelRequest, ModelResponse, ProviderStatus, TokenUsage, ToolCall
from nymbric.models.providers._parse import parse_json_object, tool_arguments


class AnthropicProvider:
    provider_name = "anthropic"

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        base_url: str = "https://api.anthropic.com",
        timeout_s: float = 120,
        temperature: float = 0,
        client: httpx.Client | None = None,
    ):
        self.model = model
        self.api_key = api_key if api_key is not None else os.environ.get("ANTHROPIC_API_KEY")
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.temperature = temperature
        self._client = client

    def _http(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        return httpx.Client(timeout=self.timeout_s)

    def check(self, *, probe: bool = False) -> ProviderStatus:
        del probe
        if not self.api_key:
            return ProviderStatus(
                provider=self.provider_name,
                ok=False,
                model=self.model,
                detail="Anthropic requires ANTHROPIC_API_KEY. Nymbric did not fall back to another provider.",
            )
        try:
            response = self._http().get(
                f"{self.base_url}/v1/models",
                headers=self._headers(),
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return ProviderStatus(
                provider=self.provider_name,
                ok=False,
                model=self.model,
                detail=f"Anthropic is not reachable: {exc}. No fallback was used.",
            )
        return ProviderStatus(
            provider=self.provider_name,
            ok=True,
            model=self.model,
            detail="Anthropic accepted the credentials.",
            supports_tools=None,
            supports_structured_output=None,
        )

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self.api_key or "",
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

    def generate(self, request: ModelRequest) -> ModelResponse:
        if not self.api_key:
            raise ProviderUnavailable(
                "Anthropic requires ANTHROPIC_API_KEY. Nymbric did not fall back to another provider."
            )
        system = "\n".join(message["content"] for message in request.messages if message.get("role") == "system")
        messages = []
        for message in request.messages:
            role = message.get("role")
            if role == "system":
                continue
            if role == "tool":
                messages.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": message.get("tool_call_id", "tool"),
                                "content": message.get("content", ""),
                            }
                        ],
                    }
                )
            elif role == "assistant" and message.get("tool_calls"):
                blocks = []
                for call in message["tool_calls"]:
                    blocks.append(
                        {
                            "type": "tool_use",
                            "id": call.get("id", "tool"),
                            "name": call.get("name"),
                            "input": call.get("arguments") or {},
                        }
                    )
                messages.append({"role": "assistant", "content": blocks})
            else:
                mapped = "assistant" if role == "assistant" else "user"
                messages.append({"role": mapped, "content": message.get("content", "")})
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 2048,
            "temperature": request.temperature or self.temperature,
            "messages": messages or [{"role": "user", "content": ""}],
        }
        if system:
            payload["system"] = system
        if request.tools:
            payload["tools"] = [
                {
                    "name": tool["function"]["name"],
                    "description": tool["function"].get("description", ""),
                    "input_schema": tool["function"].get("parameters") or {"type": "object"},
                }
                for tool in request.tools
            ]
        started = time.perf_counter()
        try:
            response = self._http().post(f"{self.base_url}/v1/messages", headers=self._headers(), json=payload)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ProviderUnavailable(f"Anthropic request failed for model '{self.model}': {exc}. No fallback was used.") from exc
        body = response.json()
        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for block in body.get("content") or []:
            if block.get("type") == "text":
                text_parts.append(block.get("text") or "")
            elif block.get("type") == "tool_use":
                calls.append(
                    ToolCall(
                        id=str(block.get("id")),
                        name=str(block.get("name")),
                        arguments=tool_arguments(block.get("input") or {}),
                    )
                )
        text = "\n".join(part for part in text_parts if part)
        structured = None
        if request.response_schema and text and not calls:
            try:
                structured = parse_json_object(text)
            except Exception:
                structured = None
        usage_raw = body.get("usage") or {}
        usage = TokenUsage(
            prompt_tokens=int(usage_raw.get("input_tokens") or 0),
            completion_tokens=int(usage_raw.get("output_tokens") or 0),
            total_tokens=int(usage_raw.get("input_tokens") or 0) + int(usage_raw.get("output_tokens") or 0),
        )
        return ModelResponse(
            text=text or None,
            tool_calls=calls,
            structured=structured,
            usage=usage,
            latency_ms=(time.perf_counter() - started) * 1000,
            provider=self.provider_name,
            model=self.model,
            finish_reason=str(body.get("stop_reason") or "stop"),
        )
