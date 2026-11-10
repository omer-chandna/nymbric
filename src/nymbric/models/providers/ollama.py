"""Ollama local inference. Connection failure is reported and never rerouted."""

from __future__ import annotations

import time
from typing import Any

import httpx

from nymbric.core.errors import ProviderUnavailable, StructuredOutputError
from nymbric.models.base import ModelRequest, ModelResponse, ProviderStatus, TokenUsage, ToolCall
from nymbric.models.providers._parse import parse_json_object, tool_arguments


class OllamaProvider:
    provider_name = "ollama"

    def __init__(
        self,
        model: str,
        *,
        base_url: str = "http://127.0.0.1:11434",
        timeout_s: float = 120,
        temperature: float = 0,
        num_ctx: int = 8192,
        client: httpx.Client | None = None,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.temperature = temperature
        self.num_ctx = num_ctx
        self._client = client

    def _http(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        return httpx.Client(timeout=self.timeout_s)

    def check(self, *, probe: bool = False) -> ProviderStatus:
        try:
            response = self._http().get(f"{self.base_url}/api/tags")
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return ProviderStatus(
                provider=self.provider_name,
                ok=False,
                model=self.model,
                detail=(
                    f"Ollama is not reachable at {self.base_url}: {exc}. "
                    "Start Ollama and pull the configured model, or rerun with --provider mock. "
                    "Nymbric did not switch providers."
                ),
            )
        payload = response.json()
        names = [item.get("name", "") for item in payload.get("models", []) if item.get("name")]
        present = self.model in names or any(name == self.model or name.startswith(f"{self.model}:") for name in names)
        detail = "Ollama is reachable."
        if not present:
            detail = (
                f"Ollama is reachable at {self.base_url}, but '{self.model}' is not in the local library. "
                f"Pull it with `ollama pull {self.model}`. Nymbric did not switch providers."
            )
        supports_tools = None
        supports_structured = None
        if probe and present:
            supports_tools, supports_structured, probe_detail = self._probe()
            detail = probe_detail
        return ProviderStatus(
            provider=self.provider_name,
            ok=present and (supports_structured is not False),
            model=self.model,
            available_models=names,
            detail=detail,
            supports_tools=supports_tools,
            supports_structured_output=supports_structured,
        )

    def _probe(self) -> tuple[bool | None, bool | None, str]:
        schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}
        try:
            response = self.generate(
                ModelRequest(
                    agent_role="probe",
                    messages=[{"role": "user", "content": "Return the JSON object {\"ok\": true}."}],
                    response_schema=schema,
                    temperature=0,
                )
            )
        except (ProviderUnavailable, StructuredOutputError) as exc:
            return None, False, f"Structured-output probe failed for {self.model}: {exc}"
        ok = bool(response.structured and response.structured.get("ok") is True)
        return True, ok, "Ollama answered a structured-output probe." if ok else "Ollama responded, but the probe object was not valid."

    def generate(self, request: ModelRequest) -> ModelResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": request.messages,
            "stream": False,
            "think": False,
            "options": {"temperature": request.temperature or self.temperature, "num_ctx": self.num_ctx},
        }
        if request.tools:
            payload["tools"] = request.tools
        if request.response_schema:
            payload["format"] = request.response_schema
        started = time.perf_counter()
        try:
            response = self._http().post(f"{self.base_url}/api/chat", json=payload)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ProviderUnavailable(
                f"Ollama request to {self.base_url} failed for model '{self.model}': {exc}. "
                "Nymbric did not fall back to another provider."
            ) from exc
        body = response.json()
        message = body.get("message") or {}
        calls = []
        for index, call in enumerate(message.get("tool_calls") or []):
            function = call.get("function") or call
            calls.append(
                ToolCall(
                    id=str(call.get("id") or f"ollama-{index}"),
                    name=str(function.get("name")),
                    arguments=tool_arguments(function.get("arguments")),
                )
            )
        text = message.get("content") or ""
        structured = None
        if request.response_schema and not calls:
            try:
                structured = parse_json_object(text)
            except StructuredOutputError:
                structured = None
                text = text
        usage = TokenUsage(
            prompt_tokens=int(body.get("prompt_eval_count") or 0),
            completion_tokens=int(body.get("eval_count") or 0),
            total_tokens=int(body.get("prompt_eval_count") or 0) + int(body.get("eval_count") or 0),
        )
        return ModelResponse(
            text=text or None,
            tool_calls=calls,
            structured=structured,
            usage=usage,
            latency_ms=(time.perf_counter() - started) * 1000,
            provider=self.provider_name,
            model=self.model,
            finish_reason="tool_calls" if calls else "stop",
            metadata={"done": body.get("done")},
        )
