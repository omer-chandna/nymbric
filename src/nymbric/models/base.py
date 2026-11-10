"""Inference request and response types shared by every provider."""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class TokenUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ModelRequest(BaseModel):
    agent_role: str
    messages: list[dict[str, Any]]
    tools: list[dict[str, Any]] = Field(default_factory=list)
    response_schema: dict[str, Any] | None = None
    temperature: float = 0
    force_final: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class ModelResponse(BaseModel):
    text: str | None = None
    tool_calls: list[ToolCall] = Field(default_factory=list)
    structured: dict[str, Any] | None = None
    usage: TokenUsage = Field(default_factory=TokenUsage)
    latency_ms: float = 0
    provider: str
    model: str
    finish_reason: str = "stop"
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProviderStatus(BaseModel):
    provider: str
    ok: bool
    detail: str
    model: str | None = None
    available_models: list[str] = Field(default_factory=list)
    supports_tools: bool | None = None
    supports_structured_output: bool | None = None


class InferenceProvider(Protocol):
    provider_name: str
    model: str

    def generate(self, request: ModelRequest) -> ModelResponse: ...

    def check(self, *, probe: bool = False) -> ProviderStatus: ...
