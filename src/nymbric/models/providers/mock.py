"""Deterministic mock inference. It never contacts another provider."""

from __future__ import annotations

import time
import uuid

from nymbric.models.base import ModelRequest, ModelResponse, ProviderStatus, TokenUsage, ToolCall
from nymbric.models.providers.mock_reader import (
    defender_decision,
    evaluation_from_task,
    graph_decision,
    lure_from_task,
    recipient_from_task,
    risk_from_task,
    scenario_from_task,
    target_decision,
    web_decision,
)

_HANDLERS = {
    "web_research": web_decision,
    "graph_research": graph_decision,
    "defender": defender_decision,
    "target": target_decision,
}


class MockProvider:
    provider_name = "mock"

    def __init__(self, model: str = "mock-deterministic"):
        self.model = model or "mock-deterministic"

    def check(self, *, probe: bool = False) -> ProviderStatus:
        del probe
        return ProviderStatus(
            provider=self.provider_name,
            ok=True,
            detail="Deterministic mock inference is available. No network provider was contacted.",
            model=self.model,
            available_models=[self.model],
            supports_tools=True,
            supports_structured_output=True,
        )

    def generate(self, request: ModelRequest) -> ModelResponse:
        started = time.perf_counter()
        role = request.agent_role
        if role in _HANDLERS:
            decision = _HANDLERS[role](request.messages, force_final=request.force_final or bool(request.response_schema and not request.tools))
        elif role == "scenario":
            decision = {"final": scenario_from_task(request.messages)}
        elif role == "lure":
            decision = {"final": lure_from_task(request.messages)}
        elif role == "evaluator":
            decision = {"final": evaluation_from_task(request.messages)}
        elif role == "risk_analysis":
            decision = {"final": risk_from_task(request.messages)}
        elif role == "recipient":
            decision = {"final": recipient_from_task(request.messages)}
        else:
            decision = {"final": {"error": f"unsupported mock role {role}"}}
        latency = (time.perf_counter() - started) * 1000
        prompt_tokens = max(1, sum(len(str(message.get("content", ""))) for message in request.messages) // 4)
        if "tool" in decision and not request.force_final:
            call = decision["tool"]
            completion = 16
            return ModelResponse(
                tool_calls=[ToolCall(id=f"mock-{uuid.uuid4().hex[:8]}", name=call["name"], arguments=call["arguments"])],
                usage=TokenUsage(prompt_tokens=prompt_tokens, completion_tokens=completion, total_tokens=prompt_tokens + completion),
                latency_ms=latency,
                provider=self.provider_name,
                model=self.model,
                finish_reason="tool_calls",
            )
        final = decision.get("final") or {}
        completion = max(1, len(str(final)) // 4)
        return ModelResponse(
            text=None,
            structured=final,
            usage=TokenUsage(prompt_tokens=prompt_tokens, completion_tokens=completion, total_tokens=prompt_tokens + completion),
            latency_ms=latency,
            provider=self.provider_name,
            model=self.model,
            finish_reason="stop",
        )
