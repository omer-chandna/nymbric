"""Tool-use loop shared by model-backed agents."""

from __future__ import annotations

import json
import time
from typing import Any

from pydantic import BaseModel, ValidationError

from nymbric.core.errors import BudgetExceeded, Cancelled, StructuredOutputError
from nymbric.execution.trace import TraceSink
from nymbric.models.base import ModelRequest
from nymbric.models.providers._parse import parse_json_object
from nymbric.schemas.messages import Budget
from nymbric.tools.registry import ToolRegistry


def trim_messages(messages: list[dict[str, Any]], max_chars: int = 48000) -> list[dict[str, Any]]:
    """Keep the task and the latest observations. Drop bulky traversals first.

    Tool names stay on the retained messages so a deterministic policy does not
    repeat work it has already done.
    """
    kept = list(messages)
    def size() -> int:
        return len(json.dumps(kept))

    def drop_named(name: str) -> bool:
        for index, message in enumerate(kept):
            if message.get("role") == "tool" and message.get("name") == name:
                if index > 0 and kept[index - 1].get("role") == "assistant":
                    del kept[index - 1 : index + 1]
                else:
                    del kept[index]
                return True
        return False

    while size() > max_chars and drop_named("traverse_graph"):
        continue
    while size() > max_chars and len(kept) > 2:
        # Drop the oldest non-system, non-initial-user message.
        for index, message in enumerate(kept):
            if message.get("role") != "system" and not (message.get("role") == "user" and index == 1):
                del kept[index]
                break
        else:
            break
    return kept


def run_tool_loop(
    *,
    role: str,
    model,
    registry: ToolRegistry,
    messages: list[dict[str, Any]],
    schema: type[BaseModel],
    budget: Budget,
    trace: TraceSink,
    stage: str,
    task_id: str,
    deadline: float,
    max_retries: int = 2,
    temperature: float = 0,
    turn: str | None = None,
    cancel_event=None,
) -> dict[str, Any]:
    force = False
    failures = 0
    schema_json = schema.model_json_schema()
    for _step in range(budget.max_steps):
        if cancel_event is not None and cancel_event.is_set():
            raise Cancelled("The run was cancelled.")
        if time.monotonic() > deadline:
            raise BudgetExceeded("The run exceeded its time budget.")
        if budget.tokens_used >= budget.max_tokens:
            raise BudgetExceeded("The run exceeded its token budget.")
        response = model.generate(
            ModelRequest(
                agent_role=role,
                messages=trim_messages(messages),
                tools=[] if force else registry.openai_tools(),
                response_schema=schema_json if force or not registry.specs else None,
                temperature=temperature,
                force_final=force,
            )
        )
        budget.tokens_used += response.usage.total_tokens
        trace.emit(
            "model_call",
            stage=stage,
            agent=role,
            task_id=task_id,
            payload={
                "provider": response.provider,
                "model": response.model,
                "latency_ms": round(response.latency_ms, 3),
                "usage": response.usage.model_dump(),
                "finish_reason": response.finish_reason,
                "tool_calls": [call.name for call in response.tool_calls],
                "forced_final": force,
            },
        )
        if response.tool_calls and not force:
            for call in response.tool_calls:
                result = registry.invoke(call.name, call.arguments, turn=turn)
                messages.append(
                    {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [{"id": call.id, "name": call.name, "arguments": call.arguments}],
                    }
                )
                messages.append(
                    {
                        "role": "tool",
                        "name": call.name,
                        "tool_call_id": call.id,
                        "content": json.dumps(result),
                    }
                )
            continue
        payload = response.structured
        if payload is None and response.text:
            try:
                payload = parse_json_object(response.text)
            except StructuredOutputError:
                payload = None
        if payload is not None:
            try:
                return schema.model_validate(payload).model_dump()
            except ValidationError as exc:
                failures += 1
                if failures > max_retries:
                    raise StructuredOutputError(
                        f"{role} returned an object that failed schema validation after {failures} attempts."
                    ) from exc
                messages.append(
                    {
                        "role": "user",
                        "content": "The previous object failed validation. Return one JSON object that matches the schema. "
                        + str(exc.errors()[:3]),
                    }
                )
                force = True
                trace.emit(
                    "retry",
                    stage=stage,
                    agent=role,
                    task_id=task_id,
                    payload={"reason": "structured_output_validation", "attempt": failures},
                )
                continue
        failures += 1
        if failures > max_retries:
            raise StructuredOutputError(f"{role} did not return a valid structured result.")
        force = True
        messages.append(
            {
                "role": "user",
                "content": "Return one JSON object matching the required schema. Do not call tools.",
            }
        )
    raise StructuredOutputError(f"{role} exhausted its step budget without a valid result.")
