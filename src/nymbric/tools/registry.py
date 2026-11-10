"""Central tool registry. Capability checks happen here, not in prompts."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from pydantic import BaseModel, ValidationError

from nymbric.core.types import Capability, SideEffect
from nymbric.execution.trace import TraceSink
from nymbric.schemas.messages import Budget


@dataclass
class ToolSpec:
    name: str
    description: str
    input_model: type[BaseModel]
    required: frozenset[Capability]
    side_effect: SideEffect
    timeout_s: float = 5
    cost: int = 1
    audit: bool = True


@dataclass
class ToolRegistry:
    specs: dict[str, ToolSpec]
    handlers: dict[str, Callable[[BaseModel], dict[str, Any]]]
    permissions: frozenset[Capability]
    budget: Budget
    trace: TraceSink
    stage: str
    agent: str
    task_id: str
    denials: list[dict[str, Any]] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)

    def openai_tools(self) -> list[dict[str, Any]]:
        exported = []
        for spec in self.specs.values():
            if not spec.required <= self.permissions:
                continue
            schema = spec.input_model.model_json_schema()
            schema.pop("title", None)
            exported.append(
                {
                    "type": "function",
                    "function": {
                        "name": spec.name,
                        "description": spec.description,
                        "parameters": schema,
                    },
                }
            )
        return exported

    def invoke(self, name: str, arguments: dict[str, Any] | None, *, turn: str | None = None) -> dict[str, Any]:
        spec = self.specs.get(name)
        if spec is None:
            return self._deny(name, arguments or {}, "unknown_tool")
        if not spec.required <= self.permissions:
            return self._deny(name, arguments or {}, "permission_denied", sorted(c.value for c in spec.required))
        if self.budget.tool_calls_used >= self.budget.max_tool_calls:
            return self._deny(name, arguments or {}, "tool_budget_exhausted")
        if name == "search_web" and self.budget.search_calls_used >= self.budget.max_search_calls:
            return self._deny(name, arguments or {}, "search_budget_exhausted")
        if name == "open_page" and self.budget.pages_read >= self.budget.max_pages_read:
            return self._deny(name, arguments or {}, "page_budget_exhausted")
        try:
            parsed = spec.input_model.model_validate(arguments or {})
        except ValidationError as exc:
            return {"error": "invalid_arguments", "detail": exc.errors()[:4]}
        started = time.perf_counter()
        try:
            output = self.handlers[name](parsed)
        except Exception as exc:  # tool bugs should surface in the trace, not escape as a successful result
            output = {"error": "tool_failed", "detail": type(exc).__name__}
        elapsed = time.perf_counter() - started
        self.budget.tool_calls_used += 1
        if name == "search_web":
            self.budget.search_calls_used += 1
        if name == "open_page" and "error" not in output:
            self.budget.pages_read += 1
        record = {
            "action_id": uuid.uuid4().hex,
            "tool": name,
            "arguments": arguments or {},
            "output": output,
            "allowed": "error" not in output or output.get("error") not in {"permission_denied", "blocked_by_mitigation"},
            "side_effect": spec.side_effect.value,
            "elapsed_s": round(elapsed, 6),
            "timeout_s": spec.timeout_s,
            "timed_out": elapsed > spec.timeout_s,
            "turn": turn,
            "task_id": self.task_id,
            "agent": self.agent,
        }
        self.calls.append(record)
        if spec.audit:
            self.trace.emit(
                "tool_call",
                stage=self.stage,
                agent=self.agent,
                task_id=self.task_id,
                payload=record,
            )
        return output

    def _deny(
        self,
        name: str,
        arguments: dict[str, Any],
        reason: str,
        required: list[str] | None = None,
    ) -> dict[str, Any]:
        payload = {"tool": name, "reason": reason, "required": required or [], "arguments": arguments}
        self.denials.append(payload)
        self.trace.emit(
            "tool_denied",
            stage=self.stage,
            agent=self.agent,
            task_id=self.task_id,
            payload=payload,
        )
        return {"error": reason, "tool": name}
