"""Qualitative reviewer. Its scores are not security decisions."""

from __future__ import annotations

from nymbric.agents.loop import run_tool_loop
from nymbric.agents.prompts import EVAL_PROMPT, system_message, user_payload
from nymbric.schemas.messages import EvaluationResult
from nymbric.tools.registry import ToolRegistry


class EvaluationAgent:
    role = "evaluator"

    def __init__(self, model):
        self.model = model

    def run(self, payload: dict, registry: ToolRegistry, trace, budget, deadline, cancel_event=None) -> dict:
        messages = [system_message(EVAL_PROMPT), user_payload(payload)]
        return run_tool_loop(
            role=self.role,
            model=self.model,
            registry=registry,
            messages=messages,
            schema=EvaluationResult,
            budget=budget,
            trace=trace,
            stage="evaluate",
            task_id=str(payload.get("task_id", "eval")),
            deadline=deadline,
            cancel_event=cancel_event,
        )
