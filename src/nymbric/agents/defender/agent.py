"""Model-backed defender. Fixtures in fixtures.py implement the same tool surface."""

from __future__ import annotations

from nymbric.agents.loop import run_tool_loop
from nymbric.agents.prompts import DEFENDER_PROMPT, system_message, user_payload
from nymbric.schemas.messages import DefenderResult, DefenderTask


class DefenderAgent:
    role = "defender"

    def __init__(self, model):
        self.model = model

    def run(self, task: DefenderTask, registry, trace, budget, deadline, cancel_event=None) -> dict:
        messages = [system_message(DEFENDER_PROMPT), user_payload(task.model_dump())]
        return run_tool_loop(
            role=self.role,
            model=self.model,
            registry=registry,
            messages=messages,
            schema=DefenderResult,
            budget=budget,
            trace=trace,
            stage="defend",
            task_id=task.task_id,
            deadline=deadline,
            turn=task.turn,
            cancel_event=cancel_event,
        )
