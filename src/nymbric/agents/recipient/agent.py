"""Optional simulated recipient. Results stay labeled as model simulations."""

from __future__ import annotations

from nymbric.agents.loop import run_tool_loop
from nymbric.agents.prompts import RECIPIENT_PROMPT, system_message, user_payload
from nymbric.schemas.messages import RecipientSimulation
from nymbric.tools.registry import ToolRegistry


class RecipientAgent:
    role = "recipient"

    def __init__(self, model):
        self.model = model

    def run(self, payload: dict, registry: ToolRegistry, trace, budget, deadline, cancel_event=None) -> dict:
        messages = [system_message(RECIPIENT_PROMPT), user_payload(payload)]
        return run_tool_loop(
            role=self.role,
            model=self.model,
            registry=registry,
            messages=messages,
            schema=RecipientSimulation,
            budget=budget,
            trace=trace,
            stage="defend",
            task_id=str(payload.get("task_id", "recipient")),
            deadline=deadline,
            cancel_event=cancel_event,
        )
