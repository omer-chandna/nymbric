"""Scenario specialist. It sees permitted evidence and no verifier labels."""

from __future__ import annotations

from nymbric.agents.loop import run_tool_loop
from nymbric.agents.prompts import SCENARIO_PROMPT, system_message, user_payload
from nymbric.schemas.messages import ScenarioGenerationTask, ScenarioResult
from nymbric.tools.registry import ToolRegistry


class ScenarioAgent:
    role = "scenario"

    def __init__(self, model):
        self.model = model

    def run(self, task: ScenarioGenerationTask, registry: ToolRegistry, trace, budget, deadline, cancel_event=None) -> dict:
        messages = [system_message(SCENARIO_PROMPT), user_payload(task.model_dump())]
        return run_tool_loop(
            role=self.role,
            model=self.model,
            registry=registry,
            messages=messages,
            schema=ScenarioResult,
            budget=budget,
            trace=trace,
            stage="scenario",
            task_id=task.task_id,
            deadline=deadline,
            cancel_event=cancel_event,
        )
