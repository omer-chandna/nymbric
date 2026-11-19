"""Lure specialist. It sees permitted evidence and no verifier labels.

It produces one inert `PhishingArtifact`. The orchestrator binds the verifier-only
ground truth (which link/attachment is the attacker's) separately.
"""

from __future__ import annotations

from nymbric.agents.loop import run_tool_loop
from nymbric.agents.prompts import LURE_PROMPT, system_message, user_payload
from nymbric.schemas.messages import LureGenerationTask, PhishingArtifact
from nymbric.tools.registry import ToolRegistry


class LureAgent:
    role = "lure"

    def __init__(self, model):
        self.model = model

    def run(self, task: LureGenerationTask, registry: ToolRegistry, trace, budget, deadline, cancel_event=None) -> dict:
        messages = [system_message(LURE_PROMPT), user_payload(task.model_dump())]
        return run_tool_loop(
            role=self.role,
            model=self.model,
            registry=registry,
            messages=messages,
            schema=PhishingArtifact,
            budget=budget,
            trace=trace,
            stage="lure",
            task_id=task.task_id,
            deadline=deadline,
            cancel_event=cancel_event,
        )
