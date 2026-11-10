"""Web research specialist."""

from __future__ import annotations

from nymbric.agents.loop import run_tool_loop
from nymbric.agents.prompts import WEB_PROMPT, system_message, user_payload
from nymbric.schemas.messages import ResearchEvidence, ResearchTask


class WebResearchAgent:
    role = "web_research"

    def __init__(self, model):
        self.model = model

    def run(self, task: ResearchTask, registry, trace, budget, deadline, cancel_event=None) -> dict:
        messages = [system_message(WEB_PROMPT), user_payload(task.model_dump())]
        return run_tool_loop(
            role=self.role,
            model=self.model,
            registry=registry,
            messages=messages,
            schema=ResearchEvidence,
            budget=budget,
            trace=trace,
            stage="research",
            task_id=task.task_id,
            deadline=deadline,
            cancel_event=cancel_event,
        )
