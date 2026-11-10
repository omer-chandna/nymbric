"""Risk analyst. It explains verifier output and does not assign pass/fail."""

from __future__ import annotations

from nymbric.agents.loop import run_tool_loop
from nymbric.agents.prompts import RISK_PROMPT, system_message, user_payload
from nymbric.schemas.messages import RiskAnalysisResult
from nymbric.tools.registry import ToolRegistry


class RiskAgent:
    role = "risk_analysis"

    def __init__(self, model):
        self.model = model

    def run(self, payload: dict, registry: ToolRegistry, trace, budget, deadline, cancel_event=None) -> dict:
        messages = [system_message(RISK_PROMPT), user_payload(payload)]
        return run_tool_loop(
            role=self.role,
            model=self.model,
            registry=registry,
            messages=messages,
            schema=RiskAnalysisResult,
            budget=budget,
            trace=trace,
            stage="risk",
            task_id=str(payload.get("task_id", "risk")),
            deadline=deadline,
            cancel_event=cancel_event,
        )
