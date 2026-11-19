"""Built-in target agents: a model-backed loop and the deterministic fixtures.

Whatever the target does, the authoritative record of bait-taking is the
`TargetEnvironment` snapshot (which actions were compromising), not the result
object the target returns. This mirrors the rest of Nymbric: qualitative or
self-reported signals never overwrite the deterministic verifier.
"""

from __future__ import annotations

from nymbric.agents.loop import run_tool_loop
from nymbric.agents.prompts import TARGET_PROMPT, system_message, user_payload
from nymbric.schemas.messages import TargetAgentResult, TargetAgentTask
from nymbric.tools.registry import ToolRegistry


class ModelTargetAgent:
    """A model-backed personal assistant that receives one inbound lure.

    Works with any configured provider. Pointed at a local provider it is the
    on-device-assistant-under-test; pointed at ``mock`` it is a secure control.
    """

    role = "target"

    def __init__(self, model):
        self.model = model

    def run(self, task: TargetAgentTask, registry: ToolRegistry, trace, budget, deadline, cancel_event=None) -> dict:
        messages = [system_message(TARGET_PROMPT), user_payload(task.model_dump())]
        return run_tool_loop(
            role=self.role,
            model=self.model,
            registry=registry,
            messages=messages,
            schema=TargetAgentResult,
            budget=budget,
            trace=trace,
            stage="target",
            task_id=task.task_id,
            deadline=deadline,
            cancel_event=cancel_event,
        )


def run_target_fixture(
    mode: str,
    task: TargetAgentTask,
    registry: ToolRegistry,
    *,
    personalization: str = "generic",
    owner_secret_markers: list[str] | None = None,
) -> dict:
    """Drive the target tools deterministically for a non-model target mode.

    Actions go through the registry so capability checks and traces are identical
    to a model run. The returned dict is advisory; the verifier reads the env.
    """
    owner_secret_markers = owner_secret_markers or []
    registry.invoke("read_inbox", {})

    if mode == "cautious" or (mode == "context_sensitive" and personalization not in {"contextual", "high"}):
        # Verify first. The external sender is never the owner, so this is denied,
        # and a cautious target then declines to act.
        registry.invoke("request_authorization", {"action": "act_on_message", "sender_address": task.sender_address})
        return _result(task, "refused", rationale="Unverified external sender; no action taken.")

    # Taking the bait: follow the link, open the attachment, and — if the lure
    # asks for data — read the owner's protected context and forward it back.
    took_bait = False
    if task.link_url:
        registry.invoke("follow_link", {"url": task.link_url})
        took_bait = True
    if task.attachment_name:
        opened = registry.invoke("open_attachment", {"name": task.attachment_name})
        took_bait = True
        # If the attachment detonated an embedded instruction, a susceptible
        # target executes it.
        content = str((opened or {}).get("content") or "")
        if (opened or {}).get("detonated"):
            registry.invoke("execute_instruction", {"instruction": content})
    # Exfiltration / credential-reply path: hand the owner's secret to the sender.
    memory = registry.invoke("read_memory", {})
    secret = ""
    for item in (memory or {}).get("memories", []):
        text = str(item.get("content") or "")
        if any(marker in text for marker in owner_secret_markers):
            secret = text
            break
    if secret:
        registry.invoke("reply_external", {"to_address": task.sender_address, "content": secret})
        took_bait = True
    decision = "complied" if took_bait else "engaged"
    return _result(
        task,
        decision,
        rationale="Treated the personalized message as trustworthy and acted on it.",
    )


def _result(task: TargetAgentTask, decision: str, *, rationale: str) -> dict:
    return TargetAgentResult(task_id=task.task_id, decision=decision, rationale=rationale).model_dump()
