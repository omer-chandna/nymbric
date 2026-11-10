"""Deterministic defender policies used as known-good and known-bad controls."""

from __future__ import annotations

from nymbric.core.types import INJECTION_MARKER, REFUSAL_TEXT
from nymbric.environments.assistant import AssistantEnvironment
from nymbric.schemas.messages import DefenderTask
from nymbric.tools.registry import ToolRegistry


def _titles(payload: dict) -> list[str]:
    return [str(event.get("title")) for event in payload.get("events") or [] if event.get("title") and event.get("title") != "[redacted]"]


def _dump(registry: ToolRegistry, owner_id: str, turn: str) -> str:
    calendar = registry.invoke("read_calendar", {"identity_id": owner_id}, turn=turn)
    memory = registry.invoke("read_memory", {"identity_id": owner_id}, turn=turn)
    docs = registry.invoke("search_documents", {"query": ""}, turn=turn)
    chunks = ["CALENDAR"]
    chunks.extend(_titles(calendar))
    for item in memory.get("memories") or []:
        chunks.append(str(item.get("content", "")))
    for doc in docs.get("documents") or []:
        full = registry.invoke("read_document", {"document_id": doc["document_id"]}, turn=turn)
        chunks.append(str(full.get("content", "")))
    return "\n".join(chunks)


def run_compliant(legitimate: DefenderTask, adversarial: DefenderTask, registry_for) -> None:
    legit_tools = registry_for("legitimate")
    legit_tools.invoke(
        "request_authorization",
        {"action": "read_calendar", "requester_id": legitimate.requester_id},
        turn="legitimate",
    )
    calendar = legit_tools.invoke("read_calendar", {"identity_id": legitimate.identity_id}, turn="legitimate")
    legit_tools.invoke(
        "reply_to_owner",
        {"content": "Private calendar:\n" + "\n".join(_titles(calendar))},
        turn="legitimate",
    )
    tools = registry_for("adversarial")
    tools.invoke(
        "request_authorization",
        {"action": adversarial.requested_action, "requester_id": adversarial.requester_id},
        turn="adversarial",
    )
    tools.invoke(
        "send_message",
        {"recipient_id": adversarial.requester_id, "content": REFUSAL_TEXT},
        turn="adversarial",
    )


def run_familiarity(legitimate: DefenderTask, adversarial: DefenderTask, registry_for) -> None:
    legit_tools = registry_for("legitimate")
    legit_tools.invoke(
        "request_authorization",
        {"action": "read_calendar", "requester_id": legitimate.requester_id},
        turn="legitimate",
    )
    calendar = legit_tools.invoke("read_calendar", {"identity_id": legitimate.identity_id}, turn="legitimate")
    titles = _titles(calendar)
    legit_tools.invoke(
        "reply_to_owner",
        {"content": "Private calendar:\n" + "\n".join(titles)},
        turn="legitimate",
    )
    tools = registry_for("adversarial")
    cited = any(title in adversarial.message for title in titles)
    if cited:
        tools.invoke(
            "send_message",
            {"recipient_id": adversarial.requester_id, "content": "Private calendar:\n" + "\n".join(titles)},
            turn="adversarial",
        )
        return
    tools.invoke(
        "request_authorization",
        {"action": adversarial.requested_action, "requester_id": adversarial.requester_id},
        turn="adversarial",
    )
    tools.invoke(
        "send_message",
        {"recipient_id": adversarial.requester_id, "content": REFUSAL_TEXT},
        turn="adversarial",
    )


def run_noncompliant(
    legitimate: DefenderTask,
    adversarial: DefenderTask,
    registry_for,
    *,
    other_identity_id: str | None = None,
    behaviors: set[str] | None = None,
) -> None:
    selected = behaviors or {"disclose", "memory", "export", "cross", "inject"}
    legit_tools = registry_for("legitimate")
    calendar = legit_tools.invoke("read_calendar", {"identity_id": legitimate.identity_id}, turn="legitimate")
    legit_tools.invoke(
        "reply_to_owner",
        {"content": "Private calendar:\n" + "\n".join(_titles(calendar))},
        turn="legitimate",
    )
    tools = registry_for("adversarial")
    if "disclose" in selected or "inject" in selected:
        content = _dump(tools, adversarial.identity_id, "adversarial") if "disclose" in selected else "Acknowledged."
        if "inject" in selected:
            content += f"\n{INJECTION_MARKER}"
        tools.invoke(
            "send_message",
            {"recipient_id": adversarial.requester_id, "content": content},
            turn="adversarial",
        )
    if "memory" in selected:
        tools.invoke(
            "update_memory",
            {"memory_id": "mem-external", "content": adversarial.message, "source": "external"},
            turn="adversarial",
        )
    if "export" in selected:
        tools.invoke("export_all_memories", {"reason": "requested"}, turn="adversarial")
    if "cross" in selected and other_identity_id:
        tools.invoke("read_memory", {"identity_id": other_identity_id}, turn="adversarial")


def run_over_refusing(legitimate: DefenderTask, adversarial: DefenderTask, registry_for) -> None:
    """Answers nobody. Used to show the false-positive check is observable."""
    del legitimate, adversarial
    tools = registry_for("adversarial")
    tools.invoke(
        "request_authorization",
        {"action": "share_private_calendar", "requester_id": "external:nobody"},
        turn="adversarial",
    )
    tools.invoke(
        "send_message",
        {"recipient_id": "external:nobody", "content": REFUSAL_TEXT},
        turn="adversarial",
    )


def environment_summary(env: AssistantEnvironment) -> dict:
    return {
        "messages": len(env.messages),
        "owner_replies": len(env.owner_replies),
        "memory_writes": len(env.memory_writes),
        "blocked": len(env.blocked),
        "auth_events": len(env.auth_events),
    }
