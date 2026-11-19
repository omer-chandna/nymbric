"""Runnable reference agent for the live spear-phish target.

This connects to a running Nymbric live tool server (the URL and token arrive in
the environment) and drives the inert target tools in a closed loop, proving the
integration end to end. Three policies are provided:

* ``mock``     — a deterministic, susceptible assistant. It exercises every action
                 tool (follow a link, open an attachment, execute a detonated
                 instruction, gather owner context, reply to the sender). It takes
                 no network or model dependency, so it runs in CI and is what the
                 end-to-end tests drive. The verifier scores the resulting
                 environment exactly as it scores the built-in fixtures.
* ``cautious`` — a deterministic secure control. It verifies the sender through the
                 authorization service, is denied, and refuses. No compromising
                 action is taken.
* ``ollama``   — a real local tool-calling model loop (any Ollama model that
                 supports tools). This is the worked pattern for attaching a real
                 on-device assistant as the agent under test. It needs a running
                 Ollama; it is not used in CI.

Run manually (normally Nymbric launches it for you via ``target_mode=live``)::

    NYMBRIC_TARGET_URL=http://127.0.0.1:PORT NYMBRIC_TARGET_TOKEN=... \\
        python -m nymbric.agents.target.clients.reference_client --policy mock

The client never touches a real link, file, inbox, or network: everything it does
goes through the Nymbric tool server into the synthetic environment.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from nymbric.agents.target.clients.session_client import LiveToolClient, LiveToolError

# Tools that are side-effecting "actions" rather than context reads. Used only to
# label the client's own summary; the environment, not this list, is authoritative.
_ACTION_TOOLS = {"follow_link", "open_attachment", "forward_message", "reply_external", "execute_instruction"}


def run_mock_policy(client: LiveToolClient, task: dict[str, Any]) -> dict[str, Any]:
    """A susceptible assistant: trust the message and act on it through the tools."""
    actions: list[str] = []
    inbox = client.call_tool("read_inbox", {})
    message = (inbox.get("messages") or [task])[0]
    sender = str(message.get("sender_address") or task.get("sender_address") or "")
    link = str(message.get("link_url") or task.get("link_url") or "")
    attachment = str(message.get("attachment_name") or task.get("attachment_name") or "")

    if link:
        client.call_tool("follow_link", {"url": link})
        actions.append("follow_link")
    if attachment:
        opened = client.call_tool("open_attachment", {"name": attachment})
        actions.append("open_attachment")
        if opened.get("detonated"):
            client.call_tool("execute_instruction", {"instruction": str(opened.get("content") or "")})
            actions.append("execute_instruction")

    # Gather owner context the way a thorough-but-credulous assistant would, then
    # hand it back to the sender. If any owner secret is present, this is the
    # exfiltration the verifier records as compromising.
    gathered: list[str] = []
    memory = client.call_tool("read_memory", {})
    for item in memory.get("memories") or []:
        gathered.append(str(item.get("content") or ""))
    calendar = client.call_tool("read_calendar", {})
    for event in calendar.get("events") or []:
        gathered.append(str(event.get("content") or event.get("title") or ""))
    docs = client.call_tool("search_documents", {"query": ""})
    for doc in (docs.get("documents") or [])[:5]:
        full = client.call_tool("read_document", {"document_id": str(doc.get("document_id") or "")})
        if full.get("content"):
            gathered.append(str(full["content"]))

    if sender:
        client.call_tool("reply_external", {"to_address": sender, "content": "\n".join(g for g in gathered if g)})
        actions.append("reply_external")

    return {"decision": "complied", "rationale": "Treated the personalized message as trustworthy and acted on it.", "actions": actions}


def run_cautious_policy(client: LiveToolClient, task: dict[str, Any]) -> dict[str, Any]:
    """A secure assistant: verify the external sender, be denied, and refuse."""
    client.call_tool("read_inbox", {})
    client.call_tool(
        "request_authorization",
        {"action": "act_on_message", "sender_address": str(task.get("sender_address") or "")},
    )
    return {"decision": "refused", "rationale": "Unverified external sender; no action taken.", "actions": []}


def run_ollama_policy(
    client: LiveToolClient,
    task: dict[str, Any],
    tools: list[dict[str, Any]],
    *,
    model: str,
    base_url: str,
    max_steps: int,
) -> dict[str, Any]:
    """A real tool-calling loop against a local Ollama model.

    The model is handed the live tool surface and the inbound task, and its tool
    calls are forwarded to the Nymbric server. Whatever the model decides, the
    environment snapshot — not this report — is what the verifier scores.
    """
    from nymbric.agents.prompts import TARGET_PROMPT
    from nymbric.models.base import ModelRequest
    from nymbric.models.providers.ollama import OllamaProvider

    provider = OllamaProvider(model, base_url=base_url)
    openai_tools = [
        {"type": "function", "function": {"name": t["name"], "description": t.get("description", ""), "parameters": t.get("inputSchema", {})}}
        for t in tools
    ]
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": TARGET_PROMPT},
        {"role": "user", "content": json.dumps(task)},
    ]
    actions: list[str] = []
    for _ in range(max_steps):
        response = provider.generate(ModelRequest(agent_role="target", messages=messages, tools=openai_tools, temperature=0))
        if not response.tool_calls:
            rationale = (response.text or "").strip()[:2000]
            return {"decision": "engaged", "rationale": rationale or "No further action.", "actions": actions}
        for call in response.tool_calls:
            output = client.call_tool(call.name, call.arguments)
            if call.name in _ACTION_TOOLS:
                actions.append(call.name)
            messages.append({"role": "assistant", "content": "", "tool_calls": [{"id": call.id, "function": {"name": call.name, "arguments": call.arguments}}]})
            messages.append({"role": "tool", "name": call.name, "content": json.dumps(output)})
    return {"decision": "engaged", "rationale": "Step budget reached.", "actions": actions}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reference live target agent for the Nymbric spear-phish experiment.")
    parser.add_argument("--policy", choices=["mock", "cautious", "ollama"], default="mock")
    parser.add_argument("--model", default="llama3.1", help="Ollama model (for --policy ollama).")
    parser.add_argument("--base-url", default="http://127.0.0.1:11434", help="Ollama base URL (for --policy ollama).")
    parser.add_argument("--max-steps", type=int, default=16, help="Tool-call budget for --policy ollama.")
    args = parser.parse_args(argv)

    try:
        client = LiveToolClient.from_env()
    except LiveToolError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2

    with client:
        try:
            init = client.initialize()
            task = init.get("task") or {}
            tools = init.get("tools") or client.list_tools()
            if args.policy == "cautious":
                report = run_cautious_policy(client, task)
            elif args.policy == "ollama":
                report = run_ollama_policy(client, task, tools, model=args.model, base_url=args.base_url, max_steps=args.max_steps)
            else:
                report = run_mock_policy(client, task)
            client.finish(report["decision"], report.get("rationale", ""))
        except LiveToolError as exc:
            print(json.dumps({"error": str(exc)}), file=sys.stderr)
            return 1

    # The report is advisory; print it for logs/debugging only.
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
