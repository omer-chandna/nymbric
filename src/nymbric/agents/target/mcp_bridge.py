"""MCP stdio bridge to the Nymbric live target server.

An MCP-capable agent attaches to Nymbric by launching this module as its MCP
server (stdio transport). The bridge speaks MCP JSON-RPC on stdin/stdout and
forwards tool discovery and tool calls to the live Nymbric tool server over HTTP
(the URL and token are inherited from the environment Nymbric set on the agent).
This keeps Nymbric free of an MCP protocol dependency while letting any standard
MCP client drive the inert target tools.

Launch chain for ``target_mode=live`` with a real MCP agent::

    Nymbric  --spawns-->  your MCP agent  (NYMBRIC_TARGET_URL / _TOKEN in env)
                              |
                              +--spawns MCP server-->  python -m nymbric.agents.target.mcp_bridge
                                                           |
                                                           +--HTTP JSON-RPC-->  Nymbric tool server (inert env)

MCP methods handled: ``initialize``, ``notifications/initialized``, ``tools/list``,
``tools/call``, ``ping``. Tool results are returned as MCP content blocks; the raw
tool output is also attached as ``structuredContent``. Everything resolves to the
synthetic environment — the bridge cannot reach a real link, file, or network.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from nymbric.agents.target.clients.session_client import LiveToolClient, LiveToolError

MCP_PROTOCOL_VERSION = "2024-11-05"
_METHOD_NOT_FOUND = -32601
_INTERNAL_ERROR = -32000


class McpStdioBridge:
    def __init__(self, client: LiveToolClient):
        self.client = client

    def handle_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Handle one JSON-RPC message. Returns a response, or None for a notification."""
        method = message.get("method")
        request_id = message.get("id")
        params = message.get("params") or {}
        if request_id is None:
            # Notification (e.g. notifications/initialized). Nothing to answer.
            return None
        try:
            result = self._dispatch(str(method), params if isinstance(params, dict) else {})
        except LiveToolError as exc:
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": _INTERNAL_ERROR, "message": str(exc)}}
        except _BridgeMethodError as exc:
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": _METHOD_NOT_FOUND, "message": str(exc)}}
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            # Warm the backend session so the inbound task is loaded, then return
            # the MCP handshake with a tools capability.
            self.client.initialize()
            requested = str(params.get("protocolVersion") or MCP_PROTOCOL_VERSION)
            return {
                "protocolVersion": requested,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "nymbric-target", "version": "1"},
            }
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": self.client.list_tools()}
        if method == "tools/call":
            name = params.get("name")
            if not isinstance(name, str) or not name:
                raise _BridgeMethodError("tools/call requires a string 'name'.")
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            output = self.client.call_tool(name, arguments)
            is_error = isinstance(output, dict) and "error" in output
            return {
                "content": [{"type": "text", "text": json.dumps(output)}],
                "isError": bool(is_error),
                "structuredContent": output,
            }
        raise _BridgeMethodError(f"Unknown MCP method '{method}'.")

    def serve(self, stdin, stdout) -> None:
        """Run the stdio loop until EOF, then finish the Nymbric session."""
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(message, dict):
                continue
            response = self.handle_message(message)
            if response is not None:
                stdout.write(json.dumps(response) + "\n")
                stdout.flush()
        # The MCP host closed the connection; tell Nymbric the session is over.
        try:
            self.client.finish("engaged", "MCP session closed.")
        except LiveToolError:
            pass


class _BridgeMethodError(Exception):
    pass


def main(argv: list[str] | None = None) -> int:
    del argv
    try:
        client = LiveToolClient.from_env()
    except LiveToolError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    with client:
        McpStdioBridge(client).serve(sys.stdin, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
