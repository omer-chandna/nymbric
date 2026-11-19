"""Minimal JSON-RPC-over-HTTP client for the live target session.

Shared by the reference client and the MCP bridge. It speaks the four methods the
:class:`~nymbric.agents.target.live_server.ToolSessionServer` exposes and keeps no
agent logic of its own, so a reference agent can be written against a handful of
plain method calls.
"""

from __future__ import annotations

import itertools
import os
from typing import Any

import httpx


class LiveToolError(RuntimeError):
    """A JSON-RPC error returned by the live target server."""


class LiveToolClient:
    def __init__(self, base_url: str, token: str, *, timeout_s: float = 30.0, client: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout_s = timeout_s
        self._client = client
        self._owns_client = client is None
        self._ids = itertools.count(1)

    @classmethod
    def from_env(cls, *, timeout_s: float = 30.0) -> "LiveToolClient":
        """Build a client from the env vars Nymbric sets for a spawned agent."""
        base_url = os.environ.get("NYMBRIC_TARGET_URL")
        token = os.environ.get("NYMBRIC_TARGET_TOKEN", "")
        if not base_url:
            raise LiveToolError("NYMBRIC_TARGET_URL is not set. This client must be launched by a Nymbric live run.")
        return cls(base_url, token, timeout_s=timeout_s)

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout_s)
        return self._client

    def _rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params or {}}
        headers = {"Authorization": f"Bearer {self.token}"}
        response = self._http().post(self.base_url, json=payload, headers=headers)
        response.raise_for_status()
        body = response.json()
        if isinstance(body, dict) and body.get("error"):
            error = body["error"]
            raise LiveToolError(f"{error.get('code')}: {error.get('message')}")
        result = body.get("result") if isinstance(body, dict) else None
        return result if isinstance(result, dict) else {}

    # -- protocol methods --------------------------------------------------
    def initialize(self) -> dict[str, Any]:
        return self._rpc("initialize")

    def list_tools(self) -> list[dict[str, Any]]:
        return self._rpc("tools/list").get("tools") or []

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Invoke one tool. Returns the raw tool output dict (the env's response)."""
        result = self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        return result.get("output") if isinstance(result.get("output"), dict) else result

    def finish(self, decision: str, rationale: str = "") -> dict[str, Any]:
        return self._rpc("session/finish", {"decision": decision, "rationale": rationale})

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "LiveToolClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
