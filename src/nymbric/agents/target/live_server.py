"""A live, in-process tool server for the spear-phish target.

This is the closed-loop counterpart to ``ExternalCommandTarget``. Instead of an
agent reporting an action log once and Nymbric replaying it, the agent connects
to this server and drives the inert target tools *interactively*: it reads a tool
result and then decides its next action, exactly as a deployed assistant would.

Transport: JSON-RPC 2.0 over a localhost-only HTTP endpoint. The server is bound
to one run's :class:`~nymbric.environments.target.TargetEnvironment` through the
normal :func:`~nymbric.tools.builtin.build_target_registry`, so capability checks,
budgets, and traces are identical to a built-in target. A thin MCP stdio bridge
(:mod:`nymbric.agents.target.mcp_bridge`) forwards MCP ``tools/call`` requests to
this same endpoint, so any MCP-capable agent can attach without Nymbric growing a
protocol dependency.

Inertness is structural: the only thing this server can do is invoke the
registry's handlers against the synthetic environment. There is no code path to a
real link, file, inbox, or network — the registry denies unknown tools, and every
"action" tool mutates the in-memory env and returns synthetic text.

Methods
-------
``initialize``       -> protocol/server info plus the public ``TargetAgentTask``
                        (the inbound message exactly as it would arrive; it carries
                        no verifier-only ground truth).
``tools/list``       -> the permitted tool descriptors (name/description/inputSchema).
``tools/call``       -> ``{name, arguments}`` invoked through the registry. Returns
                        ``{"output": <raw tool dict>, "is_error": bool}``.
``session/finish``   -> the agent's advisory self-report (decision/rationale). The
                        verifier never reads this; the environment snapshot is
                        authoritative.

A step budget caps the number of ``tools/call`` requests the server will honour.
That is independent of, and in addition to, the registry's own tool-call budget.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from nymbric.schemas.messages import TargetAgentTask
from nymbric.tools.registry import ToolRegistry

PROTOCOL_VERSION = "nymbric-live/1"
_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602


class ToolSession:
    """The mutable state of one live target session.

    Holds the registry (bound to the inert env), the public task served at
    ``initialize``, the step budget, and the agent's advisory final report. Every
    request is dispatched under ``lock`` so env/registry/budget mutations stay
    atomic even if a client opens concurrent connections.
    """

    def __init__(
        self,
        *,
        registry: ToolRegistry,
        task: TargetAgentTask,
        token: str,
        session_id: str,
        max_steps: int,
        trace=None,
    ):
        self.registry = registry
        self.task = task
        self.token = token
        self.session_id = session_id
        self.max_steps = max(1, int(max_steps))
        self.trace = trace
        self.lock = threading.Lock()
        self.steps = 0
        self.initialized = False
        self.finished = False
        self.report: dict[str, Any] = {}
        self.budget_exhausted = False

    # -- JSON-RPC method handlers (called with the lock held) --------------
    def handle(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            return self._initialize()
        if method in {"tools/list", "tools.list"}:
            return {"tools": self.tool_descriptors()}
        if method in {"tools/call", "tools.call"}:
            return self._call(params)
        if method in {"session/finish", "session.finish"}:
            return self._finish(params)
        if method in {"notifications/initialized", "initialized"}:
            return {}
        raise _RpcError(_METHOD_NOT_FOUND, f"Unknown method '{method}'.")

    def _initialize(self) -> dict[str, Any]:
        self.initialized = True
        return {
            "protocol_version": PROTOCOL_VERSION,
            "server": {"name": "nymbric-target", "experiment": "spear-phish"},
            "session_id": self.session_id,
            "max_steps": self.max_steps,
            # The public inbound task. Mirrors what the model/fixture target sees;
            # it carries no verifier-only ground truth (asserted by the suite).
            "task": self.task.model_dump(),
            "tools": self.tool_descriptors(),
            "note": "Inert synthetic environment. Links resolve to a reserved sink; attachments are inert.",
        }

    def tool_descriptors(self) -> list[dict[str, Any]]:
        descriptors = []
        for spec in self.registry.specs.values():
            if not spec.required <= self.registry.permissions:
                continue
            schema = spec.input_model.model_json_schema()
            schema.pop("title", None)
            descriptors.append({"name": spec.name, "description": spec.description, "inputSchema": schema})
        return descriptors

    def _call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise _RpcError(_INVALID_PARAMS, "tools/call requires a string 'name'.")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise _RpcError(_INVALID_PARAMS, "tools/call 'arguments' must be an object.")
        if self.steps >= self.max_steps:
            self.budget_exhausted = True
            return {"output": {"error": "step_budget_exhausted", "max_steps": self.max_steps}, "is_error": True}
        self.steps += 1
        output = self.registry.invoke(name, arguments)
        is_error = isinstance(output, dict) and "error" in output
        return {"output": output, "is_error": bool(is_error), "step": self.steps}

    def _finish(self, params: dict[str, Any]) -> dict[str, Any]:
        self.finished = True
        self.report = {
            "decision": str(params.get("decision") or "engaged"),
            "rationale": str(params.get("rationale") or "")[:2000],
        }
        return {"ok": True}


class _RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _make_handler(session: ToolSession):
    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        # Silence the default stderr access log; traces are emitted by the registry.
        def log_message(self, *args, **kwargs):  # noqa: D401, ANN001, ANN002, ANN003
            return

        def _write(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            token = header[7:].strip() if header.startswith("Bearer ") else self.headers.get("X-Nymbric-Token", "")
            return bool(session.token) and token == session.token

        def do_POST(self) -> None:  # noqa: N802
            if not self._authorized():
                self._write(401, {"error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            raw = self.rfile.read(length) if length else b""
            request_id: Any = None
            try:
                message = json.loads(raw.decode("utf-8") or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._write(200, _error_envelope(None, _PARSE_ERROR, "Request body was not valid JSON."))
                return
            if not isinstance(message, dict):
                self._write(200, _error_envelope(None, _INVALID_REQUEST, "A JSON-RPC request object is required."))
                return
            request_id = message.get("id")
            method = message.get("method")
            params = message.get("params") or {}
            if not isinstance(method, str):
                self._write(200, _error_envelope(request_id, _INVALID_REQUEST, "'method' is required."))
                return
            if not isinstance(params, dict):
                self._write(200, _error_envelope(request_id, _INVALID_PARAMS, "'params' must be an object."))
                return
            try:
                with session.lock:
                    result = session.handle(method, params)
            except _RpcError as exc:
                self._write(200, _error_envelope(request_id, exc.code, exc.message))
                return
            except Exception as exc:  # never leak a traceback to the client
                self._write(200, _error_envelope(request_id, -32000, f"server_error: {type(exc).__name__}"))
                return
            # A notification (no id) expects no response body.
            if request_id is None and method in {"notifications/initialized", "initialized"}:
                self._write(200, {"jsonrpc": "2.0", "result": {}})
                return
            self._write(200, {"jsonrpc": "2.0", "id": request_id, "result": result})

    return _Handler


def _error_envelope(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


class ToolSessionServer:
    """A localhost HTTP JSON-RPC server that serves one :class:`ToolSession`.

    Use as a context manager::

        with ToolSessionServer(registry=reg, task=task, token=tok, session_id=sid) as server:
            ...  # server.base_url is live; drive the client here
        # on exit the server is stopped and joined; the env can be snapshotted
    """

    def __init__(
        self,
        *,
        registry: ToolRegistry,
        task: TargetAgentTask,
        token: str,
        session_id: str,
        max_steps: int = 32,
        host: str = "127.0.0.1",
        trace=None,
    ):
        self.session = ToolSession(
            registry=registry, task=task, token=token, session_id=session_id, max_steps=max_steps, trace=trace
        )
        self.host = host
        self._server = ThreadingHTTPServer((host, 0), _make_handler(self.session))
        self._server.daemon_threads = True
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._server.serve_forever, name="nymbric-target-server", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> "ToolSessionServer":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
