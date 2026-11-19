"""Live, closed-loop target adapter for an out-of-process agent.

Where :class:`~nymbric.agents.target.external.ExternalCommandTarget` runs an agent
once and *replays* a reported action log, this adapter gives the agent a live tool
loop: it stands up a localhost tool server bound to the run's inert
:class:`~nymbric.environments.target.TargetEnvironment`, launches the agent, and
lets the agent read each tool result and decide its next call. When the agent
finishes (or the step budget / timeout is reached) the server is torn down and the
orchestrator snapshots the environment for the deterministic verifier.

The boundary and inertness guarantees are unchanged from the one-shot adapter: the
agent is untrusted and runs in its own process; it can only reach the synthetic
environment through the Nymbric tool server (no real link, file, inbox, or
network); and the verifier reads the environment, never the agent's self-report.

The transport is JSON-RPC over HTTP. A built-in reference client
(:mod:`nymbric.agents.target.clients.reference_client`) speaks it directly; any
MCP-capable agent can attach through the stdio bridge in
:mod:`nymbric.agents.target.mcp_bridge`.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import time
import uuid

from nymbric.agents.target.live_server import ToolSessionServer
from nymbric.core.errors import Cancelled, NymbricError
from nymbric.schemas.messages import TargetAgentResult, TargetAgentTask
from nymbric.tools.registry import ToolRegistry

DEFAULT_TIMEOUT_S = 60.0
DEFAULT_MAX_STEPS = 32


class LiveToolServerTarget:
    role = "target"

    def __init__(
        self,
        argv: list[str],
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_steps: int = DEFAULT_MAX_STEPS,
        host: str = "127.0.0.1",
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ):
        if not argv:
            raise NymbricError("LiveToolServerTarget requires a non-empty command.")
        self.argv = list(argv)
        self.timeout_s = float(timeout_s)
        self.max_steps = int(max_steps)
        self.host = host
        self.cwd = cwd
        self.env = env

    def run(self, task: TargetAgentTask, registry: ToolRegistry, trace, budget, deadline, cancel_event=None) -> dict:
        token = secrets.token_hex(16)
        session_id = f"live-{uuid.uuid4().hex[:12]}"
        server = ToolSessionServer(
            registry=registry, task=task, token=token, session_id=session_id, max_steps=self.max_steps, host=self.host, trace=trace
        )
        server.start()
        child_env = dict(os.environ if self.env is None else self.env)
        child_env.update(
            {
                "NYMBRIC_TARGET_URL": server.base_url,
                "NYMBRIC_TARGET_TOKEN": token,
                "NYMBRIC_TARGET_SESSION": session_id,
            }
        )
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv is a list, shell is not used
                self.argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=self.cwd,
                env=child_env,
            )
        except OSError as exc:
            server.stop()
            raise NymbricError(f"Live target client could not be launched: {exc}") from exc

        stderr = ""
        returncode: int | None = None
        timed_out = False
        effective = self.timeout_s
        if deadline is not None:
            effective = min(effective, max(0.5, deadline - time.monotonic()))
        started = time.monotonic()
        try:
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    proc.kill()
                    proc.communicate()
                    raise Cancelled("The run was cancelled.")
                remaining = effective - (time.monotonic() - started)
                if remaining <= 0:
                    proc.kill()
                    _, stderr = proc.communicate()
                    returncode = proc.returncode
                    timed_out = True
                    break
                try:
                    _, stderr = proc.communicate(timeout=min(0.2, remaining))
                    returncode = proc.returncode
                    break
                except subprocess.TimeoutExpired:
                    continue
        finally:
            server.stop()

        report = server.session.report or {}
        decision = str(report.get("decision") or ("timeout" if timed_out else "engaged"))
        rationale = str(report.get("rationale") or "")[:2000]
        trace.emit(
            "live_target_report",
            stage="target",
            agent="target",
            task_id=task.task_id,
            payload={
                "returncode": returncode,
                "decision": decision,
                "steps": server.session.steps,
                "finished": server.session.finished,
                "timed_out": timed_out,
                "budget_exhausted": server.session.budget_exhausted,
                "stderr": (stderr or "")[:500],
            },
        )
        return TargetAgentResult(task_id=task.task_id, decision=decision, rationale=rationale).model_dump()
