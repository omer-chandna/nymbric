"""Adapter for an out-of-process target agent (Hermes, OpenClaw, any local agent).

Contract (v1, stdin/stdout JSON):

    stdin  <- the TargetAgentTask as one JSON object (the inbound lure + owner id)
    stdout -> one JSON object:
              {
                "decision": "refused" | "engaged" | "complied" | ...,
                "rationale": "...",
                "actions": [ {"tool": "<name>", "arguments": { ... }}, ... ]
              }

The external agent decides what it *would* do and reports it; Nymbric replays
each reported action against its own inert `TargetEnvironment` through the normal
tool registry. The external agent never touches a real link, file, or network:
the environment is the only thing that "acts", and the deterministic verifier
reads that environment. Unknown tools are denied by the registry, exactly as for
a built-in target.

This boundary is deliberate: an external agent is untrusted code, so its output
is parsed as data (strict JSON, no shell, bounded time) and never executed.

To expose Nymbric's live tool surface to an agent instead (so it calls the tools
itself rather than reporting intents), wrap `build_target_registry` behind an MCP
tool server; see docs/extending.md.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

from nymbric.core.errors import NymbricError
from nymbric.schemas.messages import TargetAgentResult, TargetAgentTask
from nymbric.tools.registry import ToolRegistry


class ExternalCommandTarget:
    role = "target"

    def __init__(self, argv: list[str], *, timeout_s: float = 60.0, cwd: str | None = None, env: dict[str, str] | None = None):
        if not argv:
            raise NymbricError("ExternalCommandTarget requires a non-empty command.")
        self.argv = list(argv)
        self.timeout_s = timeout_s
        self.cwd = cwd
        self.env = env

    def run(self, task: TargetAgentTask, registry: ToolRegistry, trace, budget, deadline, cancel_event=None) -> dict:
        payload = json.dumps(task.model_dump())
        try:
            completed = subprocess.run(  # noqa: S603 - argv is a list, shell is not used
                self.argv,
                input=payload,
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
                cwd=self.cwd,
                env=self.env,
            )
        except subprocess.TimeoutExpired as exc:
            raise NymbricError(f"External target timed out after {self.timeout_s}s.") from exc
        except OSError as exc:
            raise NymbricError(f"External target could not be launched: {exc}") from exc
        report = _parse_report(completed.stdout)
        trace.emit(
            "external_target_report",
            stage="target",
            agent="target",
            task_id=task.task_id,
            payload={"returncode": completed.returncode, "decision": report.get("decision"), "action_count": len(report.get("actions") or [])},
        )
        for action in report.get("actions") or []:
            name = str(action.get("tool") or "")
            args = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
            if not name:
                continue
            registry.invoke(name, args)  # the registry denies unknown/unpermitted tools
        decision = str(report.get("decision") or "engaged")
        rationale = str(report.get("rationale") or "")[:2000]
        return TargetAgentResult(task_id=task.task_id, decision=decision, rationale=rationale).model_dump()


def _parse_report(stdout: str) -> dict[str, Any]:
    text = (stdout or "").strip()
    if not text:
        raise NymbricError("External target produced no output. Expected one JSON object on stdout.")
    # Tolerate leading log lines: take the last JSON object on stdout.
    for candidate in _json_candidates(text):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    raise NymbricError("External target output was not a JSON object matching the action-log contract.")


def _json_candidates(text: str) -> list[str]:
    candidates = [text]
    lines = [line for line in text.splitlines() if line.strip()]
    if lines:
        candidates.append(lines[-1])
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidates.append(text[start : end + 1])
    return candidates
