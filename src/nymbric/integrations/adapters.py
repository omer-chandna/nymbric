"""Optional adapters. Core experiments do not import or require these systems."""

from __future__ import annotations

import importlib.util
from typing import Any


class OptionalAdapter:
    name = "optional"

    def status(self) -> dict[str, Any]:
        available = importlib.util.find_spec(self.module) is not None if self.module else False
        return {
            "name": self.name,
            "required": False,
            "installed": available,
            "detail": self.detail if not available else f"{self.name} is installed. Nymbric still runs its own orchestrator.",
        }

    module = ""
    detail = ""


class HarborAdapter(OptionalAdapter):
    name = "harbor"
    module = "harbor"
    detail = "Harbor is not installed and is not required. Nymbric's runner is the native experiment executor."


class MCPAdapter(OptionalAdapter):
    name = "mcp"
    module = "mcp"
    detail = "An MCP SDK is not installed. Tool use in the benchmark goes through Nymbric's registry."


class LangGraphAdapter(OptionalAdapter):
    name = "langgraph"
    module = "langgraph"
    detail = (
        "LangGraph is not installed. Nymbric uses its own explicit stage machine so that permissions "
        "and verification stay outside an LLM supervisor. A LangGraph graph could later call the same agents."
    )


def integration_status() -> list[dict[str, Any]]:
    return [HarborAdapter().status(), MCPAdapter().status(), LangGraphAdapter().status()]
