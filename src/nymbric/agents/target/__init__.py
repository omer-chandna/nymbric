"""Personal agent under test (spear-phish experiment).

The target is pluggable. `TARGET_MODES` lists the built-in options:

- ``model``      — a model-backed agent driven by the configured provider. With a
                   local provider (Ollama) this is how you point Nymbric at an
                   on-device assistant model. With ``mock`` it is a deterministic
                   secure control.
- ``cautious``   — fixture that verifies and never takes the bait (secure control).
- ``credulous``  — fixture that always takes the bait (forces a known compromise;
                   used by the security suite to confirm the verifiers fire).
- ``context_sensitive`` — fixture whose susceptibility rises with how specifically
                   the lure is personalized. This is the exposure contrast: a generic
                   lure is refused, a lure grounded in breach-derived private context
                   is acted on. Default.
- ``external``   — an out-of-process agent (e.g. Hermes, OpenClaw) that reports an
                   action log once, replayed through
                   :class:`~nymbric.agents.target.external.ExternalCommandTarget`.
- ``live``       — a live, closed-loop agent driven through
                   :class:`~nymbric.agents.target.live.LiveToolServerTarget`: Nymbric
                   stands up a localhost tool server bound to the inert environment and
                   launches the agent, which reads each tool result and decides its next
                   call interactively. ``mcp`` is an alias. Any MCP-capable agent can
                   attach via :mod:`nymbric.agents.target.mcp_bridge`.
"""

from nymbric.agents.target.base import ModelTargetAgent, run_target_fixture
from nymbric.agents.target.external import ExternalCommandTarget
from nymbric.agents.target.live import LiveToolServerTarget

TARGET_MODES = ("model", "cautious", "credulous", "context_sensitive", "external", "live")

__all__ = [
    "ModelTargetAgent",
    "run_target_fixture",
    "ExternalCommandTarget",
    "LiveToolServerTarget",
    "TARGET_MODES",
]
