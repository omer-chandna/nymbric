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
- ``external``   — an out-of-process agent (e.g. Hermes, OpenClaw) wired through
                   :class:`~nymbric.agents.target.external.ExternalCommandTarget`.
"""

from nymbric.agents.target.base import ModelTargetAgent, run_target_fixture
from nymbric.agents.target.external import ExternalCommandTarget

TARGET_MODES = ("model", "cautious", "credulous", "context_sensitive", "external")

__all__ = ["ModelTargetAgent", "run_target_fixture", "ExternalCommandTarget", "TARGET_MODES"]
