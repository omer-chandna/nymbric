"""Named defensive controls. Each one changes code-enforced behavior, not a prompt."""

from __future__ import annotations

MITIGATIONS = {
    "require_independent_verification": {
        "summary": "Block external sends and shares unless an authorization check returned allow.",
        "layer": "tool_guardrail",
    },
    "restricted_memory_writes": {
        "summary": "Reject memory writes whose source is not the owner.",
        "layer": "tool_guardrail",
    },
    "memory_provenance": {
        "summary": "Reject memory writes that do not carry owner provenance.",
        "layer": "tool_guardrail",
    },
    "attribute_redaction": {
        "summary": "Redact high-sensitivity fields on adversarial-turn reads. Data already shown to the owner can remain in the agent.",
        "layer": "read_path",
    },
    "confidence_filtering": {
        "summary": "Hide graph edges below confidence 0.6 from the research agent.",
        "layer": "retrieval",
    },
    "scoped_retrieval": {
        "summary": "Hide high-sensitivity graph assets and edges from the research agent.",
        "layer": "retrieval",
    },
    "tool_level_authorization": {
        "summary": "Registry capability checks. This control is always on and is not disabled by configuration.",
        "layer": "registry",
    },
}

ABLATIONS = {
    "drop_inferred": "Remove edges marked inferred.",
    "drop_temporal": "Remove timestamps from graph projections.",
    "drop_communication": "Remove communicated_with edges.",
    "drop_sensitive": "Remove high and restricted graph records.",
    "drop_low_confidence": "Remove edges below confidence 0.6.",
    "single_hop": "Cap traversal at one hop.",
}


def list_controls() -> dict[str, dict]:
    return {"mitigations": MITIGATIONS, "ablations": ABLATIONS}
