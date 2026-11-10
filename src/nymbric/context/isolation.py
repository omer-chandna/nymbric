"""Keep agent instructions inside an allow-list and fence untrusted text."""

from __future__ import annotations

from typing import Any

from nymbric.core.errors import DelegationDenied

INSTRUCTION_KEYS = {
    "task_id",
    "parent_task_id",
    "identity_id",
    "display_name",
    "city",
    "directory_id",
    "objectives",
    "depth",
    "max_depth",
    "threat_category",
    "requested_action",
    "evidence",
    "turn",
    "requester_id",
    "requester_label",
    "requester_role",
    "claimed_authority",
    "message",
    "legitimate",
    "condition",
    "run_id",
    "evidence_count",
    "defender_mode",
    "mitigation",
    "ablation",
    "decision",
    "notes",
    "unsupported_assumptions",
    "qualitative",
}


def scrub_instruction(
    payload: dict[str, Any],
    *,
    allowed_evidence_ids: set[str] | None = None,
    allow_verification: bool = False,
) -> dict[str, Any]:
    """Drop control fields a model must not be able to set."""
    allowed = set(INSTRUCTION_KEYS)
    if allow_verification:
        allowed.add("verification")
    clean: dict[str, Any] = {}
    for key, value in payload.items():
        if key in FORBIDDEN_KEYS or key not in allowed:
            continue
        if key == "evidence":
            clean[key] = _scrub_evidence(value, allowed_evidence_ids)
        elif key == "verification" and allow_verification:
            clean[key] = value
        else:
            clean[key] = value
    return clean

FORBIDDEN_KEYS = {
    "ground_truth",
    "ground_truth_authorization",
    "expected_secure_behavior",
    "failure_conditions",
    "verifier",
    "gt_facts",
    "correct",
    "permissions_override",
    "condition_override",
}


def fence_untrusted(text: str) -> str:
    cleaned = text.replace("</untrusted_data>", "</untrusted data>")
    return f"<untrusted_data>\n{cleaned}\n</untrusted_data>"


def _scrub_evidence(value: Any, allowed_ids: set[str] | None) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    kept = []
    for item in value:
        if not isinstance(item, dict):
            continue
        if any(key in item for key in FORBIDDEN_KEYS):
            continue
        if allowed_ids is not None and item.get("evidence_id") not in allowed_ids:
            continue
        kept.append({k: v for k, v in item.items() if k not in FORBIDDEN_KEYS})
    return kept


def filter_evidence_for_permissions(
    items: list[dict[str, Any]],
    permissions: set[str],
) -> tuple[list[dict[str, Any]], bool]:
    """Remove evidence the receiving agent is not allowed to possess."""
    kept: list[dict[str, Any]] = []
    removed = False
    for item in items:
        kind = str(item.get("source_kind") or "")
        if kind.startswith("graph_") and "graph_query" not in permissions:
            removed = True
            continue
        if kind == "web_page" and "web_read" not in permissions:
            removed = True
            continue
        kept.append(item)
    return kept, removed


def assert_permissions_subset(child: set[str], parent: set[str]) -> None:
    extra = set(child) - set(parent)
    if extra:
        raise DelegationDenied(
            "Delegation cannot grant capabilities the parent task does not have: " + ", ".join(sorted(extra))
        )
