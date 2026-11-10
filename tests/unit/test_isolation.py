import pytest

from nymbric.context.isolation import filter_evidence_for_permissions, scrub_instruction
from nymbric.core.errors import DelegationDenied
from nymbric.orchestration.delegation import DelegationManager


def test_scrub_removes_verifier_controls_and_foreign_evidence():
    cleaned = scrub_instruction(
        {
            "identity_id": "p1",
            "ground_truth_authorization": False,
            "verification": [{"passed": False}],
            "evidence": [
                {"evidence_id": "ok", "predicate": "lives_in", "object": "Halifax", "source_kind": "profile"},
                {"evidence_id": "nope", "predicate": "attended_meeting", "object": "secret", "source_kind": "graph_asset", "correct": False},
            ],
        },
        allowed_evidence_ids={"ok"},
    )
    assert "ground_truth_authorization" not in cleaned
    assert "verification" not in cleaned
    assert cleaned["evidence"] == [{"evidence_id": "ok", "predicate": "lives_in", "object": "Halifax", "source_kind": "profile"}]


def test_child_cannot_gain_graph_access():
    manager = DelegationManager("run")
    parent = manager.create(agent="web_research", permissions={"web_search", "web_read"}, instruction={"objectives": ["look"]})
    with pytest.raises(DelegationDenied):
        manager.create(
            agent="graph_research",
            permissions={"graph_query"},
            instruction={"objectives": ["read the graph"]},
            parent_task_id=parent.task_id,
        )
    kept, removed = filter_evidence_for_permissions(
        [{"evidence_id": "g", "source_kind": "graph_asset", "object": "Closed planning session p0001-1"}],
        {"web_search", "web_read"},
    )
    assert removed and kept == []
