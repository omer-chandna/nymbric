import threading

import pytest

from nymbric.core.errors import ConcurrentRunError
from nymbric.models.providers.mock import MockProvider
from nymbric.orchestration.orchestrator import Orchestrator, RunSpec, run_lock
from nymbric.storage.db import Database
from nymbric.synthetic.world import generate_world
from nymbric.web_research.search import WebIndex


def _providers():
    return {role: MockProvider() for role in ["web_research", "graph_research", "scenario", "defender", "evaluator", "risk_analysis", "recipient"]}


def _world(tmp_path):
    db = Database(tmp_path / "n.sqlite")
    bundle = generate_world(personas=10, seed=4)
    db.persist_world(bundle)
    return db, bundle


def test_cancel_stops_before_research(tmp_path):
    db, bundle = _world(tmp_path)
    event = threading.Event()
    event.set()
    spec = RunSpec(
        experiment_id="exp",
        run_id="cancel-me",
        world_id=bundle["world_id"],
        condition="web",
        identity_id="p0001",
        seed=4,
        include_evaluator=False,
        include_recipient=False,
    )
    state = Orchestrator(db, _providers(), event).run(spec)
    assert state.status == "cancelled"
    assert state.evidence == []


def test_resume_does_not_repeat_completed_research(tmp_path, monkeypatch):
    db, bundle = _world(tmp_path)
    calls = {"n": 0}
    original = WebIndex.search

    def wrapped(self, query, limit=5):
        calls["n"] += 1
        return original(self, query, limit)

    monkeypatch.setattr(WebIndex, "search", wrapped)
    spec = RunSpec(
        experiment_id="exp",
        run_id="resume-me",
        world_id=bundle["world_id"],
        condition="web",
        identity_id="p0001",
        seed=4,
        pause_after="research",
        include_evaluator=False,
        include_recipient=False,
    )
    first = Orchestrator(db, _providers()).run(spec)
    assert first.status == "paused"
    assert first.evidence
    seen = calls["n"]
    assert seen > 0
    spec.resume = True
    spec.pause_after = None
    second = Orchestrator(db, _providers()).run(spec)
    assert second.status == "completed"
    assert calls["n"] == seen
    assert "ground_truth_authorization" not in second.model_dump_json()
    assert "ground_truth" not in (second.defender_input or {})["adversarial"]


def test_run_lock_rejects_overlapping_execution():
    with run_lock("same-run"):
        with pytest.raises(ConcurrentRunError):
            with run_lock("same-run"):
                pass
