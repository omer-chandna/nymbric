import json

from nymbric.core.types import CANARY_PREFIX
from nymbric.experiments.pkg_risk import execute_pkg_risk
from nymbric.storage.db import Database


def _mean(runs, condition, metric):
    values = [run["metrics"][metric] for run in runs if run["condition"] == condition and run["metrics"].get(metric) is not None]
    return sum(values) / len(values)


def test_four_conditions_isolate_private_information_and_disclosure(tmp_path):
    db = Database(tmp_path / "n.sqlite")
    summary = execute_pkg_risk(
        db,
        personas=12,
        seed=5,
        trials=3,
        provider="mock",
        defender_mode="familiarity_biased",
        threat="unauthorized_calendar",
        include_evaluator=False,
        include_recipient=True,
    )
    runs = summary["runs"]
    assert {run["status"] for run in runs} == {"completed"}
    assert len({run["content_hash"] for run in runs}) == 1
    assert _mean(runs, "web", "public_recall") > _mean(runs, "baseline", "public_recall")
    assert _mean(runs, "web", "private_recall") == 0
    assert _mean(runs, "graph", "private_recall") > _mean(runs, "web", "private_recall")
    assert _mean(runs, "graph", "unauthorized_disclosure") > _mean(runs, "web", "unauthorized_disclosure")
    assert _mean(runs, "graph", "false_positive") == 0
    web_blob = json.dumps([run for run in runs if run["condition"] == "web"])
    assert f"{CANARY_PREFIX}p" not in web_blob
    comparison = next(item for item in summary["comparisons"]["comparisons"] if item["a"] == "web" and item["b"] == "graph")
    assert comparison["claim_level"] == "paired_effect"
    assert comparison["metrics"]["private_recall"]["delta"]["mean"] > 0
    assert "deterministic" in comparison["metrics"]["private_recall"]["delta"]["variance_note"]


def test_mitigation_blocks_disclosure_without_changing_what_was_retrieved(tmp_path):
    db = Database(tmp_path / "n.sqlite")
    plain = execute_pkg_risk(
        db,
        personas=10,
        seed=8,
        trials=2,
        provider="mock",
        conditions=["graph"],
        defender_mode="familiarity_biased",
        include_evaluator=False,
        include_recipient=False,
    )
    guarded = execute_pkg_risk(
        db,
        world_id=plain["world_id"],
        trials=2,
        seed=8,
        provider="mock",
        conditions=["graph"],
        defender_mode="familiarity_biased",
        mitigation="require_independent_verification",
        include_evaluator=False,
        include_recipient=False,
    )
    assert _mean(plain["runs"], "graph", "unauthorized_disclosure") == 1
    assert _mean(guarded["runs"], "graph", "unauthorized_disclosure") == 0
    assert _mean(guarded["runs"], "graph", "mitigation_blocked") == 1
    assert abs(_mean(plain["runs"], "graph", "private_recall") - _mean(guarded["runs"], "graph", "private_recall")) < 1e-9


def test_sensitive_ablation_removes_the_familiarity_trigger(tmp_path):
    db = Database(tmp_path / "n.sqlite")
    plain = execute_pkg_risk(
        db,
        personas=10,
        seed=8,
        trials=2,
        provider="mock",
        conditions=["graph"],
        defender_mode="familiarity_biased",
        include_evaluator=False,
        include_recipient=False,
    )
    ablated = execute_pkg_risk(
        db,
        world_id=plain["world_id"],
        trials=2,
        seed=8,
        provider="mock",
        conditions=["graph"],
        defender_mode="familiarity_biased",
        ablation="drop_sensitive",
        include_evaluator=False,
        include_recipient=False,
    )
    assert _mean(ablated["runs"], "graph", "unauthorized_disclosure") == 0
    assert _mean(ablated["runs"], "graph", "private_recall") < _mean(plain["runs"], "graph", "private_recall")
