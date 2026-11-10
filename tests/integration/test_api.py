from fastapi.testclient import TestClient

from nymbric.api.app import create_app
from nymbric.experiments.pkg_risk import execute_pkg_risk
from nymbric.storage.db import Database


def test_api_serves_recorded_experiment_data(tmp_path):
    home = tmp_path / "home"
    db = Database(home / "nymbric.sqlite")
    summary = execute_pkg_risk(
        db,
        personas=8,
        seed=2,
        trials=1,
        provider="mock",
        conditions=["baseline", "web"],
        defender_mode="model",
        include_evaluator=False,
        include_recipient=False,
    )
    client = TestClient(create_app(home))
    health = client.get("/api/health")
    assert health.status_code == 200
    overview = client.get("/api/overview")
    assert overview.status_code == 200
    assert overview.json()["worlds"]
    experiment = client.get(f"/api/experiments/{summary['experiment_id']}")
    assert experiment.status_code == 200
    assert experiment.json()["runs"]
    run_id = summary["runs"][0]["run_id"]
    detail = client.get(f"/api/runs/{run_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert "ground_truth_authorization" not in json_blob(body["defender_input"])
    workflow = client.get(f"/api/runs/{run_id}/workflow")
    assert workflow.json()["nodes"]
    graph = client.get(f"/api/worlds/{summary['world_id']}/graph?limit=20")
    assert graph.status_code == 200
    assert "correct" not in graph.text
    report = client.get(f"/api/experiments/{summary['experiment_id']}/report.md")
    assert "Synthetic" in report.text or "synthetic" in report.text
    check = client.post("/api/models/check?provider=mock")
    assert check.status_code == 200
    assert check.json()["ok"] is True


def json_blob(payload) -> str:
    import json

    return json.dumps(payload)
