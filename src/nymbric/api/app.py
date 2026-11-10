"""Research API. Every page on the dashboard reads these routes."""

from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from nymbric import __version__
from nymbric.core.config import load_models
from nymbric.core.errors import NymbricError, ProviderUnavailable
from nymbric.environments.sandbox import isolation_status
from nymbric.experiments.compare import compare_runs
from nymbric.experiments.counterfactual import run_counterfactual
from nymbric.experiments.pkg_risk import execute_pkg_risk
from nymbric.experiments.security_suite import TESTS
from nymbric.integrations.adapters import integration_status
from nymbric.mitigations.policies import list_controls
from nymbric.models.router import build_provider
from nymbric.reporting.export import html_report, markdown_report
from nymbric.storage.db import Database

_JOBS: dict[str, dict[str, Any]] = {}
_JOB_LOCK = threading.Lock()


class RunRequest(BaseModel):
    personas: int = 24
    seed: int = 1
    trials: int = 2
    conditions: list[str] = Field(default_factory=lambda: ["all"])
    provider: str = "mock"
    model: str | None = None
    defender_mode: str = "familiarity_biased"
    threat: str = "unauthorized_calendar"
    ablation: str | None = None
    mitigation: str | None = None
    world_id: str | None = None


class CounterfactualRequest(RunRequest):
    factor: str
    value: str


def create_app(home: Path | None = None) -> FastAPI:
    root = Path(home or os.environ.get("NYMBRIC_HOME", ".nymbric"))
    root.mkdir(parents=True, exist_ok=True)
    db = Database(root / "nymbric.sqlite")
    app = FastAPI(title="Nymbric", version=__version__)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"name": "nymbric", "version": __version__, "isolation": isolation_status()}

    @app.get("/api/overview")
    def overview() -> dict[str, Any]:
        worlds = db.list_worlds()
        runs = [_run_row(row) for row in db.query("SELECT * FROM runs ORDER BY started_at DESC LIMIT 12")]
        findings = db.query("SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity")
        experiments = db.query("SELECT experiment_id, name, created_at FROM experiments ORDER BY created_at DESC LIMIT 8")
        try:
            models = load_models()
            model_payload = {"default_provider": models.default_provider, "default_model": models.default_model}
        except Exception as exc:  # configuration problems are data, not a crashed overview
            model_payload = {"error": str(exc)}
        return {
            "worlds": worlds,
            "runs": runs,
            "findings": [dict(row) for row in findings],
            "experiments": [dict(row) for row in experiments],
            "models": model_payload,
            "controls": list_controls(),
            "integrations": integration_status(),
            "tests": [{"id": item["id"], "primary": item["primary"]} for item in TESTS],
        }

    @app.get("/api/models")
    def models_route() -> dict[str, Any]:
        config = load_models()
        return config.model_dump()

    @app.post("/api/models/check")
    def models_check(provider: str = "mock", model: str | None = None) -> dict[str, Any]:
        from nymbric.core.config import AgentModelConfig

        chosen = model or ("mock-deterministic" if provider == "mock" else load_models().default_model)
        try:
            status = build_provider(AgentModelConfig(provider=provider, model=chosen)).check()
        except (NymbricError, ProviderUnavailable) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return status.model_dump()

    @app.get("/api/worlds")
    def worlds() -> list[dict[str, Any]]:
        return db.list_worlds()

    @app.get("/api/worlds/{world_id}/graph")
    def graph(
        world_id: str,
        relationship: str | None = None,
        sensitivity: str | None = None,
        min_confidence: float = 0,
        provenance: str | None = None,
        visibility: str | None = None,
        limit: int = 80,
        focus: str | None = None,
    ) -> dict[str, Any]:
        params: list[Any] = [world_id]
        sql = "SELECT * FROM relationships WHERE world_id = ?"
        if relationship:
            sql += " AND rel_type = ?"
            params.append(relationship)
        if sensitivity:
            sql += " AND sensitivity = ?"
            params.append(sensitivity)
        if provenance:
            sql += " AND provenance = ?"
            params.append(provenance)
        if visibility:
            sql += " AND visibility = ?"
            params.append(visibility)
        sql += " AND confidence >= ?"
        params.append(min_confidence)
        if focus:
            sql += " AND (src = ? OR dst = ? OR src_name = ? OR dst_name = ?)"
            params.extend([focus, focus, focus, focus])
        sql += " LIMIT ?"
        params.append(limit)
        rels = [dict(row) for row in db.query(sql, tuple(params))]
        node_ids = {rel["src"] for rel in rels} | {rel["dst"] for rel in rels}
        nodes = []
        if node_ids:
            placeholders = ",".join("?" for _ in node_ids)
            for row in db.query(
                f"SELECT entity_id, entity_type, name, sensitivity, visibility FROM entities WHERE world_id = ? AND entity_id IN ({placeholders})",
                (world_id, *node_ids),
            ):
                nodes.append(
                    {
                        "data": {
                            "id": row["entity_id"],
                            "label": row["name"],
                            "entity_type": row["entity_type"],
                            "sensitivity": row["sensitivity"],
                            "visibility": row["visibility"],
                        }
                    }
                )
        present = {node["data"]["id"] for node in nodes}
        edges = [
            {
                "data": {
                    "id": rel["rel_id"],
                    "source": rel["src"],
                    "target": rel["dst"],
                    "label": rel["rel_type"],
                    "confidence": rel["confidence"],
                    "sensitivity": rel["sensitivity"],
                    "inference_status": rel["inference_status"],
                    "visibility": rel["visibility"],
                    "provenance": rel["provenance"],
                }
            }
            for rel in rels
            if rel["src"] in present and rel["dst"] in present
        ]
        return {"nodes": nodes, "edges": edges}

    @app.get("/api/worlds/{world_id}/search")
    def search(world_id: str, q: str = "", limit: int = 8) -> dict[str, Any]:
        from nymbric.web_research.search import WebIndex

        return WebIndex(db, world_id).search(q, limit=limit)

    @app.get("/api/worlds/{world_id}/pages/{page_id}")
    def page(world_id: str, page_id: str) -> dict[str, Any]:
        from nymbric.web_research.search import WebIndex

        found = WebIndex(db, world_id).open_page(page_id)
        if "error" in found:
            raise HTTPException(status_code=404, detail="Page not found")
        return found

    @app.get("/api/experiments")
    def experiments() -> list[dict[str, Any]]:
        rows = []
        for row in db.query("SELECT experiment_id, name, created_at, summary_json FROM experiments ORDER BY created_at DESC LIMIT 20"):
            summary = json.loads(row["summary_json"])
            rows.append(
                {
                    "experiment_id": row["experiment_id"],
                    "name": row["name"],
                    "created_at": row["created_at"],
                    "provider": summary.get("provider"),
                    "model": summary.get("model"),
                    "defender_mode": summary.get("defender_mode"),
                    "trials": summary.get("trials"),
                    "label": summary.get("label"),
                }
            )
        return rows

    @app.get("/api/experiments/{experiment_id}")
    def experiment(experiment_id: str) -> dict[str, Any]:
        row = db.query("SELECT summary_json FROM experiments WHERE experiment_id = ?", (experiment_id,))
        if not row:
            job = _JOBS.get(experiment_id)
            if job:
                return job
            raise HTTPException(status_code=404, detail="Experiment not found")
        return json.loads(row[0]["summary_json"])

    @app.post("/api/experiments/pkg-risk")
    def start_pkg(body: RunRequest) -> dict[str, str]:
        experiment_id = f"exp-{uuid.uuid4().hex[:12]}"
        with _JOB_LOCK:
            _JOBS[experiment_id] = {"status": "running", "experiment_id": experiment_id}

        def worker() -> None:
            try:
                execute_pkg_risk(
                    db,
                    experiment_id=experiment_id,
                    personas=body.personas,
                    seed=body.seed,
                    trials=body.trials,
                    conditions=body.conditions,
                    provider=body.provider,
                    model=body.model,
                    defender_mode=body.defender_mode,
                    threat=body.threat,
                    ablation=body.ablation,
                    mitigation=body.mitigation,
                    world_id=body.world_id,
                    jsonl_dir=root / "traces",
                    include_evaluator=False,
                )
                with _JOB_LOCK:
                    _JOBS[experiment_id] = {"status": "completed", "experiment_id": experiment_id}
            except Exception as exc:
                with _JOB_LOCK:
                    _JOBS[experiment_id] = {"status": "failed", "experiment_id": experiment_id, "detail": str(exc)}

        threading.Thread(target=worker, daemon=True).start()
        return {"experiment_id": experiment_id, "status": "running"}

    @app.post("/api/counterfactuals")
    def counterfactual(body: CounterfactualRequest) -> dict[str, Any]:
        try:
            return run_counterfactual(
                db,
                factor=body.factor,
                value=body.value,
                base={
                    "personas": body.personas,
                    "seed": body.seed,
                    "trials": body.trials,
                    "conditions": body.conditions,
                    "provider": body.provider,
                    "model": body.model,
                    "defender_mode": body.defender_mode,
                    "threat": body.threat,
                    "world_id": body.world_id,
                    "include_evaluator": False,
                    "include_recipient": False,
                    "jsonl_dir": root / "traces",
                },
            )
        except (NymbricError, ProviderUnavailable, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/runs/{run_id}")
    def run_detail(run_id: str) -> dict[str, Any]:
        rows = db.query("SELECT * FROM runs WHERE run_id = ?", (run_id,))
        if not rows:
            raise HTTPException(status_code=404, detail="Run not found")
        checkpoint = db.query(
            "SELECT state_json FROM checkpoints WHERE run_id = ? AND stage = 'latest'",
            (run_id,),
        )
        state = json.loads(checkpoint[0]["state_json"]) if checkpoint else {}
        binding_rows = db.query("SELECT payload_json FROM scenario_bindings WHERE run_id = ?", (run_id,))
        return {
            "run": _run_row(rows[0]),
            "scenario": state.get("scenario"),
            "defender_input": state.get("defender_input"),
            "verification": state.get("verification"),
            "evaluation": state.get("evaluation"),
            "risk": state.get("risk"),
            "recipient": state.get("recipient"),
            "metrics": state.get("metrics"),
            "errors": state.get("errors"),
            "verifier_binding": json.loads(binding_rows[0]["payload_json"]) if binding_rows else None,
        }

    @app.get("/api/runs/{run_id}/trace")
    def trace(run_id: str) -> list[dict[str, Any]]:
        return [json.loads(row["event_json"]) for row in db.query("SELECT event_json FROM traces WHERE run_id = ? ORDER BY id", (run_id,))]

    @app.get("/api/runs/{run_id}/workflow")
    def workflow(run_id: str) -> dict[str, Any]:
        tasks = [dict(row) for row in db.query("SELECT * FROM tasks WHERE run_id = ?", (run_id,))]
        nodes = [{"data": {"id": "orchestrator", "label": "orchestrator"}}]
        edges = []
        for task in tasks:
            nodes.append({"data": {"id": task["task_id"], "label": task["agent"], "status": task["status"]}})
            parent = task["parent_task_id"] or "orchestrator"
            edges.append({"data": {"id": f"{parent}-{task['task_id']}", "source": parent, "target": task["task_id"]}})
        return {"nodes": nodes, "edges": edges}

    @app.get("/api/findings")
    def findings(limit: int = 100) -> list[dict[str, Any]]:
        rows = db.query(
            "SELECT finding_id, run_id, experiment_id, severity, policy, payload_json FROM findings ORDER BY rowid DESC LIMIT ?",
            (limit,),
        )
        return [{**{k: row[k] for k in row.keys() if k != "payload_json"}, "payload": json.loads(row["payload_json"])} for row in rows]

    @app.get("/api/experiments/{experiment_id}/compare")
    def experiment_compare(experiment_id: str) -> dict[str, Any]:
        summary = experiment(experiment_id)
        if "runs" not in summary:
            return summary
        return {"primary": compare_runs(summary["runs"], metric_family="primary"), "secondary": summary.get("secondary_comparisons")}

    @app.get("/api/experiments/{experiment_id}/report.md")
    def report_md(experiment_id: str) -> PlainTextResponse:
        return PlainTextResponse(markdown_report(experiment(experiment_id)))

    @app.get("/api/experiments/{experiment_id}/report.html")
    def report_html(experiment_id: str) -> HTMLResponse:
        return HTMLResponse(html_report(experiment(experiment_id)))

    @app.get("/api/experiments/{experiment_id}/report.json")
    def report_json(experiment_id: str) -> dict[str, Any]:
        return experiment(experiment_id)

    dist = Path(__file__).resolve().parents[3] / "dashboard" / "frontend" / "dist"

    @app.get("/")
    def index():
        index_file = dist / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return {"detail": "API is running. Build dashboard/frontend to serve the interface.", "health": "/api/health"}

    @app.get("/{full_path:path}")
    def assets(full_path: str):
        if full_path.startswith("api"):
            raise HTTPException(status_code=404, detail="Not found")
        candidate = (dist / full_path).resolve()
        if candidate.is_file() and str(candidate).startswith(str(dist.resolve())):
            return FileResponse(candidate)
        index_file = dist / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        raise HTTPException(status_code=404, detail="Not found")

    return app


def _run_row(row: Any) -> dict[str, Any]:
    payload = dict(row)
    if "metrics_json" in payload:
        payload["metrics"] = json.loads(payload.pop("metrics_json"))
    if "config_json" in payload:
        payload["config"] = json.loads(payload.pop("config_json"))
    return payload


app = create_app()
