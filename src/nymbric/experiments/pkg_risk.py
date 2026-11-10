"""PKG-Risk runner: four information-access conditions on one synthetic world."""

from __future__ import annotations

import json
import random
import uuid
from pathlib import Path
from typing import Any

from nymbric.core.config import AgentModelConfig, load_models
from nymbric.core.errors import NymbricError, ProviderUnavailable
from nymbric.core.types import ALL_CONDITIONS, Condition
from nymbric.experiments.compare import compare_runs, condition_logistic
from nymbric.models.router import build_provider
from nymbric.orchestration.orchestrator import Orchestrator, RunSpec
from nymbric.schemas.messages import Budget
from nymbric.storage.db import Database, utc_now
from nymbric.synthetic.world import generate_world

ROLES = (
    "web_research",
    "graph_research",
    "scenario",
    "defender",
    "evaluator",
    "risk_analysis",
    "recipient",
)

THREAT_CYCLE = (
    "unauthorized_calendar",
    "contextual_impersonation",
    "protected_document",
    "relationship_authority",
    "memory_poisoning",
    "inference_failure",
    "contextual_prompt_injection",
)


def execute_pkg_risk(
    db: Database,
    *,
    personas: int = 24,
    seed: int = 1,
    trials: int = 2,
    conditions: list[str] | None = None,
    provider: str | None = None,
    model: str | None = None,
    defender_mode: str = "familiarity_biased",
    threat: str = "unauthorized_calendar",
    ablation: str | None = None,
    mitigation: str | None = None,
    world_id: str | None = None,
    experiment_id: str | None = None,
    jsonl_dir: Path | None = None,
    include_recipient: bool = True,
    include_evaluator: bool = True,
) -> dict[str, Any]:
    models = load_models()
    chosen_provider = provider or models.default_provider
    providers = {}
    for role in ROLES:
        config = models.for_agent(role, chosen_provider, model)
        if chosen_provider == "mock":
            config = AgentModelConfig(provider="mock", model=model or "mock-deterministic")
        providers[role] = build_provider(config)
    status = providers["web_research"].check()
    if not status.ok:
        raise ProviderUnavailable(status.detail)
    if world_id is None:
        bundle = generate_world(personas=personas, seed=seed)
        db.persist_world(bundle)
        world_id = bundle["world_id"]
        content_hash = bundle["content_hash"]
    else:
        world = db.world_row(world_id)
        if world is None:
            raise NymbricError(f"World {world_id} does not exist. Generate it before running.")
        content_hash = world["content_hash"]
    selected = _select_identities(db, world_id, trials, seed)
    if not selected:
        raise NymbricError(f"World {world_id} has no fictional people.")
    condition_values = _conditions(conditions)
    experiment_id = experiment_id or f"exp-{uuid.uuid4().hex[:12]}"
    runs: list[dict[str, Any]] = []
    for trial_index, identity_id in enumerate(selected):
        threat_name = THREAT_CYCLE[trial_index % len(THREAT_CYCLE)] if threat == "all" else threat
        for condition in condition_values:
            run_id = f"run-{uuid.uuid4().hex[:12]}"
            jsonl_path = None
            if jsonl_dir is not None:
                jsonl_dir.mkdir(parents=True, exist_ok=True)
                jsonl_path = jsonl_dir / f"{run_id}.jsonl"
            spec = RunSpec(
                experiment_id=experiment_id,
                run_id=run_id,
                world_id=world_id,
                condition=condition,
                identity_id=identity_id,
                seed=seed,
                threat=threat_name,
                defender_mode=defender_mode,
                provider=providers["defender"].provider_name,
                model=providers["defender"].model,
                ablation=ablation,
                mitigation=mitigation,
                budget=Budget(max_tool_calls=48, max_steps=16, max_search_calls=8, max_pages_read=5, max_tokens=120000, max_seconds=180),
                trial_index=trial_index,
                include_recipient=include_recipient,
                include_evaluator=include_evaluator,
                jsonl_path=jsonl_path,
            )
            state = Orchestrator(db, providers).run(spec)
            runs.append(_public_run(state))
    summary = {
        "experiment_id": experiment_id,
        "world_id": world_id,
        "content_hash": content_hash,
        "seed": seed,
        "provider": providers["defender"].provider_name,
        "model": providers["defender"].model,
        "defender_mode": defender_mode,
        "threat": threat,
        "ablation": ablation,
        "mitigation": mitigation,
        "trials": len(selected),
        "conditions": condition_values,
        "runs": runs,
        "comparisons": compare_runs(runs, metric_family="primary"),
        "secondary_comparisons": compare_runs(runs, metric_family="secondary"),
        "logistic_disclosure": condition_logistic(runs, outcome="unauthorized_disclosure", condition="graph")
        if "graph" in condition_values and "web" in condition_values
        else None,
        "created_at": utc_now(),
        "label": (
            "Synthetic policy outcome. Not a measurement of human susceptibility "
            "or of a real personal-knowledge-graph compromise."
        ),
    }
    db.execute(
        """
        INSERT OR REPLACE INTO experiments (experiment_id, name, config_json, summary_json, created_at)
        VALUES (?, 'pkg-risk', ?, ?, ?)
        """,
        (
            experiment_id,
            json.dumps({k: summary[k] for k in ("seed", "provider", "model", "defender_mode", "threat", "ablation", "mitigation", "conditions", "world_id")}),
            json.dumps(summary),
            summary["created_at"],
        ),
    )
    return summary


def _conditions(values: list[str] | None) -> list[str]:
    if not values or values == ["all"]:
        return [condition.value for condition in ALL_CONDITIONS]
    cleaned = []
    for value in values:
        if value == "all":
            return [condition.value for condition in ALL_CONDITIONS]
        cleaned.append(Condition(value).value)
    return cleaned


def _select_identities(db: Database, world_id: str, trials: int, seed: int) -> list[str]:
    rows = db.query(
        "SELECT entity_id FROM entities WHERE world_id = ? AND entity_type = 'person' ORDER BY entity_id",
        (world_id,),
    )
    ids = [row["entity_id"] for row in rows]
    rng = random.Random(seed)
    if trials >= len(ids):
        return ids
    return rng.sample(ids, trials)


def _public_run(state) -> dict[str, Any]:
    return {
        "run_id": state.run_id,
        "experiment_id": state.experiment_id,
        "world_id": state.world_id,
        "condition": state.condition,
        "identity_id": state.identity_id,
        "trial_index": state.trial_index,
        "seed": state.seed,
        "threat": state.threat,
        "defender_mode": state.defender_mode,
        "provider": state.provider,
        "model": state.model,
        "ablation": state.ablation,
        "mitigation": state.mitigation,
        "status": state.status,
        "metrics": state.metrics,
        "content_hash": state.content_hash,
    }
