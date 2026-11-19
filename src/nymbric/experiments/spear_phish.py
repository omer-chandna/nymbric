"""Spear-phish runner: measure attack success against a target across four
information-access conditions on one synthetic world.

Same identities, same target, same threat in every condition. Only the attacker's
information access changes (baseline / web / graph / combined), so a difference in
attack success is attributable to breach-derived personalization, under the
recorded controls. Every identity, lure, and action is fictional and inert.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from nymbric.core.config import AgentModelConfig, load_models
from nymbric.core.errors import NymbricError, ProviderUnavailable
from nymbric.core.types import ALL_CONDITIONS, PHISH_PRIMARY_METRICS, PHISH_SECONDARY_METRICS, PHISH_THREATS, Condition
from nymbric.experiments.compare import compare_runs, condition_logistic
from nymbric.experiments.pkg_risk import _select_identities
from nymbric.models.router import build_provider
from nymbric.orchestration.spear_phish import PhishRunSpec, SpearPhishOrchestrator, public_run
from nymbric.schemas.messages import Budget
from nymbric.storage.db import Database, utc_now
from nymbric.synthetic.world import generate_world

ROLES = ("web_research", "graph_research", "lure", "target", "risk_analysis")


def execute_spear_phish(
    db: Database,
    *,
    personas: int = 24,
    seed: int = 1,
    trials: int = 2,
    conditions: list[str] | None = None,
    provider: str | None = None,
    model: str | None = None,
    target_mode: str = "context_sensitive",
    threat: str = "calendar_pretext_link",
    channel: str = "email",
    ablation: str | None = None,
    mitigation: str | None = None,
    world_id: str | None = None,
    experiment_id: str | None = None,
    jsonl_dir: Path | None = None,
    external_cmd: list[str] | None = None,
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
    # The target provider is what we report as the system under test.
    target_provider = providers["target"].provider_name
    target_model = providers["target"].model
    runs: list[dict[str, Any]] = []
    for trial_index, identity_id in enumerate(selected):
        threat_name = PHISH_THREATS[trial_index % len(PHISH_THREATS)] if threat == "all" else threat
        for condition in condition_values:
            run_id = f"run-{uuid.uuid4().hex[:12]}"
            jsonl_path = None
            if jsonl_dir is not None:
                jsonl_dir.mkdir(parents=True, exist_ok=True)
                jsonl_path = jsonl_dir / f"{run_id}.jsonl"
            spec = PhishRunSpec(
                experiment_id=experiment_id,
                run_id=run_id,
                world_id=world_id,
                condition=condition,
                identity_id=identity_id,
                seed=seed,
                threat=threat_name,
                target_mode=target_mode,
                channel=channel,
                provider=target_provider,
                model=target_model,
                ablation=ablation,
                mitigation=mitigation,
                budget=Budget(max_tool_calls=48, max_steps=16, max_search_calls=8, max_pages_read=5, max_tokens=120000, max_seconds=180),
                trial_index=trial_index,
                external_cmd=external_cmd,
                jsonl_path=jsonl_path,
            )
            state = SpearPhishOrchestrator(db, providers).run(spec)
            runs.append(public_run(state))

    summary = {
        "experiment_id": experiment_id,
        "experiment": "spear-phish",
        "world_id": world_id,
        "content_hash": content_hash,
        "seed": seed,
        "provider": target_provider,
        "model": target_model,
        "target_mode": target_mode,
        "threat": threat,
        "channel": channel,
        "ablation": ablation,
        "mitigation": mitigation,
        "trials": len(selected),
        "conditions": condition_values,
        "runs": runs,
        "primary_metrics": list(PHISH_PRIMARY_METRICS),
        "comparisons": compare_runs(runs, metrics=list(PHISH_PRIMARY_METRICS)),
        "secondary_comparisons": compare_runs(runs, metrics=list(PHISH_SECONDARY_METRICS)),
        "logistic_attack_success": condition_logistic(runs, outcome="attack_success", condition="graph")
        if "graph" in condition_values and "web" in condition_values
        else None,
        "created_at": utc_now(),
        "label": (
            "Synthetic attack-success outcome against a configured target agent. Not a measurement of "
            "human susceptibility and not evidence that a real assistant or operating system was compromised."
        ),
    }
    db.execute(
        """
        INSERT OR REPLACE INTO experiments (experiment_id, name, config_json, summary_json, created_at)
        VALUES (?, 'spear-phish', ?, ?, ?)
        """,
        (
            experiment_id,
            json.dumps({k: summary[k] for k in ("seed", "provider", "model", "target_mode", "threat", "channel", "ablation", "mitigation", "conditions", "world_id")}),
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
