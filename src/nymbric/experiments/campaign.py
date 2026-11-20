"""Campaign runner: a goal-directed, multi-stage red-team emulation over one
synthetic world, compared across two information regimes.

``osint`` only ever has public web info per node; ``enhanced`` lets a compromised
node yield its PKG to personalize the next hops. Holding the world, seed, entry
persona, goal, and node defender fixed, any difference in blast radius or
objective success is attributable to breach-derived personalization, under the
recorded controls. Every stage is modelled on fictional data and is inert.
"""

from __future__ import annotations

import json
import uuid
from collections import deque
from pathlib import Path
from typing import Any

from nymbric.core.config import AgentModelConfig, load_models
from nymbric.core.errors import NymbricError, ProviderUnavailable
from nymbric.experiments.compare import compare_campaign_regimes
from nymbric.models.router import build_provider
from nymbric.orchestration.campaign import CampaignOrchestrator, lateral_neighbours
from nymbric.schemas.messages import CampaignGoal, CampaignSpec
from nymbric.storage.db import Database, utc_now
from nymbric.synthetic.world import generate_world

ROLES = ("web_research", "graph_research", "lure", "target", "risk_analysis")
REGIMES = ("osint", "enhanced")


def execute_campaign(
    db: Database,
    *,
    personas: int = 16,
    seed: int = 1,
    entry: str | None = None,
    goal: str | CampaignGoal | None = None,
    regime: str = "both",
    max_depth: int = 3,
    max_nodes: int = 12,
    target_mode: str = "context_sensitive",
    threat: str = "calendar_pretext_link",
    channel: str = "email",
    mitigation: str | None = None,
    provider: str | None = None,
    model: str | None = None,
    world_id: str | None = None,
    experiment_id: str | None = None,
    jsonl_dir: Path | None = None,
) -> dict[str, Any]:
    del jsonl_dir  # campaign sub-runs persist to the runs table; no separate jsonl.
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
            raise NymbricError(f"World {world_id} does not exist. Generate it before running a campaign.")
        content_hash = world["content_hash"]

    entry_id = entry or _default_entry(db, world_id)
    entry_name = _person_name(db, world_id, entry_id)
    resolved_goal = _resolve_goal(db, world_id, entry_id, goal)

    regimes = list(REGIMES) if regime == "both" else [regime]
    for name in regimes:
        if name not in REGIMES:
            raise NymbricError(f"Unknown regime '{name}'. Expected osint, enhanced, or both.")

    experiment_id = experiment_id or f"exp-{uuid.uuid4().hex[:12]}"
    target_provider = providers["target"].provider_name
    target_model = providers["target"].model

    results: dict[str, Any] = {}
    for name in regimes:
        spec = CampaignSpec(
            experiment_id=experiment_id,
            world_id=world_id,
            seed=seed,
            entry_id=entry_id,
            goal=resolved_goal,
            regime=name,
            max_depth=max_depth,
            max_nodes=max_nodes,
            target_mode=target_mode,
            mitigation=mitigation,
            provider=target_provider,
            model=target_model,
            threat=threat,
            channel=channel,
        )
        result = CampaignOrchestrator(db, providers).run(spec)
        results[name] = result.model_dump()

    comparison = None
    if "osint" in results and "enhanced" in results:
        comparison = compare_campaign_regimes(results["osint"], results["enhanced"])

    summary = {
        "experiment_id": experiment_id,
        "experiment": "campaign",
        "world_id": world_id,
        "content_hash": content_hash,
        "seed": seed,
        "provider": target_provider,
        "model": target_model,
        "target_mode": target_mode,
        "threat": threat,
        "channel": channel,
        "mitigation": mitigation,
        "entry_id": entry_id,
        "entry_name": entry_name,
        "goal": resolved_goal.model_dump(),
        "max_depth": max_depth,
        "max_nodes": max_nodes,
        "personas": _persona_count(db, world_id),
        "regimes": results,
        "comparison": comparison,
        "created_at": utc_now(),
        "label": (
            "Synthetic, inert multi-stage attack emulation over a fictional persona graph. Initial "
            "access, PKG extraction, and lateral movement are modelled, not performed. Not evidence "
            "of a real intrusion, blast radius, or human susceptibility."
        ),
    }
    db.execute(
        """
        INSERT OR REPLACE INTO experiments (experiment_id, name, config_json, summary_json, created_at)
        VALUES (?, 'campaign', ?, ?, ?)
        """,
        (
            experiment_id,
            json.dumps(
                {
                    k: summary[k]
                    for k in (
                        "seed",
                        "provider",
                        "model",
                        "target_mode",
                        "threat",
                        "channel",
                        "mitigation",
                        "entry_id",
                        "goal",
                        "max_depth",
                        "max_nodes",
                        "world_id",
                    )
                }
            ),
            json.dumps(summary),
            summary["created_at"],
        ),
    )
    return summary


# -- entry / goal planning --------------------------------------------------
def _default_entry(db: Database, world_id: str) -> str:
    rows = db.query(
        "SELECT entity_id FROM entities WHERE world_id = ? AND entity_type = 'person' ORDER BY entity_id LIMIT 1",
        (world_id,),
    )
    if not rows:
        raise NymbricError(f"World {world_id} has no fictional people.")
    return rows[0]["entity_id"]


def _resolve_goal(db: Database, world_id: str, entry_id: str, goal: str | CampaignGoal | None) -> CampaignGoal:
    if isinstance(goal, CampaignGoal):
        return goal
    text = (goal or "crown-jewel").strip()
    kind, _, value = text.partition(":")
    kind = kind.strip().lower()
    value = value.strip()
    if kind in {"compromise", "compromise_persona", "persona"} and value:
        return CampaignGoal(kind="compromise_persona", target_persona=value, description=f"Compromise persona {value}.")
    if kind in {"exfiltrate", "exfiltrate_asset", "asset"} and value:
        return CampaignGoal(kind="exfiltrate_asset", target_asset=value, description=f"Exfiltrate asset {value}.")
    if kind in {"nodes", "count", "compromise_count"} and value:
        try:
            count = int(value)
        except ValueError as exc:
            raise NymbricError(f"Campaign goal 'nodes:{value}' needs an integer count.") from exc
        return CampaignGoal(kind="compromise_count", count=count, description=f"Compromise at least {count} personas.")
    if kind in {"crown-jewel", "crown_jewel", "default", ""}:
        return _crown_jewel_goal(db, world_id, entry_id)
    raise NymbricError(
        f"Unrecognized campaign goal '{text}'. Use compromise:<persona>, exfiltrate:<asset>, nodes:<N>, or crown-jewel."
    )


def _crown_jewel_goal(db: Database, world_id: str, entry_id: str) -> CampaignGoal:
    """Default objective: exfiltrate the restricted compensation memo of the
    deepest persona laterally reachable from the entry (prefer a 2+ hop target so
    OSINT-only is unlikely to reach it)."""
    depths = _lateral_depths(db, world_id, entry_id)
    candidates = sorted(
        ((persona, depth) for persona, depth in depths.items() if persona != entry_id and depth >= 1),
        key=lambda item: (-item[1], item[0]),
    )
    for persona, depth in candidates:
        asset_id = _restricted_document(db, world_id, persona)
        if asset_id:
            name = _person_name(db, world_id, persona)
            return CampaignGoal(
                kind="exfiltrate_asset",
                target_asset=asset_id,
                target_persona=persona,
                description=f"Exfiltrate {name}'s restricted compensation memo ({asset_id}), {depth} hop(s) from entry.",
            )
    # Fallback: the entry's own restricted memo (degenerate graph).
    asset_id = _restricted_document(db, world_id, entry_id)
    return CampaignGoal(
        kind="exfiltrate_asset",
        target_asset=asset_id or "",
        target_persona=entry_id,
        description="Exfiltrate the entry persona's restricted compensation memo.",
    )


def _lateral_depths(db: Database, world_id: str, entry_id: str, max_depth: int = 4) -> dict[str, int]:
    depth = {entry_id: 0}
    queue: deque[str] = deque([entry_id])
    while queue:
        current = queue.popleft()
        if depth[current] >= max_depth:
            continue
        for neighbour, _rel_type, _rel_id in lateral_neighbours(db, world_id, current):
            if neighbour not in depth:
                depth[neighbour] = depth[current] + 1
                queue.append(neighbour)
    return depth


def _restricted_document(db: Database, world_id: str, persona: str) -> str | None:
    rows = db.query(
        "SELECT asset_id FROM assets WHERE world_id = ? AND owner_id = ? AND kind = 'document' AND sensitivity = 'restricted' ORDER BY asset_id LIMIT 1",
        (world_id, persona),
    )
    return rows[0]["asset_id"] if rows else None


def _person_name(db: Database, world_id: str, persona: str) -> str:
    rows = db.query("SELECT name FROM entities WHERE world_id = ? AND entity_id = ?", (world_id, persona))
    if not rows:
        raise NymbricError(f"Persona {persona} is not in world {world_id}.")
    return rows[0]["name"]


def _persona_count(db: Database, world_id: str) -> int:
    rows = db.query(
        "SELECT COUNT(*) AS n FROM entities WHERE world_id = ? AND entity_type = 'person'",
        (world_id,),
    )
    return int(rows[0]["n"]) if rows else 0
