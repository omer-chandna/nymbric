"""Deterministic campaign orchestrator: a goal-directed, multi-stage red-team
emulator over Nymbric's synthetic world.

The emulator is handed one entry persona and a goal and walks an attack graph:

    initial access -> PKG extraction -> lateral movement -> objective

Every stage is MODELLED over the fictional persona graph and is fully inert.
"Initial access" is a spear-phish single-node sub-run (reusing
``SpearPhishOrchestrator``); a node is compromised only when that sub-run's
authoritative ``attack_success`` is true. "PKG extraction" reads the compromised
persona's synthetic rows (``assets`` + ``relationships``). "Lateral movement"
enumerates adjacent personas and personalizes the next hop with the breached
neighbour's PKG. Nothing here touches a real device, inbox, account, or person.

The information regime controls how much the attacker knows per node:

- ``osint``   -- every node is attacked with public web info only (``web``).
- ``enhanced``-- the entry is attacked with OSINT (``web``); once a node is
  compromised, each neighbour reached from it is attacked with the breached
  PKG (``combined``), which recovers the private meeting the OSINT web never
  sees, so the lure is highly personalized and spreads further.
"""

from __future__ import annotations

import re
import threading
import uuid
from collections import deque
from typing import Any

from nymbric.core.errors import NymbricError
from nymbric.experiments.metrics import campaign_metrics
from nymbric.orchestration.spear_phish import PhishRunSpec, SpearPhishOrchestrator
from nymbric.schemas.messages import (
    AttackGraphEdge,
    CampaignGoal,
    CampaignNodeResult,
    CampaignResult,
    CampaignSpec,
)
from nymbric.storage.db import Database

# Person entity ids are ``pNNNN``. Only person<->person edges drive lateral
# movement; edges to orgs/meetings/documents/projects/events are excluded.
_PERSON_RE = re.compile(r"^p\d{4,}$")
LATERAL_RELS = (
    "reports_to",
    "manages",
    "friend_of",
    "family_member",
    "works_with",
    "communicated_with",
)


def lateral_neighbours(db: Database, world_id: str, persona: str) -> list[tuple[str, str, str]]:
    """Adjacent personas reachable by a person<->person tie, as (id, rel_type, rel_id).

    Deterministically ordered by ``rel_id``. Shared by the orchestrator's lateral
    movement and the experiment's objective planner.
    """
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for row in db.query(
        "SELECT rel_id, src, dst, rel_type FROM relationships WHERE world_id = ? AND (src = ? OR dst = ?) ORDER BY rel_id",
        (world_id, persona, persona),
    ):
        if row["rel_type"] not in LATERAL_RELS:
            continue
        other = row["dst"] if row["src"] == persona else row["src"]
        if other == persona or not _PERSON_RE.match(other) or other in seen:
            continue
        seen.add(other)
        out.append((other, row["rel_type"], row["rel_id"]))
    return out


class CampaignOrchestrator:
    def __init__(self, db: Database, providers: dict[str, Any], cancel_event: threading.Event | None = None):
        self.db = db
        self.providers = providers
        self.cancel_event = cancel_event or threading.Event()

    # -- public entry ------------------------------------------------------
    def run(self, spec: CampaignSpec) -> CampaignResult:
        world = self.db.world_row(spec.world_id)
        if world is None:
            raise NymbricError(f"World {spec.world_id} does not exist. Generate it before running a campaign.")
        if not self._is_person(spec.world_id, spec.entry_id):
            raise NymbricError(f"Entry {spec.entry_id} is not a person in world {spec.world_id}.")

        entry_name = self._person(spec.world_id, spec.entry_id)["name"]
        campaign_id = f"camp-{spec.regime}-{uuid.uuid4().hex[:10]}"

        visited: set[str] = set()
        compromised: set[str] = set()
        nodes: list[CampaignNodeResult] = []
        edges: list[AttackGraphEdge] = []
        pkgs: dict[str, dict[str, Any]] = {}
        objective_reached = False
        objective_depth: int | None = None

        # (persona, depth, parent_id, rel_type) -- BFS keeps depth order so the
        # budgets bite deterministically regardless of graph shape.
        frontier: deque[tuple[str, int, str, str]] = deque([(spec.entry_id, 0, "", "")])
        attacks = 0

        while frontier and attacks < spec.max_nodes:
            persona, depth, parent, _rel = frontier.popleft()
            if persona in visited or depth > spec.max_depth:
                continue
            visited.add(persona)
            if self.cancel_event.is_set():
                break

            breach_enhanced = spec.regime == "enhanced" and bool(parent) and parent in compromised
            condition = "combined" if breach_enhanced else "web"

            attacks += 1
            node = self._attack_node(spec, persona, condition, depth, parent, breach_enhanced)
            nodes.append(node)

            if node.attack_success:
                compromised.add(persona)
                pkg = self._extract_pkg(spec.world_id, persona)
                node.foothold = True
                node.pkg = pkg
                pkgs[persona] = pkg
                # Lateral movement: enqueue adjacent personas within the depth budget.
                for neighbour, rel_type, rel_id in self._adjacent_personas(spec.world_id, persona):
                    if neighbour in visited:
                        continue
                    edges.append(
                        AttackGraphEdge(
                            src_id=persona,
                            dst_id=neighbour,
                            rel_type=rel_type,
                            rel_id=rel_id,
                            pivot_context=self._pivot_context(spec.world_id, persona, neighbour, rel_type, pkg),
                        )
                    )
                    if depth + 1 <= spec.max_depth:
                        frontier.append((neighbour, depth + 1, persona, rel_type))
                if not objective_reached and self._objective_reached(spec.world_id, spec.goal, compromised):
                    objective_reached = True
                    objective_depth = depth

        for edge in edges:
            edge.led_to_compromise = edge.dst_id in compromised

        total_personas = self._persona_count(spec.world_id)
        result = CampaignResult(
            campaign_id=campaign_id,
            experiment_id=spec.experiment_id,
            world_id=spec.world_id,
            seed=spec.seed,
            regime=spec.regime,
            entry_id=spec.entry_id,
            entry_name=entry_name,
            goal=spec.goal,
            target_mode=spec.target_mode,
            mitigation=spec.mitigation,
            max_depth=spec.max_depth,
            max_nodes=spec.max_nodes,
            provider=spec.provider,
            model=spec.model,
            threat=spec.threat,
            channel=spec.channel,
            nodes=nodes,
            edges=edges,
            objective_reached=objective_reached,
            objective_reached_at_depth=objective_depth,
            content_hash=world["content_hash"],
        )
        result.metrics = campaign_metrics(result, total_personas)
        return result

    # -- stages ------------------------------------------------------------
    def _attack_node(
        self,
        spec: CampaignSpec,
        persona: str,
        condition: str,
        depth: int,
        parent: str,
        breach_enhanced: bool,
    ) -> CampaignNodeResult:
        """Initial-access stage: one inert spear-phish sub-run against the node.

        The sub-run's verifier reads the inert ``TargetEnvironment`` and is the
        sole authority on whether the foothold was earned.
        """
        person = self._person(spec.world_id, persona)
        run_id = f"crun-{uuid.uuid4().hex[:12]}"
        phish_spec = PhishRunSpec(
            experiment_id=spec.experiment_id,
            run_id=run_id,
            world_id=spec.world_id,
            condition=condition,
            identity_id=persona,
            seed=spec.seed,
            threat=spec.threat,
            target_mode=spec.target_mode,
            channel=spec.channel,
            provider=self.providers["target"].provider_name,
            model=self.providers["target"].model,
            mitigation=spec.mitigation,
            trial_index=depth,
        )
        state = SpearPhishOrchestrator(self.db, self.providers, self.cancel_event).run(phish_spec)
        metrics = state.metrics or {}
        success = bool(metrics.get("attack_success"))
        control = "" if success else self._control_held(spec, metrics)
        return CampaignNodeResult(
            persona_id=persona,
            name=person["name"],
            depth=depth,
            parent_id=parent,
            condition=condition,
            breach_enhanced=breach_enhanced,
            attack_success=success,
            personalization=str(metrics.get("personalization_level") or "generic"),
            personalization_grounded=int(metrics.get("personalization_grounded") or 0),
            control_held=control,
            run_id=run_id,
        )

    def _control_held(self, spec: CampaignSpec, metrics: dict[str, Any]) -> str:
        if int(metrics.get("mitigation_blocked") or 0) > 0 and spec.mitigation:
            return spec.mitigation
        return f"target_declined:{spec.target_mode}"

    def _extract_pkg(self, world_id: str, persona: str) -> dict[str, Any]:
        """PKG-extraction stage: pull the compromised persona's synthetic rows.

        Stores a compact summary (ids / kinds / titles / sensitivities and the
        adjacency), not raw canary content, so the campaign record stays small.
        """
        assets = [
            {
                "asset_id": row["asset_id"],
                "kind": row["kind"],
                "title": row["title"],
                "sensitivity": row["sensitivity"],
                "visibility": row["visibility"],
            }
            for row in self.db.query(
                "SELECT asset_id, kind, title, sensitivity, visibility FROM assets WHERE world_id = ? AND owner_id = ? ORDER BY asset_id",
                (world_id, persona),
            )
        ]
        rels = [
            {
                "rel_id": row["rel_id"],
                "src": row["src"],
                "dst": row["dst"],
                "rel_type": row["rel_type"],
                "src_name": row["src_name"],
                "dst_name": row["dst_name"],
                "sensitivity": row["sensitivity"],
            }
            for row in self.db.query(
                "SELECT rel_id, src, dst, rel_type, src_name, dst_name, sensitivity FROM relationships WHERE world_id = ? AND (src = ? OR dst = ?) ORDER BY rel_id",
                (world_id, persona, persona),
            )
        ]
        return {
            "asset_count": len(assets),
            "relationship_count": len(rels),
            "asset_ids": [a["asset_id"] for a in assets],
            "restricted_asset_ids": [a["asset_id"] for a in assets if a["sensitivity"] == "restricted"],
            "restricted_documents": [a["asset_id"] for a in assets if a["kind"] == "document" and a["sensitivity"] == "restricted"],
            "assets": assets,
            "relationships": rels,
        }

    # -- graph helpers -----------------------------------------------------
    def _adjacent_personas(self, world_id: str, persona: str) -> list[tuple[str, str, str]]:
        return lateral_neighbours(self.db, world_id, persona)

    def _pivot_context(self, world_id: str, persona: str, neighbour: str, rel_type: str, pkg: dict[str, Any]) -> dict[str, Any]:
        """Describe the shared private context the breached PKG gives for this hop."""
        neighbour_name = self._person(world_id, neighbour)["name"]
        shared_meeting = ""
        for row in self.db.query(
            "SELECT title, content FROM assets WHERE world_id = ? AND owner_id = ? AND kind = 'calendar_event'",
            (world_id, persona),
        ):
            if neighbour_name and neighbour_name in (row["content"] or ""):
                shared_meeting = row["title"]
                break
        return {
            "rel_type": rel_type,
            "shared_with": neighbour_name,
            "shared_meeting": shared_meeting,
            "source": "breached_pkg",
            "note": (
                f"Pivot from compromised {persona} to {neighbour} via a {rel_type} tie recovered "
                "from the breached private knowledge graph."
            ),
        }

    def _objective_reached(self, world_id: str, goal: CampaignGoal, compromised: set[str]) -> bool:
        if goal.kind == "compromise_persona":
            return goal.target_persona in compromised
        if goal.kind == "compromise_count":
            return len(compromised) >= max(1, goal.count)
        if goal.kind == "exfiltrate_asset":
            owner = self._asset_owner(world_id, goal.target_asset)
            return owner is not None and owner in compromised
        raise NymbricError(f"Unknown campaign goal kind '{goal.kind}'.")

    # -- world lookups -----------------------------------------------------
    def _person(self, world_id: str, persona: str) -> dict[str, Any]:
        rows = self.db.query(
            "SELECT name FROM entities WHERE world_id = ? AND entity_id = ?",
            (world_id, persona),
        )
        if not rows:
            raise NymbricError(f"Persona {persona} is not in world {world_id}.")
        return {"name": rows[0]["name"]}

    def _is_person(self, world_id: str, persona: str) -> bool:
        rows = self.db.query(
            "SELECT 1 FROM entities WHERE world_id = ? AND entity_id = ? AND entity_type = 'person'",
            (world_id, persona),
        )
        return bool(rows)

    def _asset_owner(self, world_id: str, asset_id: str) -> str | None:
        rows = self.db.query(
            "SELECT owner_id FROM assets WHERE world_id = ? AND asset_id = ?",
            (world_id, asset_id),
        )
        return rows[0]["owner_id"] if rows else None

    def _persona_count(self, world_id: str) -> int:
        rows = self.db.query(
            "SELECT COUNT(*) AS n FROM entities WHERE world_id = ? AND entity_type = 'person'",
            (world_id,),
        )
        return int(rows[0]["n"]) if rows else 0
