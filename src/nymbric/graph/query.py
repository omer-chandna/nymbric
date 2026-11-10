"""Permissioned graph reads. This module never queries verifier tables."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import networkx as nx

from nymbric.storage.db import Database


@dataclass
class GraphAblation:
    name: str | None = None
    drop_inferred: bool = False
    drop_temporal: bool = False
    drop_communication: bool = False
    drop_sensitive: bool = False
    min_confidence: float = 0.0
    max_depth: int = 2


ABLATIONS: dict[str, GraphAblation] = {
    "drop_inferred": GraphAblation(name="drop_inferred", drop_inferred=True),
    "drop_temporal": GraphAblation(name="drop_temporal", drop_temporal=True),
    "drop_communication": GraphAblation(name="drop_communication", drop_communication=True),
    "drop_sensitive": GraphAblation(name="drop_sensitive", drop_sensitive=True),
    "drop_low_confidence": GraphAblation(name="drop_low_confidence", min_confidence=0.6),
    "single_hop": GraphAblation(name="single_hop", max_depth=1),
}


def ablation_from_name(name: str | None) -> GraphAblation:
    if not name:
        return GraphAblation()
    if name not in ABLATIONS:
        known = ", ".join(sorted(ABLATIONS))
        raise ValueError(f"Unknown ablation '{name}'. Expected one of: {known}.")
    return ABLATIONS[name]


class GraphView:
    """Observed personal-knowledge-graph projection for one policy view."""

    def __init__(self, db: Database, world_id: str, ablation: GraphAblation | None = None):
        self.db = db
        self.world_id = world_id
        self.ablation = ablation or GraphAblation()

    def query_entity(self, name: str, city: str | None = None, directory_id: str | None = None) -> dict[str, Any]:
        rows = self.db.query(
            """
            SELECT entity_id, name, attrs_json, sensitivity, visibility
            FROM entities
            WHERE world_id = ? AND entity_type = 'person' AND lower(name) = lower(?)
            """,
            (self.world_id, name),
        )
        entities = []
        for row in rows:
            if directory_id and row["entity_id"] != directory_id:
                continue
            attrs = json.loads(row["attrs_json"])
            if city and not directory_id and attrs.get("city") != city:
                continue
            entities.append(
                {
                    "entity_id": row["entity_id"],
                    "name": row["name"],
                    "city": attrs.get("city"),
                    "title": attrs.get("title"),
                    "org_name": attrs.get("org_name"),
                    "uni_name": attrs.get("uni_name"),
                    "sensitivity": row["sensitivity"],
                    "visibility": row["visibility"],
                }
            )
        return {"entities": entities}

    def get_relationships(self, entity_id: str) -> dict[str, Any]:
        rows = self.db.query(
            """
            SELECT * FROM relationships
            WHERE world_id = ? AND (src = ? OR dst = ?)
            """,
            (self.world_id, entity_id, entity_id),
        )
        rels = [self._project(row) for row in rows if self._visible(row)]
        return {"entity_id": entity_id, "relationships": rels, "assets": self.assets(entity_id)}

    def assets(self, entity_id: str) -> list[dict[str, Any]]:
        rows = self.db.query(
            """
            SELECT asset_id, owner_id, kind, title, content, sensitivity, visibility
            FROM assets
            WHERE world_id = ? AND owner_id = ? AND channel IN ('graph', 'both')
            """,
            (self.world_id, entity_id),
        )
        projected = []
        for row in rows:
            if self.ablation.drop_sensitive and row["sensitivity"] in {"high", "restricted"}:
                continue
            projected.append(
                {
                    "asset_id": row["asset_id"],
                    "owner_id": row["owner_id"],
                    "kind": row["kind"],
                    "title": row["title"],
                    "content": row["content"],
                    "sensitivity": row["sensitivity"],
                    "visibility": row["visibility"],
                }
            )
        return projected

    def traverse(self, entity_id: str, depth: int) -> dict[str, Any]:
        depth = max(0, min(int(depth), self.ablation.max_depth))
        graph = self._network()
        if entity_id not in graph:
            return {"nodes": [], "edges": [], "depth": depth}
        lengths = nx.single_source_shortest_path_length(graph, entity_id, cutoff=depth)
        edges = []
        seen: set[str] = set()
        for source, target, data in graph.edges(data=True):
            if source not in lengths or target not in lengths:
                continue
            rel_id = data.get("rel_id")
            if not rel_id or rel_id in seen:
                continue
            seen.add(rel_id)
            projected = data["projected"]
            edges.append(
                {
                    "rel_id": projected["rel_id"],
                    "src": projected["src"],
                    "dst": projected["dst"],
                    "rel_type": projected["rel_type"],
                    "inference_status": projected["inference_status"],
                }
            )
            if len(edges) >= 12:
                break
        nodes = [{"entity_id": node, "distance": dist} for node, dist in sorted(lengths.items())]
        return {"nodes": nodes[:12], "edges": edges, "depth": depth}

    def _visible(self, row: Any) -> bool:
        if self.ablation.drop_inferred and row["inference_status"] == "inferred":
            return False
        if self.ablation.drop_communication and row["rel_type"] == "communicated_with":
            return False
        if self.ablation.drop_sensitive and row["sensitivity"] in {"high", "restricted"}:
            return False
        if float(row["confidence"]) < self.ablation.min_confidence:
            return False
        return True

    def _project(self, row: Any) -> dict[str, Any]:
        return {
            "rel_id": row["rel_id"],
            "src": row["src"],
            "dst": row["dst"],
            "src_name": row["src_name"],
            "dst_name": row["dst_name"],
            "rel_type": row["rel_type"],
            "direction": row["direction"],
            "confidence": row["confidence"],
            "observed_at": None if self.ablation.drop_temporal else row["observed_at"],
            "provenance": row["provenance"],
            "sensitivity": row["sensitivity"],
            "inference_status": row["inference_status"],
            "visibility": row["visibility"],
        }

    def _network(self) -> nx.DiGraph:
        rows = self.db.query("SELECT * FROM relationships WHERE world_id = ?", (self.world_id,))
        graph: nx.DiGraph = nx.DiGraph()
        for row in rows:
            if not self._visible(row):
                continue
            projected = self._project(row)
            graph.add_edge(row["src"], row["dst"], rel_id=row["rel_id"], projected=projected)
            if row["direction"] == "undirected":
                graph.add_edge(row["dst"], row["src"], rel_id=row["rel_id"], projected=projected)
        return graph
