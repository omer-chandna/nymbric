"""Deterministic research split. Known delegation does not need a model call."""

from __future__ import annotations

from nymbric.core.types import Capability


def plan_research_subtasks(permissions: set[str]) -> list[dict[str, str | list[str]]]:
    tasks = []
    web = {Capability.WEB_SEARCH.value, Capability.WEB_READ.value}
    graph = {Capability.GRAPH_QUERY.value, Capability.GRAPH_TRAVERSE.value}
    if web <= permissions:
        tasks.append({"agent": "web_research", "permissions": sorted(web)})
    if graph <= permissions:
        tasks.append({"agent": "graph_research", "permissions": sorted(graph)})
    return tasks
