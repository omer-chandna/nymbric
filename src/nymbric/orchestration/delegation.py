"""Parent/child tasks. Children cannot receive capabilities the parent lacks."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from nymbric.context.isolation import assert_permissions_subset, scrub_instruction
from nymbric.core.errors import DelegationDenied


@dataclass
class TaskNode:
    task_id: str
    run_id: str
    parent_task_id: str | None
    agent: str
    depth: int
    permissions: set[str]
    instruction: dict[str, Any]
    status: str = "pending"
    result: dict[str, Any] | None = None
    error: str | None = None


@dataclass
class DelegationManager:
    run_id: str
    max_depth: int = 3
    tasks: dict[str, TaskNode] = field(default_factory=dict)

    def create(
        self,
        *,
        agent: str,
        permissions: set[str],
        instruction: dict[str, Any],
        parent_task_id: str | None = None,
        depth: int | None = None,
        allow_verification: bool = False,
    ) -> TaskNode:
        parent = self.tasks.get(parent_task_id) if parent_task_id else None
        if parent is not None:
            assert_permissions_subset(set(permissions), parent.permissions)
            resolved_depth = parent.depth + 1 if depth is None else depth
            if resolved_depth > self.max_depth:
                raise DelegationDenied(f"Delegation depth {resolved_depth} exceeds {self.max_depth}.")
        else:
            resolved_depth = 0 if depth is None else depth
            if resolved_depth > self.max_depth:
                raise DelegationDenied(f"Delegation depth {resolved_depth} exceeds {self.max_depth}.")
        clean = scrub_instruction(instruction, allow_verification=allow_verification)
        node = TaskNode(
            task_id=f"task-{uuid.uuid4().hex[:12]}",
            run_id=self.run_id,
            parent_task_id=parent_task_id,
            agent=agent,
            depth=resolved_depth,
            permissions=set(permissions),
            instruction=clean,
        )
        self.tasks[node.task_id] = node
        return node

    def complete(self, task_id: str, result: dict[str, Any]) -> None:
        self.tasks[task_id].status = "completed"
        self.tasks[task_id].result = result

    def fail(self, task_id: str, error: str) -> None:
        self.tasks[task_id].status = "failed"
        self.tasks[task_id].error = error
