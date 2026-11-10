"""Durable experiment state. Verifier bindings are stored outside this object."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ExperimentState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    experiment_id: str
    run_id: str
    world_id: str
    condition: str
    identity_id: str
    display_name: str
    city: str
    trial_index: int = 0
    seed: int
    threat: str
    defender_mode: str
    provider: str
    model: str
    ablation: str | None = None
    mitigation: str | None = None
    stage: str = "init"
    status: str = "running"
    permissions: list[str] = Field(default_factory=list)
    completed_stages: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    agent_outputs: dict[str, Any] = Field(default_factory=dict)
    defender_input: dict[str, Any] | None = None
    verification: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[dict[str, Any]] = Field(default_factory=list)
    usage: dict[str, Any] = Field(default_factory=dict)
    started_at: str
    content_hash: str = ""
    parent_task_id: str | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)
    risk: dict[str, Any] | None = None
    evaluation: dict[str, Any] | None = None
    recipient: dict[str, Any] | None = None
    scenario: dict[str, Any] | None = None
    include_recipient: bool = True
    include_evaluator: bool = True
