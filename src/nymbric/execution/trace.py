"""Structured execution traces. Payloads are redacted and appended to JSONL."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from nymbric.core.redact import redact
from nymbric.storage.db import Database, utc_now

TRACE_SCHEMA = "nymbric.trace.v1"


class TraceSink:
    def __init__(self, db: Database, run_id: str, experiment_id: str, jsonl_path: Path | None = None):
        self.db = db
        self.run_id = run_id
        self.experiment_id = experiment_id
        self.jsonl_path = jsonl_path
        self.events: list[dict[str, Any]] = []
        if jsonl_path is not None:
            jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    def emit(
        self,
        event_type: str,
        *,
        stage: str,
        payload: dict[str, Any] | None = None,
        agent: str | None = None,
        task_id: str | None = None,
        parent_task_id: str | None = None,
    ) -> dict[str, Any]:
        event = {
            "schema_version": TRACE_SCHEMA,
            "event_id": uuid.uuid4().hex,
            "run_id": self.run_id,
            "experiment_id": self.experiment_id,
            "ts": utc_now(),
            "stage": stage,
            "event_type": event_type,
            "agent": agent,
            "task_id": task_id,
            "parent_task_id": parent_task_id,
            "payload": redact(payload or {}),
        }
        self.events.append(event)
        self.db.execute(
            "INSERT INTO traces (run_id, event_json) VALUES (?, ?)",
            (self.run_id, json.dumps(event, sort_keys=True)),
        )
        if self.jsonl_path is not None:
            with self.jsonl_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
        return event
