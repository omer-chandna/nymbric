"""Checkpoint load and save. The snapshot is the experiment state, not verifier secrets."""

from __future__ import annotations

from nymbric.core.errors import CheckpointError
from nymbric.orchestration.state import ExperimentState
from nymbric.storage.db import Database, utc_now


def save_checkpoint(db: Database, state: ExperimentState) -> None:
    payload = state.model_dump_json()
    now = utc_now()
    db.execute(
        """
        INSERT INTO checkpoints (run_id, stage, state_json, created_at)
        VALUES (?, 'latest', ?, ?)
        ON CONFLICT(run_id, stage) DO UPDATE SET state_json=excluded.state_json, created_at=excluded.created_at
        """,
        (state.run_id, payload, now),
    )
    db.execute(
        """
        INSERT INTO checkpoints (run_id, stage, state_json, created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(run_id, stage) DO UPDATE SET state_json=excluded.state_json, created_at=excluded.created_at
        """,
        (state.run_id, state.stage, payload, now),
    )


def load_checkpoint(db: Database, run_id: str) -> ExperimentState:
    rows = db.query(
        "SELECT state_json FROM checkpoints WHERE run_id = ? AND stage = 'latest'",
        (run_id,),
    )
    if not rows:
        raise CheckpointError(f"No checkpoint exists for run {run_id}.")
    return ExperimentState.model_validate_json(rows[0]["state_json"])
