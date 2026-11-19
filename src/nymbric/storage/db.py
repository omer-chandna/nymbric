"""SQLite persistence for worlds, runs, traces, and verifier-only records."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS worlds (
  world_id TEXT PRIMARY KEY,
  seed INTEGER NOT NULL,
  persona_count INTEGER NOT NULL,
  config_json TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entities (
  world_id TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  name TEXT NOT NULL,
  attrs_json TEXT NOT NULL,
  sensitivity TEXT NOT NULL,
  visibility TEXT NOT NULL,
  PRIMARY KEY (world_id, entity_id)
);

CREATE TABLE IF NOT EXISTS relationships (
  world_id TEXT NOT NULL,
  rel_id TEXT NOT NULL,
  src TEXT NOT NULL,
  dst TEXT NOT NULL,
  rel_type TEXT NOT NULL,
  direction TEXT NOT NULL,
  confidence REAL NOT NULL,
  observed_at TEXT NOT NULL,
  provenance TEXT NOT NULL,
  sensitivity TEXT NOT NULL,
  inference_status TEXT NOT NULL,
  visibility TEXT NOT NULL,
  src_name TEXT NOT NULL,
  dst_name TEXT NOT NULL,
  PRIMARY KEY (world_id, rel_id)
);

CREATE TABLE IF NOT EXISTS assets (
  world_id TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  sensitivity TEXT NOT NULL,
  visibility TEXT NOT NULL,
  channel TEXT NOT NULL,
  PRIMARY KEY (world_id, asset_id)
);

CREATE TABLE IF NOT EXISTS gt_facts (
  world_id TEXT NOT NULL,
  fact_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  predicate TEXT NOT NULL,
  object TEXT NOT NULL,
  object_id TEXT NOT NULL,
  visibility TEXT NOT NULL,
  current INTEGER NOT NULL,
  sensitivity TEXT NOT NULL,
  PRIMARY KEY (world_id, fact_id)
);

CREATE TABLE IF NOT EXISTS gt_relationships (
  world_id TEXT NOT NULL,
  rel_id TEXT NOT NULL,
  correct INTEGER NOT NULL,
  PRIMARY KEY (world_id, rel_id)
);

CREATE TABLE IF NOT EXISTS gt_assets (
  world_id TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  sensitivity TEXT NOT NULL,
  PRIMARY KEY (world_id, asset_id)
);

CREATE TABLE IF NOT EXISTS scenario_bindings (
  run_id TEXT NOT NULL,
  scenario_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  PRIMARY KEY (run_id, scenario_id)
);

CREATE TABLE IF NOT EXISTS lure_bindings (
  run_id TEXT NOT NULL,
  lure_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  PRIMARY KEY (run_id, lure_id)
);

CREATE TABLE IF NOT EXISTS pages (
  world_id TEXT NOT NULL,
  page_id TEXT NOT NULL,
  url TEXT NOT NULL,
  title TEXT NOT NULL,
  site TEXT NOT NULL,
  body TEXT NOT NULL,
  published_at TEXT NOT NULL,
  archived INTEGER NOT NULL,
  reliability REAL NOT NULL,
  status TEXT NOT NULL,
  entity_ids_json TEXT NOT NULL,
  related_json TEXT NOT NULL,
  PRIMARY KEY (world_id, page_id)
);

CREATE TABLE IF NOT EXISTS experiments (
  experiment_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  config_json TEXT NOT NULL,
  summary_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  experiment_id TEXT NOT NULL,
  world_id TEXT NOT NULL,
  condition TEXT NOT NULL,
  identity_id TEXT NOT NULL,
  trial_index INTEGER NOT NULL,
  seed INTEGER NOT NULL,
  threat TEXT NOT NULL,
  defender_mode TEXT NOT NULL,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  ablation TEXT,
  mitigation TEXT,
  status TEXT NOT NULL,
  metrics_json TEXT NOT NULL,
  config_json TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  content_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
  run_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  state_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (run_id, stage)
);

CREATE TABLE IF NOT EXISTS tasks (
  task_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  parent_task_id TEXT,
  agent TEXT NOT NULL,
  depth INTEGER NOT NULL,
  status TEXT NOT NULL,
  permissions_json TEXT NOT NULL,
  instruction_json TEXT NOT NULL,
  result_json TEXT,
  error TEXT
);

CREATE TABLE IF NOT EXISTS traces (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  event_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  finding_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  experiment_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  policy TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_traces_run ON traces(run_id);
CREATE INDEX IF NOT EXISTS idx_runs_experiment ON runs(experiment_id);
CREATE INDEX IF NOT EXISTS idx_rel_src ON relationships(world_id, src);
CREATE INDEX IF NOT EXISTS idx_rel_dst ON relationships(world_id, dst);
CREATE INDEX IF NOT EXISTS idx_assets_owner ON assets(world_id, owner_id);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self) -> None:
        with self._lock:
            self.conn.executescript(SCHEMA)
            self._ensure_fts()
            self.conn.commit()

    def _ensure_fts(self) -> None:
        row = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='pages_fts'"
        ).fetchone()
        if row is None:
            self.conn.execute(
                """
                CREATE VIRTUAL TABLE pages_fts USING fts5(
                  title, body, url,
                  page_id UNINDEXED,
                  world_id UNINDEXED,
                  tokenize='porter'
                )
                """
            )

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur

    def executemany(self, sql: str, rows: list[tuple[Any, ...]]) -> None:
        with self._lock:
            self.conn.executemany(sql, rows)
            self.conn.commit()

    def query(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self.conn.execute(sql, params))

    def persist_world(self, bundle: dict[str, Any]) -> None:
        with self._lock:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO worlds
                (world_id, seed, persona_count, config_json, content_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    bundle["world_id"],
                    bundle["seed"],
                    bundle["persona_count"],
                    json.dumps(bundle["config"], sort_keys=True),
                    bundle["content_hash"],
                    utc_now(),
                ),
            )
            wid = bundle["world_id"]
            for table in (
                "entities",
                "relationships",
                "assets",
                "gt_facts",
                "gt_relationships",
                "gt_assets",
                "pages",
            ):
                self.conn.execute(f"DELETE FROM {table} WHERE world_id = ?", (wid,))
            self.conn.execute("DELETE FROM pages_fts WHERE world_id = ?", (wid,))
            self.conn.executemany(
                """
                INSERT INTO entities
                (world_id, entity_id, entity_type, name, attrs_json, sensitivity, visibility)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        wid,
                        e["entity_id"],
                        e["entity_type"],
                        e["name"],
                        json.dumps(e["attrs"], sort_keys=True),
                        e["sensitivity"],
                        e["visibility"],
                    )
                    for e in bundle["entities"]
                ],
            )
            self.conn.executemany(
                """
                INSERT INTO relationships
                (world_id, rel_id, src, dst, rel_type, direction, confidence, observed_at,
                 provenance, sensitivity, inference_status, visibility, src_name, dst_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        wid,
                        r["rel_id"],
                        r["src"],
                        r["dst"],
                        r["rel_type"],
                        r["direction"],
                        r["confidence"],
                        r["observed_at"],
                        r["provenance"],
                        r["sensitivity"],
                        r["inference_status"],
                        r["visibility"],
                        r["src_name"],
                        r["dst_name"],
                    )
                    for r in bundle["relationships"]
                ],
            )
            self.conn.executemany(
                """
                INSERT INTO assets
                (world_id, asset_id, owner_id, kind, title, content, sensitivity, visibility, channel)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        wid,
                        a["asset_id"],
                        a["owner_id"],
                        a["kind"],
                        a["title"],
                        a["content"],
                        a["sensitivity"],
                        a["visibility"],
                        a["channel"],
                    )
                    for a in bundle["assets"]
                ],
            )
            self.conn.executemany(
                """
                INSERT INTO gt_facts
                (world_id, fact_id, subject_id, predicate, object, object_id, visibility, current, sensitivity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        wid,
                        f["fact_id"],
                        f["subject_id"],
                        f["predicate"],
                        f["object"],
                        f["object_id"],
                        f["visibility"],
                        1 if f["current"] else 0,
                        f["sensitivity"],
                    )
                    for f in bundle["gt_facts"]
                ],
            )
            self.conn.executemany(
                "INSERT INTO gt_relationships (world_id, rel_id, correct) VALUES (?, ?, ?)",
                [(wid, g["rel_id"], 1 if g["correct"] else 0) for g in bundle["gt_relationships"]],
            )
            self.conn.executemany(
                """
                INSERT INTO gt_assets (world_id, asset_id, owner_id, kind, value, sensitivity)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (wid, a["asset_id"], a["owner_id"], a["kind"], a["value"], a["sensitivity"])
                    for a in bundle["gt_assets"]
                ],
            )
            self.conn.executemany(
                """
                INSERT INTO pages
                (world_id, page_id, url, title, site, body, published_at, archived, reliability, status,
                 entity_ids_json, related_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        wid,
                        p["page_id"],
                        p["url"],
                        p["title"],
                        p["site"],
                        p["body"],
                        p["published_at"],
                        1 if p["archived"] else 0,
                        p["reliability"],
                        p["status"],
                        json.dumps(p["entity_ids"]),
                        json.dumps(p["related"]),
                    )
                    for p in bundle["pages"]
                ],
            )
            self.conn.executemany(
                """
                INSERT INTO pages_fts (title, body, url, page_id, world_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                [(p["title"], p["body"], p["url"], p["page_id"], wid) for p in bundle["pages"]],
            )
            self.conn.commit()

    def latest_world_id(self) -> str | None:
        rows = self.query("SELECT world_id FROM worlds ORDER BY created_at DESC LIMIT 1")
        return rows[0]["world_id"] if rows else None

    def world_row(self, world_id: str) -> dict[str, Any] | None:
        rows = self.query("SELECT * FROM worlds WHERE world_id = ?", (world_id,))
        if not rows:
            return None
        row = dict(rows[0])
        row["config"] = json.loads(row.pop("config_json"))
        return row

    def list_worlds(self) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT world_id, seed, persona_count, content_hash, created_at FROM worlds ORDER BY created_at DESC"
        )
        return [dict(r) for r in rows]
