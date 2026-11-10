"""Synthetic public-web search over the SQLite FTS5 index."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from nymbric.storage.db import Database

_TOKEN = re.compile(r"[A-Za-z0-9']+")


def fts_query(text: str) -> str:
    tokens = [tok for tok in _TOKEN.findall(text) if len(tok) > 1][:8]
    if not tokens:
        return ""
    return " OR ".join(f'"{tok}"' for tok in tokens)


class WebIndex:
    def __init__(self, db: Database, world_id: str):
        self.db = db
        self.world_id = world_id

    def search(self, query: str, limit: int = 5) -> dict[str, Any]:
        match = fts_query(query)
        if not match:
            return {"query": query, "results": []}
        try:
            rows = self.db.query(
                """
                SELECT page_id, title, url,
                       snippet(pages_fts, 1, '', '', ' … ', 18) AS snippet,
                       bm25(pages_fts) AS score
                FROM pages_fts
                WHERE pages_fts MATCH ? AND world_id = ?
                ORDER BY score
                LIMIT ?
                """,
                (match, self.world_id, int(limit)),
            )
        except sqlite3.OperationalError:
            return {"query": query, "results": [], "warning": "The search query could not be parsed."}
        return {
            "query": query,
            "results": [
                {
                    "page_id": row["page_id"],
                    "title": row["title"],
                    "url": row["url"],
                    "snippet": row["snippet"],
                    "score": row["score"],
                }
                for row in rows
            ],
        }

    def open_page(self, page_id: str) -> dict[str, Any]:
        rows = self.db.query(
            """
            SELECT page_id, url, title, site, body, published_at, archived, reliability, status, related_json
            FROM pages WHERE world_id = ? AND page_id = ?
            """,
            (self.world_id, page_id),
        )
        if not rows:
            return {"error": "not_found", "page_id": page_id}
        row = rows[0]
        return {
            "page_id": row["page_id"],
            "url": row["url"],
            "title": row["title"],
            "site": row["site"],
            "body": row["body"],
            "published_at": row["published_at"],
            "archived": bool(row["archived"]),
            "reliability": row["reliability"],
            "status": row["status"],
            "related": json.loads(row["related_json"]),
        }

    def find_on_page(self, page_id: str, query: str) -> dict[str, Any]:
        page = self.open_page(page_id)
        if "error" in page:
            return page
        needle = query.lower()
        hits = []
        for line in page["body"].splitlines():
            if needle in line.lower():
                hits.append(line.strip())
            if len(hits) >= 8:
                break
        return {"page_id": page_id, "query": query, "hits": hits, "body": page["body"] if hits else ""}
