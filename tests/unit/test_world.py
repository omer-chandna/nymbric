import tempfile
from pathlib import Path

from nymbric.core.types import CANARY_PREFIX
from nymbric.storage.db import Database
from nymbric.synthetic.world import generate_world
from nymbric.web_research.search import WebIndex


def test_world_is_deterministic_and_separates_private_records():
    first = generate_world(personas=30, seed=42)
    second = generate_world(personas=30, seed=42)
    assert first["content_hash"] == second["content_hash"]
    blob = "\n".join(page["body"] for page in first["pages"])
    assert CANARY_PREFIX + "p" not in blob
    for asset in first["assets"]:
        if asset["sensitivity"] in {"high", "restricted"}:
            assert asset["title"] not in blob


def test_five_hundred_personas_index_and_search():
    bundle = generate_world(personas=500, seed=7)
    assert bundle["persona_count"] == 500
    assert len(bundle["pages"]) > 500
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "world.sqlite")
        db.persist_world(bundle)
        person = next(entity for entity in bundle["entities"] if entity["entity_type"] == "person")
        results = WebIndex(db, bundle["world_id"]).search(person["name"], limit=5)
        assert results["results"]
        page = WebIndex(db, bundle["world_id"]).open_page(results["results"][0]["page_id"])
        assert person["name"] in page["body"]
