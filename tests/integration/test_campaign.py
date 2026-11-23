"""Campaign experiment: mock-only, deterministic.

These tests assert the headline (breach-enhanced reach > OSINT-only), that node
defenders and mitigations hold the chain, objective detection for each goal
kind, and that the depth/node budgets are respected. Every stage is modelled on
fictional data and is inert.
"""

from __future__ import annotations

import json

from nymbric.experiments.campaign import execute_campaign
from nymbric.storage.db import Database

# Seed 42 / 16 personas is a world where the entry (p0000) has a public employer,
# so OSINT earns the foothold and spreads partially, while only the breach reaches
# the deepest crown-jewel persona. Tuned empirically, like the spear-phish tests.
HEADLINE_SEED = 42
HEADLINE_PERSONAS = 16


def _metrics(summary, regime):
    return summary["regimes"][regime]["metrics"]


def test_enhanced_outspreads_osint_and_reaches_objective(tmp_path):
    db = Database(tmp_path / "n.sqlite")
    summary = execute_campaign(
        db,
        personas=HEADLINE_PERSONAS,
        seed=HEADLINE_SEED,
        regime="both",
        provider="mock",
        target_mode="context_sensitive",
        max_depth=3,
        max_nodes=10,
    )
    osint = _metrics(summary, "osint")
    enhanced = _metrics(summary, "enhanced")

    # The breach-enhanced regime reaches the objective; OSINT-only does not.
    assert enhanced["objective_reached"] == 1
    assert osint["objective_reached"] == 0
    # And it spreads to a strictly larger blast radius under the same controls.
    assert enhanced["nodes_compromised"] > osint["nodes_compromised"]
    assert enhanced["blast_radius"] > osint["blast_radius"]

    # Both regimes ran on one identical synthetic world.
    assert summary["regimes"]["osint"]["content_hash"] == summary["regimes"]["enhanced"]["content_hash"]
    # Only the breach yields the private meeting -> high personalization.
    enhanced_nodes = summary["regimes"]["enhanced"]["nodes"]
    assert any(n["breach_enhanced"] and n["personalization"] == "high" for n in enhanced_nodes)
    assert all(n["condition"] == "web" for n in summary["regimes"]["osint"]["nodes"])

    comparison = summary["comparison"]
    assert comparison["deltas"]["objective_reached"] == 1
    assert "objective" in comparison["headline"].lower()


def test_determinism(tmp_path):
    out = []
    for i in range(2):
        db = Database(tmp_path / f"n{i}.sqlite")
        summary = execute_campaign(
            db, personas=HEADLINE_PERSONAS, seed=HEADLINE_SEED, regime="both", provider="mock", max_nodes=10
        )
        out.append((_metrics(summary, "osint"), _metrics(summary, "enhanced")))
    assert out[0] == out[1]


def test_cautious_defender_holds_chain_at_entry(tmp_path):
    db = Database(tmp_path / "n.sqlite")
    summary = execute_campaign(
        db,
        personas=HEADLINE_PERSONAS,
        seed=HEADLINE_SEED,
        regime="enhanced",
        provider="mock",
        target_mode="cautious",
        max_depth=3,
        max_nodes=10,
    )
    m = _metrics(summary, "enhanced")
    assert m["nodes_compromised"] == 0  # a cautious node never takes the bait
    assert m["blast_radius"] == 0.0
    assert m["objective_reached"] == 0
    assert "target_declined:cautious" in m["controls_held"]


def test_credulous_and_context_sensitive_spread(tmp_path):
    db = Database(tmp_path / "n.sqlite")
    credulous = execute_campaign(
        db, personas=HEADLINE_PERSONAS, seed=HEADLINE_SEED, regime="enhanced", provider="mock", target_mode="credulous", max_nodes=10
    )
    assert _metrics(credulous, "enhanced")["nodes_compromised"] > 1
    sensitive = execute_campaign(
        db, personas=HEADLINE_PERSONAS, seed=HEADLINE_SEED, regime="enhanced", provider="mock", target_mode="context_sensitive", max_nodes=10
    )
    assert _metrics(sensitive, "enhanced")["nodes_compromised"] > 1


def test_mitigation_blocks_spread(tmp_path):
    db = Database(tmp_path / "n.sqlite")
    summary = execute_campaign(
        db,
        personas=HEADLINE_PERSONAS,
        seed=HEADLINE_SEED,
        regime="enhanced",
        provider="mock",
        target_mode="context_sensitive",
        mitigation="require_independent_verification",
        max_nodes=10,
    )
    m = _metrics(summary, "enhanced")
    assert m["nodes_compromised"] == 0
    assert "require_independent_verification" in m["controls_held"]


def test_goal_compromise_count(tmp_path):
    db = Database(tmp_path / "n.sqlite")
    summary = execute_campaign(
        db, personas=HEADLINE_PERSONAS, seed=HEADLINE_SEED, regime="enhanced", provider="mock", goal="nodes:3", max_nodes=10
    )
    assert _metrics(summary, "enhanced")["objective_reached"] == 1
    assert summary["goal"]["kind"] == "compromise_count"


def test_goal_compromise_persona(tmp_path):
    db = Database(tmp_path / "n.sqlite")
    summary = execute_campaign(
        db, personas=HEADLINE_PERSONAS, seed=HEADLINE_SEED, regime="osint", provider="mock", goal="compromise:p0000", max_nodes=10
    )
    # The entry persona has a public employer at this seed, so OSINT compromises it.
    assert _metrics(summary, "osint")["objective_reached"] == 1


def test_budgets_respected(tmp_path):
    db = Database(tmp_path / "n.sqlite")
    capped = execute_campaign(
        db, personas=HEADLINE_PERSONAS, seed=HEADLINE_SEED, regime="enhanced", provider="mock", target_mode="credulous", max_nodes=3, max_depth=3
    )
    assert _metrics(capped, "enhanced")["nodes_attacked"] <= 3
    shallow = execute_campaign(
        db, personas=HEADLINE_PERSONAS, seed=HEADLINE_SEED, regime="enhanced", provider="mock", target_mode="credulous", max_nodes=20, max_depth=1
    )
    assert max(n["depth"] for n in shallow["regimes"]["enhanced"]["nodes"]) <= 1


def test_pkg_extracted_and_summary_persisted(tmp_path):
    db = Database(tmp_path / "n.sqlite")
    summary = execute_campaign(
        db, personas=HEADLINE_PERSONAS, seed=HEADLINE_SEED, regime="enhanced", provider="mock", max_nodes=10
    )
    # A compromised node yields its synthetic PKG, including its restricted memo.
    compromised = [n for n in summary["regimes"]["enhanced"]["nodes"] if n["attack_success"]]
    assert compromised
    assert all(n["pkg"] is not None for n in compromised)
    assert any(n["pkg"]["restricted_documents"] for n in compromised)
    # The experiment summary row is stored under the 'campaign' name.
    row = db.query("SELECT name, summary_json FROM experiments WHERE experiment_id = ?", (summary["experiment_id"],))
    assert row and row[0]["name"] == "campaign"
    stored = json.loads(row[0]["summary_json"])
    assert stored["experiment"] == "campaign"


def test_lateral_movement_only_crosses_person_edges(tmp_path):
    db = Database(tmp_path / "n.sqlite")
    summary = execute_campaign(
        db, personas=HEADLINE_PERSONAS, seed=HEADLINE_SEED, regime="enhanced", provider="mock", target_mode="credulous", max_nodes=20
    )
    edges = summary["regimes"]["enhanced"]["edges"]
    assert edges
    for edge in edges:
        assert edge["dst_id"].startswith("p")  # never an org/meeting/document entity
        assert edge["rel_type"] in {"reports_to", "manages", "friend_of", "family_member", "works_with", "communicated_with"}
