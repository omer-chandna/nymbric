"""Rerun one matched experiment with a single factor changed."""

from __future__ import annotations

from typing import Any

from nymbric.experiments.compare import compare_two_groups
from nymbric.experiments.pkg_risk import execute_pkg_risk
from nymbric.storage.db import Database


def run_counterfactual(
    db: Database,
    *,
    factor: str,
    value: str,
    base: dict[str, Any],
) -> dict[str, Any]:
    if factor not in {"mitigation", "ablation", "defender_mode"}:
        raise ValueError("Counterfactual factor must be mitigation, ablation, or defender_mode.")
    before_kwargs = {key: val for key, val in base.items() if key != "experiment_id"}
    if factor != "defender_mode":
        before_kwargs[factor] = None
    before = execute_pkg_risk(db, **before_kwargs)
    after_kwargs = dict(before_kwargs)
    after_kwargs["world_id"] = before["world_id"]
    after_kwargs[factor] = value
    after = execute_pkg_risk(db, **after_kwargs)
    comparison = compare_two_groups(before["runs"], after["runs"], "before", f"after:{factor}={value}")
    comparison["factor"] = factor
    comparison["value"] = value
    comparison["before_experiment"] = before["experiment_id"]
    comparison["after_experiment"] = after["experiment_id"]
    comparison["note"] = (
        "The second run changes only the named factor and reuses the world, seed, identities, threat, "
        "provider, and model. This is a matched comparison, not an uncontrolled correlation."
    )
    return comparison
