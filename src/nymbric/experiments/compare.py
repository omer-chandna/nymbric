"""Matched comparisons. Causal wording is used only when one factor changes."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from nymbric.core.types import PRIMARY_METRICS, SECONDARY_METRICS
from nymbric.experiments.stats import bonferroni, logistic_regression, paired_binary, paired_delta_ci

BINARY_METRICS = {
    "unauthorized_disclosure",
    "unauthorized_action",
    "authorization_compliance",
    "false_positive",
    "false_negative",
    "memory_integrity_violation",
    "missing_independent_verification",
    # Spear-phish binary outcomes.
    "attack_success",
    "data_exfiltration",
    "link_followed",
    "attachment_opened",
    "instruction_execution",
    "target_resisted",
    "personalization_grounded",
}


def compare_runs(runs: list[dict[str, Any]], *, metric_family: str = "primary", metrics: list[str] | None = None) -> dict[str, Any]:
    """Compare conditions inside one experiment, or two explicit run lists already filtered.

    Pass an explicit ``metrics`` list to compare metric names outside the PKG-Risk
    primary/secondary families (the spear-phish experiment uses this).
    """
    grouped: dict[tuple, dict[str, dict[str, Any]]] = defaultdict(dict)
    for run in runs:
        key = (
            run.get("identity_id"),
            run.get("trial_index"),
            run.get("threat"),
            run.get("defender_mode"),
            run.get("provider"),
            run.get("model"),
            run.get("world_id"),
            run.get("ablation"),
            run.get("mitigation"),
            run.get("seed"),
        )
        grouped[key][run.get("condition")] = run
    present = {run.get("condition") for run in runs}
    preferred = ["baseline", "web", "graph", "combined"]
    conditions = [name for name in preferred if name in present] + sorted(name for name in present if name not in preferred)
    metrics = list(metrics) if metrics is not None else list(PRIMARY_METRICS if metric_family == "primary" else SECONDARY_METRICS)
    reports = []
    for left_index, left_name in enumerate(conditions):
        for right_name in conditions[left_index + 1 :]:
            reports.append(_pair(grouped, left_name, right_name, metrics))
    return {"conditions": conditions, "family": metric_family, "comparisons": reports}


def compare_two_groups(group_a: list[dict[str, Any]], group_b: list[dict[str, Any]], label_a: str, label_b: str) -> dict[str, Any]:
    """Compare two matched sets that already share every factor except the one under test."""
    by_key_a = {_match_key(run): run for run in group_a}
    pairs = []
    for run in group_b:
        other = by_key_a.get(_match_key(run))
        if other:
            pairs.append((other, run))
    controlled = _controls_ok(group_a, group_b)
    metrics = list(PRIMARY_METRICS) + ["fact_precision", "public_recall", "authorization_compliance"]
    results = {}
    p_values = []
    names = []
    for metric in metrics:
        deltas = []
        binary_a = []
        binary_b = []
        for left, right in pairs:
            lv = (left.get("metrics") or {}).get(metric)
            rv = (right.get("metrics") or {}).get(metric)
            if lv is None or rv is None:
                continue
            deltas.append(float(rv) - float(lv))
            if metric in BINARY_METRICS:
                binary_a.append(int(lv))
                binary_b.append(int(rv))
        entry: dict[str, Any] = {
            "n_pairs": len(deltas),
            "delta_b_minus_a": paired_delta_ci(deltas, seed=len(deltas) + 3) if deltas else None,
        }
        if binary_a:
            entry["mcnemar"] = paired_binary(binary_a, binary_b)
            p_values.append(entry["mcnemar"]["p_mcnemar"])
            names.append(metric)
        elif deltas:
            p_values.append((entry["delta_b_minus_a"] or {}).get("p_permutation"))
            names.append(metric)
        results[metric] = entry
    adjusted = bonferroni(p_values)
    for name, value in zip(names, adjusted):
        results[name]["p_bonferroni"] = value
    return {
        "label_a": label_a,
        "label_b": label_b,
        "n_pairs": len(pairs),
        "controlled": controlled,
        "claim_level": "paired_effect" if controlled and pairs else "unsupported",
        "metrics": results,
        "limitation": (
            "Paired effects are differences under the recorded controls. They are not estimates of "
            "real-world harm, human susceptibility, or an operating-system compromise."
        ),
    }


def condition_logistic(runs: list[dict[str, Any]], *, outcome: str, condition: str) -> dict[str, Any]:
    rows = []
    for run in runs:
        value = (run.get("metrics") or {}).get(outcome)
        if value is None or run.get("condition") not in {condition, "baseline", "web"}:
            continue
        if run.get("condition") not in {condition, "web"} and condition != "graph":
            continue
        predictor = 1.0 if run.get("condition") == condition else 0.0
        if run.get("condition") in {condition, "web", "baseline"}:
            rows.append((predictor, int(value)))
    # Keep only the named condition and web, the predeclared public-information contrast when present.
    filtered = []
    for run in runs:
        if run.get("condition") not in {condition, "web"}:
            continue
        value = (run.get("metrics") or {}).get(outcome)
        if value is None:
            continue
        filtered.append((1.0 if run.get("condition") == condition else 0.0, int(value)))
    fit = logistic_regression(filtered)
    fit["outcome"] = outcome
    fit["condition"] = condition
    fit["reference"] = "web"
    fit["n"] = len(filtered)
    return fit


def _pair(grouped, left_name: str, right_name: str, metrics: list[str]) -> dict[str, Any]:
    deltas: dict[str, list[float]] = {metric: [] for metric in metrics}
    binary: dict[str, tuple[list[int], list[int]]] = {metric: ([], []) for metric in metrics if metric in BINARY_METRICS}
    controls = set()
    n = 0
    for key, conditions in grouped.items():
        if left_name not in conditions or right_name not in conditions:
            continue
        n += 1
        controls.add(key[3:9])
        for metric in metrics:
            lv = (conditions[left_name].get("metrics") or {}).get(metric)
            rv = (conditions[right_name].get("metrics") or {}).get(metric)
            if lv is None or rv is None:
                continue
            deltas[metric].append(float(rv) - float(lv))
            if metric in BINARY_METRICS:
                binary[metric][0].append(int(lv))
                binary[metric][1].append(int(rv))
    body: dict[str, Any] = {}
    p_values: list[float | None] = []
    order: list[str] = []
    for metric, values in deltas.items():
        entry: dict[str, Any] = {"n_pairs": len(values), "delta": paired_delta_ci(values, seed=n + len(metric)) if values else None}
        if metric in binary and binary[metric][0]:
            entry["mcnemar"] = paired_binary(*binary[metric])
            p_values.append(entry["mcnemar"]["p_mcnemar"])
            order.append(metric)
        elif values:
            p_values.append(entry["delta"]["p_permutation"] if entry["delta"] else None)
            order.append(metric)
        body[metric] = entry
    for metric, adjusted in zip(order, bonferroni(p_values)):
        body[metric]["p_bonferroni"] = adjusted
        p_raw = body[metric].get("mcnemar", {}).get("p_mcnemar")
        if p_raw is None and body[metric].get("delta"):
            p_raw = body[metric]["delta"].get("p_permutation")
        body[metric]["significant_0_05"] = bool(adjusted is not None and adjusted < 0.05)
    return {
        "a": left_name,
        "b": right_name,
        "n_pairs": n,
        "claim_level": "paired_effect" if len(controls) == 1 and n else "unsupported",
        "metrics": body,
    }


def compare_campaign_regimes(osint: dict[str, Any], enhanced: dict[str, Any]) -> dict[str, Any]:
    """Compare the OSINT-only and breach-enhanced regimes of one campaign.

    Both regimes run on the same world, seed, entry, goal, and node defender, so
    the only thing that changes is the attacker's information access. Under the
    deterministic mock there is one campaign per regime (no sampling variance),
    so this is a direct matched difference, not a bootstrap interval.
    """
    om = osint.get("metrics") or {}
    em = enhanced.get("metrics") or {}
    keys = (
        "objective_reached",
        "nodes_compromised",
        "blast_radius",
        "blast_radius_count",
        "depth_reached",
        "nodes_attacked",
        "attack_success_rate",
    )
    deltas = {}
    for key in keys:
        left = om.get(key)
        right = em.get(key)
        deltas[key] = (right - left) if isinstance(left, (int, float)) and isinstance(right, (int, float)) else None
    if em.get("objective_reached") and not om.get("objective_reached"):
        headline = (
            "Breach-enhanced personalization reached the objective and a larger blast radius than "
            "OSINT-only, holding world, seed, entry, defender, and threat fixed."
        )
    elif (em.get("blast_radius_count") or 0) > (om.get("blast_radius_count") or 0):
        headline = "Breach-enhanced personalization spread further than OSINT-only under identical controls."
    else:
        headline = "No regime separation in this configuration (e.g. a defender held the chain at the entry)."
    return {
        "osint": om,
        "enhanced": em,
        "deltas": deltas,
        "claim_level": "deterministic_single_world",
        "headline": headline,
        "limitation": (
            "A regime difference is a property of the synthetic world and the recorded node defender. "
            "It is not an estimate of real-world blast radius, human susceptibility, or an actual intrusion."
        ),
    }


def _match_key(run: dict[str, Any]) -> tuple:
    return (
        run.get("identity_id"),
        run.get("trial_index"),
        run.get("threat"),
        run.get("defender_mode"),
        run.get("provider"),
        run.get("model"),
        run.get("world_id"),
        run.get("seed"),
    )


def _controls_ok(group_a: list[dict[str, Any]], group_b: list[dict[str, Any]]) -> bool:
    if not group_a or not group_b:
        return False
    fields = ("defender_mode", "provider", "model", "world_id", "threat", "seed")
    return all(len({run.get(field) for run in group_a + group_b}) == 1 for field in fields)
