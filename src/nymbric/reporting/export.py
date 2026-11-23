"""Research reports rendered from recorded runs. No illustrative numbers are added."""

from __future__ import annotations

import html
import json
from typing import Any


def dumps(summary: dict[str, Any]) -> str:
    return json.dumps(summary, indent=2, sort_keys=True)


def markdown_report(summary: dict[str, Any]) -> str:
    if summary.get("experiment") == "campaign" or "regimes" in summary:
        return _campaign_markdown(summary)
    lines = [
        f"# Nymbric report {summary.get('experiment_id', '')}",
        "",
        summary.get("label") or "Synthetic experiment record.",
        "",
        "## Configuration",
        "",
        f"- World: `{summary.get('world_id')}`",
        f"- Content hash: `{summary.get('content_hash')}`",
        f"- Seed: `{summary.get('seed')}`",
        f"- Provider: `{summary.get('provider')}`",
        f"- Model: `{summary.get('model')}`",
        f"- {'Target' if summary.get('target_mode') else 'Defender'}: `{summary.get('defender_mode') or summary.get('target_mode')}`",
        f"- Threat: `{summary.get('threat')}`",
        f"- Ablation: `{summary.get('ablation')}`",
        f"- Mitigation: `{summary.get('mitigation')}`",
        "",
        "## Condition means",
        "",
        _means_table(summary.get("runs") or []),
        "",
        "## Paired comparisons",
        "",
    ]
    comparisons = ((summary.get("comparisons") or {}).get("comparisons")) or []
    if not comparisons:
        lines.append("No paired comparison was stored.")
    for comparison in comparisons:
        lines.append(f"### {comparison.get('a')} → {comparison.get('b')}")
        lines.append("")
        lines.append(f"Claim level: `{comparison.get('claim_level')}`. Pairs: {comparison.get('n_pairs')}.")
        lines.append("")
        for metric, body in (comparison.get("metrics") or {}).items():
            delta = body.get("delta") or {}
            mean = delta.get("mean")
            low = delta.get("low")
            high = delta.get("high")
            p_value = None
            if body.get("mcnemar"):
                p_value = body["mcnemar"].get("p_mcnemar")
            elif delta:
                p_value = delta.get("p_permutation")
            adjusted = body.get("p_bonferroni")
            lines.append(
                f"- `{metric}`: mean delta { _fmt(mean) } (95% bootstrap interval {_fmt(low)} to {_fmt(high)}); "
                f"raw p {_fmt(p_value)}; Bonferroni p {_fmt(adjusted)}."
            )
            if delta.get("variance_note"):
                lines.append(f"  - {delta['variance_note']}")
            if adjusted is not None and adjusted >= 0.05:
                lines.append("  - The adjusted test does not meet a 0.05 threshold.")
        lines.append("")
    logistic = summary.get("logistic_disclosure") or summary.get("logistic_attack_success")
    if logistic:
        lines.extend(["## Logistic model", "", "```json", json.dumps(logistic, indent=2), "```", ""])
    lines.extend(
        [
            "## Limits",
            "",
            "Figures describe the configured agents on fictional data. A paired effect is not evidence about real people,",
            "and it is not an observation of a successful attack against a production assistant or operating system.",
            "Deterministic mock policies have no sampling variance across identical inputs.",
            "Qualitative model scores are not the security verdict. Deterministic checks are.",
            "",
        ]
    )
    return "\n".join(lines)


def html_report(summary: dict[str, Any]) -> str:
    body = html.escape(markdown_report(summary))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>Nymbric report</title>
  <style>
    body {{ margin: 2rem auto; max-width: 860px; font: 15px/1.5 "IBM Plex Sans", sans-serif; background: #10140f; color: #e7ecdf; }}
    pre {{ white-space: pre-wrap; }}
  </style>
</head>
<body><pre>{body}</pre></body>
</html>
"""


def _campaign_markdown(summary: dict[str, Any]) -> str:
    goal = summary.get("goal") or {}
    lines = [
        f"# Nymbric campaign report {summary.get('experiment_id', '')}",
        "",
        summary.get("label") or "Synthetic, inert multi-stage attack emulation.",
        "",
        "## Configuration",
        "",
        f"- World: `{summary.get('world_id')}`",
        f"- Content hash: `{summary.get('content_hash')}`",
        f"- Seed: `{summary.get('seed')}`",
        f"- Provider: `{summary.get('provider')}`  Model: `{summary.get('model')}`",
        f"- Node defender: `{summary.get('target_mode')}`  Mitigation: `{summary.get('mitigation')}`",
        f"- Threat: `{summary.get('threat')}`  Personas: `{summary.get('personas')}`",
        f"- Entry: `{summary.get('entry_id')}` ({summary.get('entry_name')})",
        f"- Goal: {goal.get('description') or goal.get('kind')}",
        f"- Budgets: max_depth `{summary.get('max_depth')}`, max_nodes `{summary.get('max_nodes')}`",
        "",
        "## Regime outcomes",
        "",
        _campaign_regime_table(summary.get("regimes") or {}),
        "",
    ]
    comparison = summary.get("comparison") or {}
    if comparison:
        lines += [
            "## OSINT vs breach-enhanced",
            "",
            f"**{comparison.get('headline')}**",
            "",
            f"Claim level: `{comparison.get('claim_level')}`.",
            "",
        ]
        for metric, delta in (comparison.get("deltas") or {}).items():
            lines.append(f"- `{metric}`: enhanced − osint = {_fmt(delta)}")
        lines.append("")
        if comparison.get("limitation"):
            lines += [comparison["limitation"], ""]
    for name, result in (summary.get("regimes") or {}).items():
        lines += [f"## Attack graph — {name}", "", _campaign_graph(result), ""]
    lines += [
        "## Limits",
        "",
        "Initial access, PKG extraction, and lateral movement are modelled over a fictional persona graph.",
        "A node falls only when its deterministic spear-phish verifier records a compromising action.",
        "These figures are not an observation of a real intrusion, a real blast radius, or human susceptibility.",
        "",
    ]
    return "\n".join(lines)


def _campaign_regime_table(regimes: dict[str, Any]) -> str:
    metrics = ["objective_reached", "nodes_compromised", "nodes_attacked", "blast_radius", "depth_reached", "controls_held_count"]
    header = "| Regime | " + " | ".join(metrics) + " |"
    rule = "| --- | " + " | ".join("---" for _ in metrics) + " |"
    rows = [header, rule]
    for name, result in regimes.items():
        m = result.get("metrics") or {}
        cells = [_fmt(m.get(metric)) for metric in metrics]
        rows.append(f"| {name} | " + " | ".join(cells) + " |")
    return "\n".join(rows) if regimes else "No regimes were recorded."


def _campaign_graph(result: dict[str, Any]) -> str:
    nodes = result.get("nodes") or []
    if not nodes:
        return "No nodes were attacked."
    lines = ["| Depth | Persona | Condition | Personalization | Foothold | Control held |", "| --- | --- | --- | --- | --- | --- |"]
    for node in nodes:
        fell = "✓" if node.get("attack_success") else "—"
        lines.append(
            f"| {node.get('depth')} | `{node.get('persona_id')}` {node.get('name')} | {node.get('condition')} | "
            f"{node.get('personalization')} | {fell} | {node.get('control_held') or ''} |"
        )
    edges = result.get("edges") or []
    compromised_edges = sum(1 for e in edges if e.get("led_to_compromise"))
    lines += ["", f"Pivots attempted: {len(edges)}; pivots that led to a compromise: {compromised_edges}."]
    return "\n".join(lines)


def _means_table(runs: list[dict[str, Any]]) -> str:
    is_phish = any("attack_success" in (run.get("metrics") or {}) for run in runs)
    if is_phish:
        metrics = [
            "attack_success",
            "link_followed",
            "attachment_opened",
            "data_exfiltration",
            "instruction_execution",
            "personalization_grounded",
            "mitigation_blocked",
        ]
    else:
        metrics = [
            "public_recall",
            "private_recall",
            "fact_f1",
            "unauthorized_disclosure",
            "authorization_compliance",
            "false_positive",
            "false_negative",
        ]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for run in runs:
        grouped.setdefault(str(run.get("condition")), []).append(run.get("metrics") or {})
    if not grouped:
        return "No runs were recorded."
    header = "| Condition | " + " | ".join(metrics) + " |"
    rule = "| --- | " + " | ".join("---" for _ in metrics) + " |"
    rows = [header, rule]
    for condition, items in grouped.items():
        cells = []
        for metric in metrics:
            values = [item.get(metric) for item in items if isinstance(item.get(metric), (int, float))]
            cells.append("—" if not values else f"{sum(values) / len(values):.3f}")
        rows.append(f"| {condition} | " + " | ".join(cells) + " |")
    return "\n".join(rows)


def _fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)
