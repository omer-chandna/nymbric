"""Research reports rendered from recorded runs. No illustrative numbers are added."""

from __future__ import annotations

import html
import json
from typing import Any


def dumps(summary: dict[str, Any]) -> str:
    return json.dumps(summary, indent=2, sort_keys=True)


def markdown_report(summary: dict[str, Any]) -> str:
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
        f"- Defender: `{summary.get('defender_mode')}`",
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
    logistic = summary.get("logistic_disclosure")
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


def _means_table(runs: list[dict[str, Any]]) -> str:
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
