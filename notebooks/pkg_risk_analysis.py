"""Reproduce PKG-Risk summaries from a stored experiment JSON file.

Usage:
    python notebooks/pkg_risk_analysis.py examples/mock_pkg_risk_summary.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from nymbric.experiments.compare import compare_runs
from nymbric.reporting.export import markdown_report


def main(path: str) -> None:
    summary = json.loads(Path(path).read_text(encoding="utf-8"))
    if "runs" not in summary:
        print("This file has no runs. It is not a PKG-Risk summary.")
        return
    fresh = compare_runs(summary["runs"], metric_family="primary")
    print(summary.get("label", ""))
    print(f"provider={summary.get('provider')} model={summary.get('model')} defender={summary.get('defender_mode')}")
    print(markdown_report({**summary, "comparisons": fresh}))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Pass a summary JSON path.")
        sys.exit(2)
    main(sys.argv[1])
