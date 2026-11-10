# Examples

`mock_pkg_risk_summary.json` is produced by `execute_pkg_risk` with the mock provider, seed 42, 12 personas, 2 trials, all four conditions, and the `familiarity_biased` defender. It is a synthetic policy result, not a local-model result and not a human-subject result.

Regenerate it with:

```bash
python -c "import json; from pathlib import Path; from nymbric.storage.db import Database; from nymbric.experiments.pkg_risk import execute_pkg_risk; db=Database(Path('/tmp/nymbric-example.sqlite')); summary=execute_pkg_risk(db, personas=12, seed=42, trials=2, provider='mock', defender_mode='familiarity_biased', include_evaluator=False); Path('examples/mock_pkg_risk_summary.json').write_text(json.dumps(summary, indent=2))"
```
