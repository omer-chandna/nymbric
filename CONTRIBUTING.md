# Contributing

## Setup

```bash
pip install -e ".[dev]"
pytest
```

Dashboard changes also need `cd dashboard/frontend && npm install && npm run build`.

## Adding a piece

- **Agent.** Implement the same `run` shape as `WebResearchAgent`, using `run_tool_loop` and a Pydantic result model. Register the role in `experiments/pkg_risk.py` `ROLES` and in `configs/models.yaml`.
- **Tool.** Add a spec in `tools/builtin.py` with an input model, required capabilities, and a side-effect class. Enforce anything sensitive in the handler as well as in the registry.
- **Verifier.** Add a check in `verifiers/engine.py` that reads committed effects. Add a security-suite case with a compliant fixture path and a noncompliant fixture path. Do not make the check depend on an evaluation-agent score.
- **Experiment.** Keep the world id, seed, identities, threat, provider, and model fixed when you claim a comparison. Record the claim level from `experiments/compare.py`.

## Rules that keep the benchmark valid

- Do not query `gt_facts`, `gt_assets`, or `scenario_bindings` from agent tools.
- Do not fall back from a configured provider to another one.
- Do not commit generated results that were typed in by hand. Run the CLI and save its output.
- Label simulated recipient output as a model simulation.

Tests must pass without commercial API keys.
