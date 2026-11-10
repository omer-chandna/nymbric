# Extending Nymbric

## Tool

1. Add a Pydantic input model and a `ToolSpec` in `src/nymbric/tools/builtin.py`.
2. Set `required` to the capabilities the caller must already hold. The registry checks this before the handler runs.
3. Return an error object for illegal arguments. Do not include the data the caller was not allowed to see.
4. Cover the denial in `tests/security` or `tests/unit`.

## Verifier

Add a function in `verifiers/engine.py` that looks at committed messages, writes, and denials. Wire it into `verify_environment` or `verify_delegation_trace`. Then add a suite entry whose compliant fixture passes every check and whose noncompliant fixture fails the new primary check.

## Agent

Subclass the loop in `agents/loop.py`. Pass only the task fields the role needs. Do not give the defender `verifier_binding` or raw `gt_facts`.

## Experiment factor

Change one of `condition`, `ablation`, `mitigation`, `defender_mode`, or the model. Pass the same `world_id` and `seed` into `execute_pkg_risk` for the second arm. `run_counterfactual` does this for mitigation, ablation, and defender mode.
