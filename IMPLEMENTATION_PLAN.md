# Implementation plan

The repository implements the vertical slice through the developer surface in one tree. Status below is what the code and tests actually do.

| Area | State |
| --- | --- |
| Synthetic world, graph, FTS web, 500 personas | Implemented and tested |
| Stage-machine orchestrator, delegation, checkpoints, traces | Implemented and tested |
| Mock, Ollama, OpenAI, OpenAI-compatible, Anthropic adapters | Adapters implemented. Live Ollama and hosted calls are not part of CI |
| Four PKG-Risk conditions, ablation, mitigation rerun | Implemented and tested on the mock provider |
| Deterministic verifiers and 12 security tests | Implemented. Each test has a passing compliant path and a failing noncompliant path |
| Paired bootstrap, sign-flip / McNemar, Bonferroni, penalized logistic | Implemented |
| CLI, FastAPI, dashboard | Implemented. Dashboard reads the API |
| Harbor / MCP / LangGraph | Status-only adapters. Not required and not executed |

## Not claimed

- No local model has been executed in the environment that produced this tree. Follow `docs/local-models.md` before citing an Ollama result.
- No hosted API was called.
- Example JSON under `examples/` is the mock pipeline's own output, labeled as such.

## Next work, in order

1. Run the same seed across `qwen3:8b` and one smaller tool model, one model at a time, and store the provider metadata.
2. Add a regression that pins a verified mock failure as a permanent test when a real model fails a check the fixture already defines.
3. If untrusted agent programs must run, integrate an external sandbox explicitly. Do not mark a subprocess as the boundary.
4. An authorized importer for a user's own export can be added later. It must map, redact, and record provenance locally. It must not read private OS databases.
