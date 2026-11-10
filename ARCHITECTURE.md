# Architecture

## Decision: a purpose-built stage machine

PKG-Risk is a fixed sequence of controlled stages: research, scenario, defend, verify, evaluate, risk, persist. Permissions, ground truth, and pass/fail decisions have to be ordinary code. LangGraph (current checkpoint APIs included) can store graph state and resume a thread, but it does not provide Nymbric's capability lattice or the separation between agent-visible state and verifier bindings. Adopting it would add a dependency without removing the security-critical code.

Nymbric therefore uses an explicit stage machine:

- `Orchestrator` advances stages, writes checkpoints, and is the only component that may read verifier tables during a run.
- Specialists are model-backed agents with a shared tool loop, except for the deterministic research split and the defender fixtures.
- The tool registry drops calls whose required capabilities are not in the task's set. Prompts repeat the rule; they do not enforce it.
- Delegation checks that the child capability set is a subset of the parent and that depth stays within the limit.
- Checkpoints store `ExperimentState`. Scenario bindings with `ground_truth_authorization` are a separate table and are not copied into defender tasks.

Harbor is not imported. If Ollama, OpenAI, or Anthropic is unavailable, the provider raises `ProviderUnavailable` and the run stops.

## Agents

| Agent | Job | Tools |
| --- | --- | --- |
| Research coordinator | Deterministic split into web and/or graph subtasks | none |
| Web research | Search and read the synthetic web | `search_web`, `open_page`, `find_on_page` |
| Graph research | Query the permitted projection | `query_entity`, `get_relationships`, `traverse_graph` |
| Scenario | Build one inert fictional scenario from permitted evidence | none |
| Defender | Owner reply plus the adversarial turn | assistant tools, never `memory_admin` |
| Evaluation | Rubric scores, marked non-authoritative | none |
| Risk analysis | Explain verifier failures and name a rerun-able control | none |
| Recipient | Simulated credibility, marked as not human data | none |

Combined access delegates web and graph specialists. Their evidence is merged after both return. A web task cannot receive graph-sourced evidence; `filter_evidence_for_permissions` strips it.

## Data

One SQLite file holds the world, pages (FTS5), runs, checkpoints, traces, findings, and verifier bindings. NetworkX builds the in-memory traversal graph from the rows the current ablation allows. Ground-truth correctness is not a column on `relationships`. It lives in `gt_relationships` and `gt_facts`, which agent tools do not query.

The world generator draws people, employment, friendship, family, projects, public events, private meetings, memories, and documents from one seed, then renders public pages from the public subset. Private titles and canary tokens are checked against the page text before the world is returned.

## Inference

`ModelRouter` builds one adapter per role from `configs/models.yaml`, with `${VAR:-default}` interpolation. `--provider` overrides every role for a controlled comparison. Adapters:

- `mock` — deterministic tool policy over the conversation so far. It does not query the database itself.
- `ollama` — `POST /api/chat` with tools, optional JSON schema `format`, `think: false`, and `num_ctx` default 8192.
- `openai` and `openai_compatible` — chat completions.
- `anthropic` — Messages API.

Malformed structured output raises after a short retry. It is not coerced into a success.

## Verification and statistics

`verifiers/engine.py` inspects committed tool effects: external messages, memory writes, authorization order, denied tools, and cross-identity attempts. Qualitative scores never overwrite those booleans.

`experiments/stats.py` reports bootstrap intervals, exact sign-flip or McNemar p-values for small samples, Bonferroni adjustment inside the declared family, and an L2-penalized logistic fit that warns on separation. Causal wording in `compare.py` is limited to `paired_effect` when the recorded controls match.

## Execution boundary

Agents run in-process. A subprocess is not treated as a sandbox. Untrusted code execution is disabled. Simulation tools do not open network connections. See `environments/sandbox.py`.

## Dashboard

The FastAPI app in `src/nymbric/api` is the only backend. `dashboard/frontend` is a Vite client. `dashboard/backend` is intentionally not a second server.
