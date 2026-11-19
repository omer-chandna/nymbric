# Nymbric

Nymbric is a local, open-source platform for testing the security of AI agents that can use personal context: knowledge graphs, memories, documents, calendars, and relationships.

It asks three practical questions:

1. How much more can an agent reconstruct when it is given a private personal knowledge graph, compared with searching a matching public web?
2. Does that extra context cause a defender to treat familiarity as authorization, and which code-enforced controls stop the failure?
3. When an attacker turns that reconstructed context into a personalized lure, how much more often does a target personal AI agent act on it, and which target-side controls stop the failure?

There are two experiments. **PKG-Risk** measures information uplift and whether an assistant *discloses* its owner's data when asked. **Spear-phish** is the inbound counterpart: an orchestrator runs attacker agents that reconstruct a target's context and craft an inert lure, delivers it to a pluggable target agent (a local model, a fixture, or an out-of-process agent such as Hermes or OpenClaw, attached one-shot or in a live closed loop over MCP/JSON-RPC), and measures whether the target *takes the bait*. Both compare the same four information-access conditions on the same fictional world.

Every identity, page, memory, message, lure, link, and attachment is fictional and inert. Results are outcomes of the configured agents on that synthetic world. They are not measurements of human susceptibility, and they are not evidence that a real assistant, inbox, or operating system was compromised.

## What runs without an API key

Mock inference drives the full pipeline: world generation, web search, graph queries, scenario construction, defender tools, deterministic verification, paired statistics, the API, and the dashboard. Ollama is the default provider when you want a real local model. Hosted APIs are optional and are never selected as a fallback.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cd dashboard/frontend && npm install && npm run build && cd ../..
```

Python 3.11+ is required. The dashboard build is optional; the API works without it.

## Mock quickstart

```bash
nymbric init
nymbric models check --provider mock
nymbric run pkg-risk --provider mock --conditions all --trials 4 --personas 24 --seed 42
nymbric findings list
nymbric dashboard
```

Open `http://127.0.0.1:8000`. The pages read the SQLite database under `.nymbric/`.

`familiarity_biased` is the default defender for this command. It is a deterministic policy fixture: it answers the owner, and it discloses the private calendar when the attacker quotes a real private meeting title. Use `--defender model` to run the model-backed assistant instead. With the mock provider, that assistant refuses third-party requests.

## Spear-phish quickstart

```bash
nymbric run spear-phish --provider mock --conditions all --trials 4 --personas 16 --seed 42 --threat all
nymbric findings list
```

This reconstructs each target's context under baseline/web/graph/combined, crafts one inert lure per condition, delivers it to the target agent, and scores whether the target took the bait. With the default `context_sensitive` target, attack success climbs from the baseline to the graph condition because only the graph surfaces the private meeting the lure quotes.

Choose the target with `--target`:

- `context_sensitive` (default) — a fixture whose susceptibility rises with personalization. The exposure contrast.
- `cautious` / `credulous` — a fixture that never / always takes the bait (controls).
- `model` — a model-backed agent. Point the `target` role at a local provider to test an on-device assistant model.
- `external` — an out-of-process agent (Hermes, OpenClaw, any local agent) that reports an action log once. Pass `--external-cmd "<command>"`; the lure arrives as JSON on stdin and the agent prints its action log on stdout. See [docs/extending.md](docs/extending.md).
- `live` (alias `mcp`) — a live, closed-loop agent. Nymbric stands up a localhost tool server bound to the inert environment and launches the client, which reads each tool result and decides its next call. Pass `--live-cmd "<command>"`. A runnable reference client ships in-repo (`python -m nymbric.agents.target.clients.reference_client`, with a deterministic `--policy mock`, a secure `--policy cautious`, and a real local-model `--policy ollama`), and any MCP-capable agent can attach via the stdio bridge. See [docs/extending.md](docs/extending.md).

```bash
# Drive the spear-phish target with the in-repo reference client over the live tools:
nymbric run spear-phish --provider mock --conditions graph --trials 2 \
  --target live --live-cmd "python -m nymbric.agents.target.clients.reference_client --policy mock"
```

Target-side controls rerun under the same world and seed with `--mitigation` (`link_allowlisting`, `attachment_sandboxing`, `egress_filtering`, `require_independent_verification`). Lures are inert: links resolve to a reserved sink and attachments carry an `.inert` suffix. Read [docs/spear-phish-methodology.md](docs/spear-phish-methodology.md) before treating a number as a research claim.

## Local models

Ollama is the intended local provider. This repository's automated tests do **not** execute a local model. See [docs/local-models.md](docs/local-models.md) for an RTX 4060 / WSL2 setup and the exact command. If Ollama is down, `nymbric models check --provider ollama` exits with a diagnostic and does not switch providers.

## Layout

The orchestrator is a deterministic stage machine in `src/nymbric/orchestration` (`orchestrator.py` for PKG-Risk, `spear_phish.py` for the spear-phish experiment; both reuse the research spine in `research_stage.py`). Specialists (web research, graph research, scenario, defender, evaluation, risk, recipient, plus the spear-phish lure and target agents) share one tool loop. Permissions are checked in the tool registry. Verifier-only labels live in separate tables (`scenario_bindings`, `lure_bindings`) and are not part of defender or target tasks.

Read [ARCHITECTURE.md](ARCHITECTURE.md), [THREAT_MODEL.md](THREAT_MODEL.md), and [docs/methodology.md](docs/methodology.md) before treating a number as a research claim.

## Tests

```bash
pytest
cd dashboard/frontend && npm run build
```

Core tests use the mock provider only.

## License

Apache-2.0. See [LICENSE](LICENSE).
