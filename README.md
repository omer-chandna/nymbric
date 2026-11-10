# Nymbric

Nymbric is a local, open-source platform for testing the security of AI agents that can use personal context: knowledge graphs, memories, documents, calendars, and relationships.

It asks two practical questions:

1. How much more can an agent reconstruct when it is given a private personal knowledge graph, compared with searching a matching public web?
2. Does that extra context cause a defender to treat familiarity as authorization, and which code-enforced controls stop the failure?

The flagship experiment is **PKG-Risk**. Every identity, page, memory, and message in that experiment is fictional. Results are outcomes of the configured agents on that synthetic world. They are not measurements of human susceptibility, and they are not evidence that a real assistant or operating system was compromised.

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

## Local models

Ollama is the intended local provider. This repository's automated tests do **not** execute a local model. See [docs/local-models.md](docs/local-models.md) for an RTX 4060 / WSL2 setup and the exact command. If Ollama is down, `nymbric models check --provider ollama` exits with a diagnostic and does not switch providers.

## Layout

The orchestrator is a deterministic stage machine in `src/nymbric/orchestration`. Specialists (web research, graph research, scenario, defender, evaluation, risk, recipient) share one tool loop. Permissions are checked in the tool registry. Verifier-only labels live in separate tables and are not part of defender tasks.

Read [ARCHITECTURE.md](ARCHITECTURE.md), [THREAT_MODEL.md](THREAT_MODEL.md), and [docs/methodology.md](docs/methodology.md) before treating a number as a research claim.

## Tests

```bash
pytest
cd dashboard/frontend && npm run build
```

Core tests use the mock provider only.

## License

Apache-2.0. See [LICENSE](LICENSE).
