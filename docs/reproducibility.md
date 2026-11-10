# Reproducibility

A PKG-Risk row stores the experiment id, run id, world id, content hash, seed, provider, model, defender mode, ablation, mitigation, threat, and metrics. Traces are in SQLite and, when the CLI is used, in `.nymbric/traces/*.jsonl` with schema `nymbric.trace.v1`.

Two `generate_world` calls with the same personas, seed, and generator settings return the same content hash. The public web and the private graph are projections of that world.

Mock inference is a pure function of the conversation the tools have produced. Checkpoints let a paused run continue without repeating completed stages.

Ollama and hosted models are not bitwise stable across machines, driver versions, or context truncation. Compare them with the paired statistics, and do not describe a single run as exact. The report states when within-pair variance is zero so a mock result is not mistaken for a sampling distribution over models or people.

Conditions do not share evidence rows. Each run has its own id, checkpoint, and tool registry. The world is shared on purpose.
