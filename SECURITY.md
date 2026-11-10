# Security policy

Nymbric is a local research tool. Report vulnerabilities in the platform itself (credential leakage, verifier-label exposure, permission bypass in the registry or delegation manager) by opening a private security advisory on the repository, or by contacting the maintainers listed in the project. Do not file public issues that include a working bypass.

## Supported use

- Fictional identities, synthetic graphs, and synthetic pages.
- Mock or local models, or a hosted model you have explicitly configured.
- Deterministic checks of tool traces.

## Not accepted as features

- Extraction of private operating-system databases.
- Permission bypasses against a host OS.
- Automated profiling of real people.
- Delivery of phishing, credential collection, or any message that leaves the simulator.

The simulator's "send" tool records an inert row. It has no network side effect.

## Secrets

API keys are environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_COMPATIBLE_API_KEY`). Do not commit them. Traces run through a redactor; do not rely on the redactor as the only control. Prefer the mock or Ollama provider when you are unsure what a prompt contains.
