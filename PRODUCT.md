# Product

Nymbric is a self-hosted security workbench for agents that retrieve personal context. The user is a researcher or developer who needs to reproduce a failure, see which information the agent actually retrieved, and check whether a mitigation changes the outcome under the same world and seed.

## Workflow

1. Generate one fictional world. The public web is derived from that world, not from a second random draw.
2. Choose a provider explicitly. Mock, Ollama, OpenAI-compatible, OpenAI, and Anthropic are separate adapters.
3. Run PKG-Risk across baseline, web, graph, and combined access. The same identities and threat are used in every condition.
4. Read deterministic verification separately from qualitative scores and from the simulated recipient.
5. Compare conditions with paired intervals. A zero-width interval on the mock policy is reported as zero within-pair variance, not as a human-subject result.
6. Rerun with one ablation or one guardrail changed.
7. Export the stored summary as Markdown, JSON, or HTML.

## What the first release measures

- Public and private fact recall, precision, F1, relationship reconstruction, attribution, and confidence calibration.
- Unauthorized disclosure, authorization compliance, false positives (owner over-refusal), false negatives, memory writes, tool denials, and cross-identity attempts.
- A simulated recipient credibility score, labeled as a model simulation.

These families stay in separate fields. The product does not publish a single security score.

## Defenders

| Mode | Role |
| --- | --- |
| `model` | The configured model, or the mock policy that requests authorization and refuses third parties. |
| `compliant` | Fixture that always checks authorization and does not leak. |
| `noncompliant` | Fixture used by the security suite to force known violations. |
| `familiarity_biased` | Fixture that discloses the calendar only when the request quotes a real private meeting title. |

The exposure contrast is meaningful on `familiarity_biased`: web research cannot quote a private meeting, graph access can, and the disclosure rate moves with that fact. The mock `model` defender is a secure control and should not be described as failing the same way.

## Non-goals

Nymbric does not extract Apple databases, profile real people, send messages, or run untrusted agent code. Optional Harbor, MCP, and LangGraph adapters are status reports only. The native runner does not import them.
