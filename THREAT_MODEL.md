# Threat model

## Assets

- Verifier-only labels: relationship correctness, authorization ground truth, canary inventory.
- Capability sets and experiment configuration.
- Provider credentials, which are read from the environment and redacted in traces.
- The synthetic world and the run database on disk. They are fictional, but the machine owner should still treat the database as experiment data.

## Adversaries considered

1. A model under test, including text in synthetic pages, memories, and the adversarial request. It can choose tool arguments. It cannot register tools, rewrite the stage list, or grant capabilities.
2. A delegated child task that asks for a broader capability set or attaches evidence from another channel.
3. A mistaken configuration that would silently switch from Ollama to a hosted API, or that would send a real personal record to a hosted model. The product refuses the first and is built so the benchmark itself has no real personal records.

## Controls

- Tool calls are allow-listed per task and validated with Pydantic models.
- Child permissions must be a subset of the parent.
- Agent instructions are scrubbed. Keys such as `ground_truth_authorization` and `correct` are dropped. Verification results are included only for the risk analyst.
- Untrusted text is wrapped before it is placed in a model message. The orchestrator never parses a new permission set out of model output.
- Cross-identity reads return a denial and do not load the other identity's assets.
- External sends can be blocked by the `require_independent_verification` guardrail unless an authorization check returned allow.
- Traces pass through a redactor for credential-shaped strings.

## Out of scope

- A developer who edits Nymbric and queries `gt_facts` from a new tool. The process is trusted.
- Isolation of untrusted Python. That requires an external sandbox; this release does not pretend a subprocess is one.
- Real phishing, credential theft, OS permission bypass, or targeting a real person. Those are not features and must not be added as "research modes."

## Residual risk

Read-time redaction does not erase a value the defender already loaded for the owner. The send guardrail is the control that stops the subsequent disclosure. Reports should say which layer fired.

Hosted providers receive the prompts you configure. Do not point a hosted model at anything other than the fictional world.

Deterministic mock results can show a perfect separation between conditions. That is a property of the fixture, not a confidence interval about deployed assistants. The report text says so when within-pair variance is zero.
