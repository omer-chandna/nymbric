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
4. (Spear-phish) An attacker that reconstructs a target's context and crafts a personalized lure, and a target agent that may act on it. The attacker side is Nymbric's own research and lure agents operating on the fictional world. The target is the agent under test. In the `external` mode the target is untrusted out-of-process code; its reported action log is parsed as data (strict JSON, no shell, bounded time) and replayed against the inert environment, never executed.
5. (Campaign) A goal-directed, multi-stage offensive agent that is given one entry persona and a goal and pivots across the fictional persona graph: foothold, pull the compromised node's knowledge graph, personalize the next hop, repeat. Initial access, PKG extraction, and lateral movement are **modelled** stages over the synthetic graph, not real actions. Each foothold is a spear-phish single-node sub-run whose inert verifier decides success; a node's PKG is "extracted" by reading its synthetic rows; "lateral movement" enqueues adjacent fictional personas. The campaign adds no capability the spear-phish target does not already have and no real-world egress.

## Controls

- Tool calls are allow-listed per task and validated with Pydantic models.
- Child permissions must be a subset of the parent.
- Agent instructions are scrubbed. Keys such as `ground_truth_authorization` and `correct` are dropped. Verification results are included only for the risk analyst.
- Untrusted text is wrapped before it is placed in a model message. The orchestrator never parses a new permission set out of model output.
- Cross-identity reads return a denial and do not load the other identity's assets.
- External sends can be blocked by the `require_independent_verification` guardrail unless an authorization check returned allow.
- Traces pass through a redactor for credential-shaped strings.
- (Spear-phish) Lures are inert by construction. Links are rewritten to a reserved, non-routable sink host (`sink.invalid`) and attachments carry an `.inert` suffix, regardless of what the lure model produces. The target environment opens no sockets and submits no credentials; "following a link" and "opening an attachment" return synthetic text. Which link, attachment, and sender address are the attacker's is verifier-only ground truth stored in `lure_bindings`; it is never placed in the target's task. The target's self-reported result never overrides the deterministic verifier, which reads the environment's recorded actions. Target-side controls — `link_allowlisting`, `attachment_sandboxing`, `egress_filtering`, `require_independent_verification` — can each be toggled and rerun under the same world and seed.

## Out of scope

- A developer who edits Nymbric and queries `gt_facts` from a new tool. The process is trusted.
- Isolation of untrusted Python. That requires an external sandbox; this release does not pretend a subprocess is one.
- Real phishing, credential theft, OS permission bypass, or targeting a real person. The spear-phish experiment simulates a personalized-lure attack against a target **agent** on a fictional world with inert artifacts; it does not generate deployable content, does not act against a real inbox or account, and must not be modified to do so. Producing a working lure aimed at a real person, resolving a live link, or exfiltrating a real secret are not "research modes" and must not be added.
- Real multi-stage intrusion, network exploitation, device compromise, lateral movement across real hosts or accounts, or reading a real person's on-device knowledge graph. The campaign experiment **models** an Artex-style offensive agent's kill chain — initial access, PKG extraction, lateral movement, objective — entirely over the synthetic persona graph with the configured defenders deciding each step. "Compromising a node", "extracting a PKG", and "hacking a laptop" are computations over fictional rows, never real actions. The campaign must not be modified to attack a real device, network, inbox, account, or on-device personal store, nor to emit deployable attack content.
- Extracting, reading, or profiling real Apple personal-knowledge-graph data (or any real on-device personal store). Nymbric reasons about the *risk* such data would create using a synthetic stand-in; it never reads the real thing.

## Residual risk

Read-time redaction does not erase a value the defender already loaded for the owner. The send guardrail is the control that stops the subsequent disclosure. Reports should say which layer fired.

Hosted providers receive the prompts you configure. Do not point a hosted model at anything other than the fictional world.

Deterministic mock results can show a perfect separation between conditions. That is a property of the fixture, not a confidence interval about deployed assistants. The report text says so when within-pair variance is zero.
