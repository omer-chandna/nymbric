"""Pydantic contracts for agent tasks and results.

Verifier-only authorization labels are intentionally absent from the schemas
an agent is allowed to emit. The orchestrator stores those labels separately.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Budget(APIModel):
    max_search_calls: int = 6
    max_pages_read: int = 4
    max_steps: int = 12
    max_tool_calls: int = 18
    max_tokens: int = 80000
    max_seconds: float = 120
    tokens_used: int = 0
    tool_calls_used: int = 0
    search_calls_used: int = 0
    pages_read: int = 0

    def snapshot(self) -> dict[str, Any]:
        return self.model_dump()


class TokenUsage(APIModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ResearchTask(APIModel):
    task_id: str
    parent_task_id: str | None = None
    identity_id: str
    display_name: str
    city: str
    directory_id: str
    objectives: list[str]
    depth: int = 1


class GraphQueryTask(ResearchTask):
    max_depth: int = 2


class EvidenceItem(APIModel):
    evidence_id: str
    subject_id: str
    predicate: str
    object: str
    confidence: float = Field(ge=0, le=1)
    source_ref: str
    source_kind: str
    provenance: str
    excerpt: str
    sensitivity: str = "public"
    asserted: bool = True
    kind: str = "fact"
    inference_status: str = "observed"


class ResearchEvidence(APIModel):
    task_id: str
    agent: str
    items: list[EvidenceItem]
    queries: list[str] = Field(default_factory=list)
    pages_read: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)


class ScenarioGenerationTask(APIModel):
    task_id: str
    parent_task_id: str | None = None
    threat_category: str
    identity_id: str
    display_name: str
    requested_action: str
    evidence: list[EvidenceItem]


class ScenarioResult(APIModel):
    scenario_id: str
    threat_category: str
    identity_id: str
    available_information: list[str]
    evidence_dependencies: list[str]
    relevant_relationships: list[str]
    requester_label: str
    requester_role: str
    requested_action: str
    claimed_authority: str
    message: str
    difficulty: str
    unsupported_assumptions: list[str]
    fictional: bool = True
    inert: bool = True


class LureGenerationTask(APIModel):
    """Attacker-side request to craft one inert spear-phishing lure.

    The lure agent sees only permitted evidence. Verifier-only ground truth
    (which link/attachment is the attacker's) is bound separately and never
    appears here or in the target's task.
    """

    task_id: str
    parent_task_id: str | None = None
    threat_category: str
    identity_id: str
    display_name: str
    channel: str
    sink_url: str
    attachment_name: str
    evidence: list[EvidenceItem]


class PhishingArtifact(APIModel):
    """One inert, fictional lure. Not deployable content.

    `exploited_evidence` records which reconstructed facts the lure leans on, so
    uplift can be attributed to breach-derived personalization rather than style.
    """

    lure_id: str
    threat_category: str
    identity_id: str
    channel: str
    sender_display: str
    sender_address: str
    subject: str
    body: str
    call_to_action: str
    link_url: str = ""
    attachment_name: str = ""
    exploited_evidence: list[str] = Field(default_factory=list)
    personalization: str = "generic"  # generic | contextual | high
    pretext: str = ""
    fictional: bool = True
    inert: bool = True


class TargetAgentTask(APIModel):
    """One inbound lure delivered to the personal agent under test.

    The target is told who it serves and is handed the message exactly as it
    would arrive in an inbox. It is not told whether the message is an attack.
    """

    task_id: str
    owner_id: str
    owner_name: str
    channel: str
    sender_display: str
    sender_address: str
    subject: str
    body: str
    link_url: str = ""
    attachment_name: str = ""


class TargetActionRecord(APIModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    sequence: int
    compromising: bool = False


class TargetAgentResult(APIModel):
    task_id: str
    decision: str  # ignored | reported | refused | engaged | complied
    followed_link: bool = False
    opened_attachment: bool = False
    forwarded_data: bool = False
    executed_instruction: bool = False
    rationale: str = ""
    label: str = "agent_under_test_not_human_susceptibility"


class DefenderTask(APIModel):
    task_id: str
    parent_task_id: str | None = None
    turn: str
    identity_id: str
    requester_id: str
    requester_label: str
    requester_role: str
    requested_action: str
    claimed_authority: str
    message: str
    legitimate: bool = False


class DefenderResult(APIModel):
    task_id: str
    decision: str
    notes: str = ""


class AgentAction(APIModel):
    action_id: str
    run_id: str
    task_id: str
    agent: str
    tool: str
    arguments: dict[str, Any]
    output: dict[str, Any]
    allowed: bool
    side_effect: str
    sequence: int


class VerificationResult(APIModel):
    check_id: str
    title: str
    passed: bool
    severity: str
    evidence: list[str]
    authoritative: bool = True


class RiskAnalysisTask(APIModel):
    task_id: str
    run_id: str
    condition: str
    defender_mode: str
    threat_category: str
    verification: list[VerificationResult]
    evidence_count: int
    mitigation: str | None = None
    ablation: str | None = None


class MitigationRecommendation(APIModel):
    mitigation_id: str
    policy: str
    rationale: str
    addresses_check: str


class RiskFinding(APIModel):
    policy: str
    check_id: str
    severity: str
    summary: str
    sources: list[str]
    claim_level: str = "observed"


class RiskAnalysisResult(APIModel):
    summary: str
    findings: list[RiskFinding]
    recommendations: list[MitigationRecommendation]
    claim_level: str
    limitations: str


class EvaluationResult(APIModel):
    research_accuracy: int = Field(ge=0, le=5)
    evidence_grounding: int = Field(ge=0, le=5)
    contextual_relevance: int = Field(ge=0, le=5)
    scenario_plausibility: int = Field(ge=0, le=5)
    uncertainty_handling: int = Field(ge=0, le=5)
    defensive_response_quality: int = Field(ge=0, le=5)
    notes: str
    authority: str = "non_authoritative"


class RecipientSimulation(APIModel):
    simulation_only: bool = True
    disclaimer: str
    perceived_credibility: float = Field(ge=0, le=1)
    noticed_inconsistency: bool
    simulated_unsafe_response: bool
    label: str = "model_simulation_not_human_susceptibility"


# --- Campaign experiment ---------------------------------------------------
# A goal-directed, multi-stage red-team emulator. Every stage ("initial access",
# "PKG extraction", "lateral movement") is MODELLED over the synthetic persona
# graph and is fully inert. No real device, inbox, account, or person is touched.


class CampaignGoal(APIModel):
    """What the emulated offensive agent is trying to achieve.

    - ``compromise_persona``: earn a foothold on ``target_persona``.
    - ``exfiltrate_asset``: compromise the owner of ``target_asset`` (e.g. a
      ``restricted`` compensation memo) so the asset is pulled with their PKG.
    - ``compromise_count``: compromise at least ``count`` personas.
    """

    kind: str  # compromise_persona | exfiltrate_asset | compromise_count
    target_persona: str = ""
    target_asset: str = ""
    count: int = 0
    description: str = ""


class CampaignSpec(APIModel):
    """One campaign run: one entry persona, one goal, one information regime."""

    experiment_id: str
    world_id: str
    seed: int
    entry_id: str
    goal: CampaignGoal
    regime: str  # osint | enhanced
    max_depth: int = 3
    max_nodes: int = 12
    target_mode: str = "context_sensitive"
    mitigation: str | None = None
    provider: str = "mock"
    model: str = "mock-deterministic"
    threat: str = "calendar_pretext_link"
    channel: str = "email"


class CampaignNodeResult(APIModel):
    """One attempted foothold on one persona, scored by the authoritative verifier."""

    persona_id: str
    name: str
    depth: int
    parent_id: str = ""
    condition: str  # baseline | web | graph | combined (the attacker's info access)
    breach_enhanced: bool = False
    attack_success: bool = False
    personalization: str = "generic"
    personalization_grounded: int = 0
    foothold: bool = False
    control_held: str = ""  # which defence stopped it; empty when the node fell
    run_id: str = ""
    pkg: dict[str, Any] | None = None  # extracted PKG summary, None if not compromised


class AttackGraphEdge(APIModel):
    """A pivot the emulator attempted from a compromised node to an adjacent persona."""

    src_id: str
    dst_id: str
    rel_type: str
    rel_id: str = ""
    pivot_context: dict[str, Any] = Field(default_factory=dict)
    led_to_compromise: bool = False


class CampaignResult(APIModel):
    campaign_id: str
    experiment_id: str
    world_id: str
    seed: int
    regime: str
    entry_id: str
    entry_name: str
    goal: CampaignGoal
    target_mode: str
    mitigation: str | None = None
    max_depth: int
    max_nodes: int
    provider: str
    model: str
    threat: str
    channel: str
    nodes: list[CampaignNodeResult] = Field(default_factory=list)
    edges: list[AttackGraphEdge] = Field(default_factory=list)
    objective_reached: bool = False
    objective_reached_at_depth: int | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)
    content_hash: str = ""
    label: str = (
        "Synthetic, inert multi-stage attack emulation over a fictional persona graph. "
        "Initial access, PKG extraction, and lateral movement are modelled, not performed."
    )
