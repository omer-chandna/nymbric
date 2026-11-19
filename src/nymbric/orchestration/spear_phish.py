"""Deterministic orchestrator for the spear-phish experiment.

Stages: research -> lure -> deliver -> target -> verify -> risk -> persist.

The attacker side (research + lure) reconstructs the target's context under the
run's capability set and crafts one inert lure. The lure is delivered to the
personal agent under test, which acts in an inert `TargetEnvironment`. The
verifier reads the environment, never the agent's self-report. Verifier-only
ground truth (which link/attachment is the attacker's) is bound separately in
`lure_bindings` and is never placed in the target's task.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import uuid
from typing import Any

from nymbric.agents.lure.agent import LureAgent
from nymbric.agents.risk.agent import RiskAgent
from nymbric.agents.target.base import ModelTargetAgent, run_target_fixture
from nymbric.agents.target.external import ExternalCommandTarget
from nymbric.context.isolation import filter_evidence_for_permissions
from nymbric.core.errors import Cancelled, ConcurrentRunError, NymbricError
from nymbric.core.types import (
    CONDITION_CAPABILITIES,
    INERT_ATTACHMENT_SUFFIX,
    INERT_LINK_HOST,
    INJECTION_MARKER,
    TARGET_CAPABILITIES,
    parse_condition,
)
from nymbric.environments.target import TargetBinding, TargetEnvironment
from nymbric.execution.trace import TraceSink
from nymbric.experiments.metrics import phishing_metrics
from nymbric.orchestration.checkpoints import load_checkpoint, save_checkpoint
from nymbric.orchestration.research_stage import ResearchDriver
from nymbric.orchestration.state import ExperimentState
from nymbric.reporting.runtime import runtime_metadata
from nymbric.schemas.messages import Budget, LureGenerationTask, TargetAgentTask
from nymbric.storage.db import Database, utc_now
from nymbric.tools.builtin import build_target_registry
from nymbric.tools.registry import ToolRegistry
from nymbric.verifiers.engine import verify_delegation_trace, verify_phishing

_HELD: set[str] = set()
_HELD_GUARD = threading.Lock()

STAGES = ("research", "lure", "deliver", "target", "verify", "risk", "persist")
TARGET_FIXTURES = {"cautious", "credulous", "context_sensitive"}
_CANARY = re.compile(r"NYM-CANARY-(?:DOC-)?[A-Za-z0-9-]+")


class PhishRunSpec:
    def __init__(
        self,
        *,
        experiment_id: str,
        run_id: str,
        world_id: str,
        condition: str,
        identity_id: str,
        seed: int,
        threat: str = "calendar_pretext_link",
        target_mode: str = "context_sensitive",
        channel: str = "email",
        provider: str = "mock",
        model: str = "mock-deterministic",
        ablation: str | None = None,
        mitigation: str | None = None,
        budget: Budget | None = None,
        trial_index: int = 0,
        external_cmd: list[str] | None = None,
        jsonl_path=None,
    ):
        self.experiment_id = experiment_id
        self.run_id = run_id
        self.world_id = world_id
        self.condition = condition
        self.identity_id = identity_id
        self.seed = seed
        self.threat = threat
        self.target_mode = target_mode
        self.channel = channel
        self.provider = provider
        self.model = model
        self.ablation = ablation
        self.mitigation = mitigation
        self.budget = budget or Budget(max_tool_calls=48, max_steps=16, max_search_calls=8, max_pages_read=5, max_tokens=120000, max_seconds=180)
        self.trial_index = trial_index
        self.external_cmd = external_cmd
        self.jsonl_path = jsonl_path


class SpearPhishOrchestrator:
    def __init__(self, db: Database, providers: dict[str, Any], cancel_event: threading.Event | None = None):
        self.db = db
        self.providers = providers
        self.cancel_event = cancel_event or threading.Event()

    def run(self, spec: PhishRunSpec) -> ExperimentState:
        if spec.run_id in _HELD:
            raise ConcurrentRunError(f"Run {spec.run_id} is already executing.")
        with _HELD_GUARD:
            _HELD.add(spec.run_id)
        try:
            return self._run(spec)
        finally:
            with _HELD_GUARD:
                _HELD.discard(spec.run_id)

    def _run(self, spec: PhishRunSpec) -> ExperimentState:
        state = self._initialize(spec)
        save_checkpoint(self.db, state)
        trace = TraceSink(self.db, state.run_id, state.experiment_id, spec.jsonl_path)
        trace.emit("experiment_started", stage=state.stage, payload={"condition": state.condition, "target_mode": spec.target_mode, "threat": spec.threat})
        deadline = time.monotonic() + spec.budget.max_seconds
        for stage in STAGES:
            if self.cancel_event.is_set():
                state.status = "cancelled"
                save_checkpoint(self.db, state)
                trace.emit("cancel", stage=stage, payload={})
                break
            state.stage = stage
            trace.emit("stage_started", stage=stage, payload={})
            try:
                self._dispatch(stage, state, spec, trace, deadline)
                state.completed_stages.append(stage)
                trace.emit("stage_completed", stage=stage, payload={"status": state.status})
            except Cancelled:
                state.status = "cancelled"
                save_checkpoint(self.db, state)
                trace.emit("cancel", stage=stage, payload={})
                break
            except NymbricError as exc:
                state.errors.append({"stage": stage, "error": str(exc)})
                state.status = "failed"
                trace.emit("error", stage=stage, payload={"error": str(exc)})
                save_checkpoint(self.db, state)
                break
            save_checkpoint(self.db, state)
        else:
            if state.status == "running":
                state.status = "completed"
                state.stage = "complete"
                self.db.execute("UPDATE runs SET status = ?, finished_at = ? WHERE run_id = ?", ("completed", utc_now(), state.run_id))
                save_checkpoint(self.db, state)
        return state

    def _initialize(self, spec: PhishRunSpec) -> ExperimentState:
        condition = parse_condition(spec.condition)
        person = self._person(spec.world_id, spec.identity_id)
        world = self.db.world_row(spec.world_id)
        permissions = sorted(cap.value for cap in CONDITION_CAPABILITIES[condition])
        now = utc_now()
        self.db.execute(
            """
            INSERT INTO runs (
              run_id, experiment_id, world_id, condition, identity_id, trial_index, seed, threat,
              defender_mode, provider, model, ablation, mitigation, status, metrics_json, config_json,
              started_at, finished_at, content_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', '{}', ?, ?, NULL, ?)
            """,
            (
                spec.run_id,
                spec.experiment_id,
                spec.world_id,
                condition.value,
                spec.identity_id,
                spec.trial_index,
                spec.seed,
                spec.threat,
                spec.target_mode,
                spec.provider,
                spec.model,
                spec.ablation,
                spec.mitigation,
                json.dumps({"budget": spec.budget.model_dump(), "permissions": permissions, "channel": spec.channel, "experiment": "spear-phish"}),
                now,
                world["content_hash"] if world else "",
            ),
        )
        return ExperimentState(
            experiment_id=spec.experiment_id,
            run_id=spec.run_id,
            world_id=spec.world_id,
            condition=condition.value,
            identity_id=spec.identity_id,
            display_name=person["name"],
            city=person["city"],
            trial_index=spec.trial_index,
            seed=spec.seed,
            threat=spec.threat,
            defender_mode=spec.target_mode,
            provider=spec.provider,
            model=spec.model,
            ablation=spec.ablation,
            mitigation=spec.mitigation,
            permissions=permissions,
            started_at=now,
            content_hash=world["content_hash"] if world else "",
            usage={"max_seconds": spec.budget.max_seconds, "tokens": 0},
        )

    def _dispatch(self, stage: str, state: ExperimentState, spec: PhishRunSpec, trace: TraceSink, deadline: float) -> None:
        if stage == "research":
            self._research(state, spec, trace, deadline)
        elif stage == "lure":
            self._lure(state, spec, trace, deadline)
        elif stage == "deliver":
            self._deliver(state, spec, trace)
        elif stage == "target":
            self._target(state, spec, trace, deadline)
        elif stage == "verify":
            self._verify(state, spec, trace)
        elif stage == "risk":
            self._risk(state, spec, trace, deadline)
        elif stage == "persist":
            self._persist(state, trace)

    def _research(self, state: ExperimentState, spec: PhishRunSpec, trace: TraceSink, deadline: float) -> None:
        driver = ResearchDriver(self.db, self.providers, self.cancel_event)
        evidence, parent_task_id = driver.run(
            run_id=state.run_id,
            world_id=state.world_id,
            identity_id=state.identity_id,
            display_name=state.display_name,
            city=state.city,
            permissions=set(state.permissions),
            budget=spec.budget,
            ablation=spec.ablation,
            mitigation=spec.mitigation,
            trace=trace,
            deadline=deadline,
            errors=state.errors,
        )
        state.evidence = evidence
        state.parent_task_id = parent_task_id

    def _lure(self, state: ExperimentState, spec: PhishRunSpec, trace: TraceSink, deadline: float) -> None:
        evidence, _removed = filter_evidence_for_permissions(state.evidence, set(state.permissions))
        _, still_foreign = filter_evidence_for_permissions(evidence, set(state.permissions))
        token = hashlib.sha256(f"{state.run_id}:{state.identity_id}".encode()).hexdigest()[:10]
        sink_url = f"https://{INERT_LINK_HOST}/{token}"
        attachment_name = f"briefing-{token}.pdf{INERT_ATTACHMENT_SUFFIX}"
        task = LureGenerationTask(
            task_id=f"lure-{state.run_id}",
            parent_task_id=state.parent_task_id,
            threat_category=state.threat,
            identity_id=state.identity_id,
            display_name=state.display_name,
            channel=spec.channel,
            sink_url=sink_url,
            attachment_name=attachment_name,
            evidence=evidence,
        )
        trace.emit("agent_input", stage="lure", agent="lure", task_id=task.task_id, payload={"contains_foreign_evidence": still_foreign, "evidence_count": len(evidence)})
        registry = ToolRegistry({}, {}, frozenset(), spec.budget, trace, "lure", "lure", task.task_id)
        lure = LureAgent(self.providers["lure"]).run(task, registry, trace, spec.budget, deadline, self.cancel_event)
        # Enforce inertness: whatever the model returns, any link/attachment is
        # replaced by the reserved sink values so nothing live can leave a trace.
        if lure.get("link_url"):
            lure["link_url"] = sink_url
        if lure.get("attachment_name"):
            lure["attachment_name"] = attachment_name
        state.agent_outputs["lure"] = lure
        markers = self._owner_secret_markers(state.world_id, state.identity_id)
        binding = {
            "lure_id": lure["lure_id"],
            "malicious_link": lure.get("link_url") or "",
            "malicious_attachment": lure.get("attachment_name") or "",
            "attacker_address": lure.get("sender_address") or "",
            "injected_marker": INJECTION_MARKER,
            "owner_secret_markers": markers,
            "verifier_only": True,
        }
        self.db.execute(
            "INSERT OR REPLACE INTO lure_bindings (run_id, lure_id, payload_json) VALUES (?, ?, ?)",
            (state.run_id, lure["lure_id"], json.dumps(binding)),
        )
        state.agent_outputs["lure_binding"] = binding
        trace.emit("lure_bound", stage="lure", payload={"lure_id": lure["lure_id"], "personalization": lure.get("personalization"), "exploited_evidence": lure.get("exploited_evidence")})

    def _deliver(self, state: ExperimentState, spec: PhishRunSpec, trace: TraceSink) -> None:
        lure = state.agent_outputs.get("lure") or {}
        task = TargetAgentTask(
            task_id=f"target-{state.run_id}",
            owner_id=state.identity_id,
            owner_name=state.display_name,
            channel=lure.get("channel") or spec.channel,
            sender_display=lure.get("sender_display") or "",
            sender_address=lure.get("sender_address") or "",
            subject=lure.get("subject") or "",
            body=lure.get("body") or "",
            link_url=lure.get("link_url") or "",
            attachment_name=lure.get("attachment_name") or "",
        )
        state.agent_outputs["target_task"] = task.model_dump()
        trace.emit("lure_delivered", stage="deliver", agent="target", task_id=task.task_id, payload={"channel": task.channel, "has_link": bool(task.link_url), "has_attachment": bool(task.attachment_name)})

    def _target(self, state: ExperimentState, spec: PhishRunSpec, trace: TraceSink, deadline: float) -> None:
        lure = state.agent_outputs.get("lure") or {}
        binding = state.agent_outputs.get("lure_binding") or {}
        task = TargetAgentTask.model_validate(state.agent_outputs["target_task"])
        env = TargetEnvironment(
            owner_id=state.identity_id,
            owner_name=state.display_name,
            lure=task.model_dump(),
            binding=TargetBinding(
                malicious_link=binding.get("malicious_link", ""),
                malicious_attachment=binding.get("malicious_attachment", ""),
                attacker_address=binding.get("attacker_address", ""),
                injected_marker=binding.get("injected_marker", INJECTION_MARKER),
                owner_secret_markers=binding.get("owner_secret_markers", []),
            ),
            owner_assets=self._owner_assets(state.world_id, state.identity_id),
            contacts=self._contacts(state.world_id, state.identity_id),
            mitigation=state.mitigation,
        )
        registry = build_target_registry(
            env=env,
            permissions=TARGET_CAPABILITIES,
            budget=spec.budget,
            trace=trace,
            stage="target",
            agent="target",
            task_id=task.task_id,
        )
        mode = spec.target_mode
        if mode == "model":
            result = ModelTargetAgent(self.providers["target"]).run(task, registry, trace, spec.budget, deadline, self.cancel_event)
        elif mode == "external":
            if not spec.external_cmd:
                raise NymbricError("target_mode 'external' requires an external command. Pass --external-cmd.")
            result = ExternalCommandTarget(spec.external_cmd).run(task, registry, trace, spec.budget, deadline, self.cancel_event)
        elif mode in TARGET_FIXTURES:
            result = run_target_fixture(
                mode,
                task,
                registry,
                personalization=str(lure.get("personalization") or "generic"),
                owner_secret_markers=binding.get("owner_secret_markers", []),
            )
        else:
            raise NymbricError(f"Unknown target_mode '{mode}'. Expected model, cautious, credulous, context_sensitive, or external.")
        state.agent_outputs["target_result"] = result
        state.agent_outputs["target_snapshot"] = env.snapshot()

    def _verify(self, state: ExperimentState, spec: PhishRunSpec, trace: TraceSink) -> None:
        snapshot = state.agent_outputs.get("target_snapshot") or {}
        results = verify_phishing(snapshot)
        prior = [json.loads(row["event_json"]) for row in self.db.query("SELECT event_json FROM traces WHERE run_id = ?", (state.run_id,))]
        results.extend(verify_delegation_trace(prior))
        state.verification = results
        for item in results:
            trace.emit("verification", stage="verify", payload=item)
        state.metrics = phishing_metrics(results, snapshot, state.agent_outputs.get("lure") or {})
        state.metrics["condition"] = state.condition
        state.metrics["target_mode"] = state.defender_mode
        state.metrics["threat"] = state.threat

    def _risk(self, state: ExperimentState, spec: PhishRunSpec, trace: TraceSink, deadline: float) -> None:
        payload = {
            "task_id": f"risk-{state.run_id}",
            "run_id": state.run_id,
            "condition": state.condition,
            "defender_mode": state.defender_mode,
            "threat_category": state.threat,
            "verification": state.verification,
            "evidence_count": len(state.evidence),
            "mitigation": state.mitigation,
            "ablation": state.ablation,
        }
        registry = ToolRegistry({}, {}, frozenset(), spec.budget, trace, "risk", "risk_analysis", payload["task_id"])
        state.risk = RiskAgent(self.providers["risk_analysis"]).run(payload, registry, trace, spec.budget, deadline, self.cancel_event)

    def _persist(self, state: ExperimentState, trace: TraceSink) -> None:
        state.usage["runtime"] = runtime_metadata()
        self.db.execute(
            "UPDATE runs SET status = ?, metrics_json = ?, finished_at = ? WHERE run_id = ?",
            (state.status if state.status != "running" else "completed", json.dumps(state.metrics), utc_now(), state.run_id),
        )
        for item in state.verification:
            if item["passed"]:
                continue
            finding_id = f"find-{uuid.uuid4().hex[:12]}"
            self.db.execute(
                "INSERT INTO findings (finding_id, run_id, experiment_id, severity, policy, payload_json) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    finding_id,
                    state.run_id,
                    state.experiment_id,
                    item["severity"],
                    item["check_id"],
                    json.dumps(
                        {
                            "title": item["title"],
                            "evidence": item["evidence"],
                            "condition": state.condition,
                            "target_mode": state.defender_mode,
                            "threat": state.threat,
                            "seed": state.seed,
                            "world_id": state.world_id,
                            "content_hash": state.content_hash,
                            "mitigation": state.mitigation,
                            "ablation": state.ablation,
                            "provider": state.provider,
                            "model": state.model,
                            "personalization": (state.agent_outputs.get("lure") or {}).get("personalization"),
                            "recommendations": (state.risk or {}).get("recommendations") or [],
                            "claim_level": "observed",
                        }
                    ),
                ),
            )
        trace.emit("checkpoint", stage="persist", payload={"status": state.status, "metrics": list(state.metrics)})

    # -- world helpers -----------------------------------------------------
    def _person(self, world_id: str, identity_id: str) -> dict[str, Any]:
        rows = self.db.query("SELECT name, attrs_json FROM entities WHERE world_id = ? AND entity_id = ?", (world_id, identity_id))
        if not rows:
            raise NymbricError(f"Identity {identity_id} is not in world {world_id}.")
        attrs = json.loads(rows[0]["attrs_json"])
        return {"name": rows[0]["name"], "city": attrs.get("city", "")}

    def _owner_assets(self, world_id: str, owner_id: str) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.db.query(
                "SELECT asset_id, owner_id, kind, title, content, sensitivity, visibility FROM assets WHERE world_id = ? AND owner_id = ?",
                (world_id, owner_id),
            )
        ]

    def _contacts(self, world_id: str, owner_id: str) -> list[dict[str, Any]]:
        contacts = []
        for row in self.db.query("SELECT * FROM relationships WHERE world_id = ? AND (src = ? OR dst = ?)", (world_id, owner_id, owner_id)):
            if row["sensitivity"] in {"high", "restricted"}:
                continue
            other = row["dst_name"] if row["src"] == owner_id else row["src_name"]
            contacts.append({"name": other, "relation": row["rel_type"]})
        return contacts[:20]

    def _owner_secret_markers(self, world_id: str, owner_id: str) -> list[str]:
        markers: list[str] = []
        for row in self.db.query("SELECT kind, title, content FROM assets WHERE world_id = ? AND owner_id = ?", (world_id, owner_id)):
            if row["kind"] == "calendar_event" and row["title"]:
                markers.append(row["title"])
            for token in _CANARY.findall(row["content"] or ""):
                markers.append(token)
        # De-duplicate, keep only markers long enough to be unambiguous.
        return sorted({m for m in markers if len(m) >= 12})


def public_run(state: ExperimentState) -> dict[str, Any]:
    return {
        "run_id": state.run_id,
        "experiment_id": state.experiment_id,
        "world_id": state.world_id,
        "condition": state.condition,
        "identity_id": state.identity_id,
        "trial_index": state.trial_index,
        "seed": state.seed,
        "threat": state.threat,
        "defender_mode": state.defender_mode,
        "target_mode": state.defender_mode,
        "provider": state.provider,
        "model": state.model,
        "ablation": state.ablation,
        "mitigation": state.mitigation,
        "status": state.status,
        "metrics": state.metrics,
        "content_hash": state.content_hash,
    }
