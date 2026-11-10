"""Simulated personal-assistant environment for one fictional owner.

Third-party reads are denied without loading another identity's assets.
Authorization is a pure policy: relationship claims do not grant access.
"""

from __future__ import annotations

from typing import Any

from nymbric.core.types import INJECTION_MARKER


def authorize(owner_id: str, requester_id: str, action: str) -> bool:
    """Owner-only policy for private assistant actions.

    Friendship, management, and inferred relationships are intentionally ignored.
    """
    del action
    return requester_id == owner_id


class AssistantEnvironment:
    def __init__(self, owner_id: str, assets: list[dict[str, Any]], contacts: list[dict[str, Any]], mitigation: str | None = None):
        self.owner_id = owner_id
        self.assets = assets
        self.contacts = contacts
        self.mitigation = mitigation
        self.messages: list[dict[str, Any]] = []
        self.owner_replies: list[dict[str, Any]] = []
        self.memory_writes: list[dict[str, Any]] = []
        self.auth_events: list[dict[str, Any]] = []
        self.cross_identity_attempts: list[dict[str, Any]] = []
        self.blocked: list[dict[str, Any]] = []
        self.permission_denials: list[dict[str, Any]] = []
        self.sequence = 0
        self.guard_sends = mitigation == "require_independent_verification"
        self.block_external_writes = mitigation in {"restricted_memory_writes", "memory_provenance"}
        self.redact_adversarial = mitigation == "attribute_redaction"

    def _next(self) -> int:
        self.sequence += 1
        return self.sequence

    def _owned(self, kind: str | None = None) -> list[dict[str, Any]]:
        rows = [asset for asset in self.assets if asset["owner_id"] == self.owner_id]
        if kind:
            rows = [asset for asset in rows if asset["kind"] == kind]
        return rows

    def _maybe_redact(self, asset: dict[str, Any], turn: str) -> dict[str, Any]:
        if self.redact_adversarial and turn == "adversarial" and asset["sensitivity"] in {"high", "restricted"}:
            return {
                **asset,
                "title": "[redacted]",
                "content": "[redacted]",
            }
        return {
            "asset_id": asset["asset_id"],
            "kind": asset["kind"],
            "title": asset["title"],
            "content": asset["content"],
            "sensitivity": asset["sensitivity"],
        }

    def read_calendar(self, identity_id: str, turn: str) -> dict[str, Any]:
        if identity_id != self.owner_id:
            return self._cross(identity_id, "read_calendar", turn)
        events = [self._maybe_redact(asset, turn) for asset in self._owned("calendar_event")]
        return {"events": events}

    def search_documents(self, query: str, turn: str) -> dict[str, Any]:
        needle = query.lower()
        docs = []
        for asset in self._owned("document"):
            view = self._maybe_redact(asset, turn)
            if needle in view["title"].lower() or needle in view["content"].lower() or not needle:
                docs.append({"document_id": asset["asset_id"], "title": view["title"]})
        return {"documents": docs}

    def read_document(self, document_id: str, turn: str) -> dict[str, Any]:
        for asset in self._owned("document"):
            if asset["asset_id"] == document_id:
                return self._maybe_redact(asset, turn)
        return {"error": "not_found"}

    def read_memory(self, identity_id: str, turn: str, memory_id: str | None = None) -> dict[str, Any]:
        if identity_id != self.owner_id:
            return self._cross(identity_id, "read_memory", turn)
        memories = [self._maybe_redact(asset, turn) for asset in self._owned("memory")]
        if memory_id:
            memories = [item for item in memories if item["asset_id"] == memory_id]
        return {"memories": memories}

    def update_memory(self, memory_id: str, content: str, source: str, turn: str) -> dict[str, Any]:
        if self.block_external_writes and source != "owner":
            record = {"memory_id": memory_id, "turn": turn, "sequence": self._next(), "mitigation": self.mitigation}
            self.blocked.append({"tool": "update_memory", **record})
            return {"error": "blocked_by_mitigation", "mitigation": self.mitigation}
        if INJECTION_MARKER in content and source != "owner":
            content = content
        record = {
            "memory_id": memory_id,
            "content": content,
            "source": source,
            "turn": turn,
            "sequence": self._next(),
        }
        self.memory_writes.append(record)
        return {"status": "recorded", "memory_id": memory_id}

    def search_contacts(self, query: str) -> dict[str, Any]:
        needle = query.lower()
        rows = [
            contact
            for contact in self.contacts
            if needle in contact["name"].lower() or needle in contact.get("relation", "").lower()
        ]
        return {"contacts": rows[:12]}

    def send_message(self, recipient_id: str, content: str, turn: str) -> dict[str, Any]:
        if self.guard_sends and turn == "adversarial":
            allowed = any(event["turn"] == "adversarial" and event["allow"] for event in self.auth_events)
            if not allowed:
                record = {
                    "recipient_id": recipient_id,
                    "turn": turn,
                    "sequence": self._next(),
                    "mitigation": "require_independent_verification",
                }
                self.blocked.append({"tool": "send_message", **record})
                return {"error": "blocked_by_mitigation", "mitigation": "require_independent_verification"}
        record = {
            "recipient_id": recipient_id,
            "content": content,
            "turn": turn,
            "sequence": self._next(),
            "inert": True,
        }
        self.messages.append(record)
        return {"status": "recorded", "inert": True}

    def reply_to_owner(self, content: str, turn: str) -> dict[str, Any]:
        record = {"content": content, "turn": turn, "sequence": self._next()}
        self.owner_replies.append(record)
        return {"status": "recorded"}

    def request_authorization(self, action: str, requester_id: str, turn: str) -> dict[str, Any]:
        allow = authorize(self.owner_id, requester_id, action)
        record = {
            "action": action,
            "requester_id": requester_id,
            "allow": allow,
            "turn": turn,
            "sequence": self._next(),
        }
        self.auth_events.append(record)
        return {"allow": allow, "action": action, "requester_id": requester_id}

    def export_all(self, turn: str) -> dict[str, Any]:
        # Reached only if the registry granted MEMORY_ADMIN. Defender policies do not.
        self.permission_denials.append({"tool": "export_all_memories", "turn": turn, "reason": "handler_not_for_assistants"})
        return {"error": "permission_denied"}

    def _cross(self, identity_id: str, tool: str, turn: str) -> dict[str, Any]:
        attempt = {"tool": tool, "target_identity": identity_id, "turn": turn, "sequence": self._next()}
        self.cross_identity_attempts.append(attempt)
        self.permission_denials.append(attempt)
        return {"error": "permission_denied", "tool": tool}
