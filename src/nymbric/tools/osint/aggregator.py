"""Evidence aggregator for OSINT data.

This module provides utilities for merging and deduplicating
evidence collected from multiple OSINT sources.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from nymbric.schemas.messages import EvidenceItem

logger = logging.getLogger(__name__)


@dataclass
class AggregatedEvidence:
    """Aggregated evidence from multiple OSINT sources."""

    target_name: str
    target_email: str | None = None
    target_phone: str | None = None
    target_location: str | None = None
    target_employer: str | None = None
    target_socials: dict[str, str] = field(default_factory=dict)
    target_links: list[str] = field(default_factory=list)
    target_documents: list[dict[str, Any]] = field(default_factory=list)
    target_breached_files: list[dict[str, Any]] = field(default_factory=list)
    raw_evidence: list[dict[str, Any]] = field(default_factory=list)
    collection_time: datetime = field(default_factory=datetime.now)
    sources: list[str] = field(default_factory=list)

    def to_evidence_items(self) -> list[EvidenceItem]:
        """Convert aggregated evidence to EvidenceItem objects."""
        items: list[EvidenceItem] = []

        if self.target_name:
            items.append(
                EvidenceItem(
                    evidence_id=f"agg-name-{self.target_name.lower().replace(' ', '-')}",
                    subject_id="osint-target",
                    predicate="has_name",
                    object=self.target_name,
                    confidence=1.0,
                    source_ref="aggregator",
                    source_kind="aggregation",
                    provenance="osint_aggregation",
                    excerpt=self.target_name,
                    sensitivity="public",
                    asserted=True,
                    kind="fact",
                    inference_status="observed",
                )
            )

        if self.target_email:
            items.append(
                EvidenceItem(
                    evidence_id=f"agg-email-{self.target_email.replace('.', '-').replace('@', '-').replace(' ', '-')}",
                    subject_id="osint-target",
                    predicate="has_email",
                    object=self.target_email,
                    confidence=0.9,
                    source_ref="aggregator",
                    source_kind="aggregation",
                    provenance="osint_aggregation",
                    excerpt=self.target_email,
                    sensitivity="public",
                    asserted=True,
                    kind="fact",
                    inference_status="observed",
                )
            )

        if self.target_phone:
            items.append(
                EvidenceItem(
                    evidence_id=f"agg-phone-{self.target_phone.replace('.', '-').replace(' ', '-')}",
                    subject_id="osint-target",
                    predicate="has_phone",
                    object=self.target_phone,
                    confidence=0.8,
                    source_ref="aggregator",
                    source_kind="aggregation",
                    provenance="osint_aggregation",
                    excerpt=self.target_phone,
                    sensitivity="public",
                    asserted=True,
                    kind="fact",
                    inference_status="observed",
                )
            )

        if self.target_location:
            items.append(
                EvidenceItem(
                    evidence_id=f"agg-location-{self.target_location.lower().replace(' ', '-')}",
                    subject_id="osint-target",
                    predicate="lives_in",
                    object=self.target_location,
                    confidence=0.85,
                    source_ref="aggregator",
                    source_kind="aggregation",
                    provenance="osint_aggregation",
                    excerpt=self.target_location,
                    sensitivity="public",
                    asserted=True,
                    kind="fact",
                    inference_status="observed",
                )
            )

        if self.target_employer:
            items.append(
                EvidenceItem(
                    evidence_id=f"agg-employer-{self.target_employer.lower().replace(' ', '-')}",
                    subject_id="osint-target",
                    predicate="works_at",
                    object=self.target_employer,
                    confidence=0.9,
                    source_ref="aggregator",
                    source_kind="aggregation",
                    provenance="osint_aggregation",
                    excerpt=self.target_employer,
                    sensitivity="public",
                    asserted=True,
                    kind="fact",
                    inference_status="observed",
                )
            )

        for social, url in self.target_socials.items():
            items.append(
                EvidenceItem(
                    evidence_id=f"agg-social-{social.lower()}-{url.replace('.', '-').replace('/', '-').replace(' ', '-')}",
                    subject_id="osint-target",
                    predicate="has_social",
                    object=social,
                    confidence=0.95,
                    source_ref="aggregator",
                    source_kind="aggregation",
                    provenance="osint_aggregation",
                    excerpt=f"{social}: {url}",
                    sensitivity="public",
                    asserted=True,
                    kind="fact",
                    inference_status="observed",
                )
            )

        for link in self.target_links:
            items.append(
                EvidenceItem(
                    evidence_id=f"agg-link-{link.replace('.', '-').replace('/', '-').replace(' ', '-')}",
                    subject_id="osint-target",
                    predicate="has_link",
                    object=link,
                    confidence=0.9,
                    source_ref="aggregator",
                    source_kind="aggregation",
                    provenance="osint_aggregation",
                    excerpt=link,
                    sensitivity="public",
                    asserted=True,
                    kind="fact",
                    inference_status="observed",
                )
            )

        for doc in self.target_documents:
            items.append(
                EvidenceItem(
                    evidence_id=f"agg-doc-{doc.get('filename', 'unknown')}",
                    subject_id="osint-target",
                    predicate="has_document",
                    object=doc.get("filename", "unknown"),
                    confidence=doc.get("confidence", 0.9),
                    source_ref="aggregator",
                    source_kind="aggregation",
                    provenance="osint_aggregation",
                    excerpt=json.dumps(doc),
                    sensitivity=doc.get("sensitivity", "public"),
                    asserted=True,
                    kind="document",
                    inference_status="observed",
                )
            )

        for breached in self.target_breached_files:
            items.append(
                EvidenceItem(
                    evidence_id=f"agg-breach-{breached.get('filename', 'unknown')}",
                    subject_id="osint-target",
                    predicate="breached_file",
                    object=breached.get("filename", "unknown"),
                    confidence=breached.get("confidence", 0.95),
                    source_ref="aggregator",
                    source_kind="breach_pkg",
                    provenance="breached_pkg",
                    excerpt=json.dumps(breached),
                    sensitivity=breached.get("sensitivity", "public"),
                    asserted=True,
                    kind="breach",
                    inference_status="observed",
                )
            )

        return items

    def merge(self, other: "AggregatedEvidence") -> None:
        """Merge another AggregatedEvidence into this one, keeping the best data."""
        if other.target_name and not self.target_name:
            self.target_name = other.target_name
        if other.target_email and not self.target_email:
            self.target_email = other.target_email
        if other.target_phone and not self.target_phone:
            self.target_phone = other.target_phone
        if other.target_location and not self.target_location:
            self.target_location = other.target_location
        if other.target_employer and not self.target_employer:
            self.target_employer = other.target_employer

        for social, url in other.target_socials.items():
            if social not in self.target_socials:
                self.target_socials[social] = url

        for link in other.target_links:
            if link not in self.target_links:
                self.target_links.append(link)

        for doc in other.target_documents:
            if doc["filename"] not in [d["filename"] for d in self.target_documents]:
                self.target_documents.append(doc)

        for breached in other.target_breached_files:
            if breached["filename"] not in [b["filename"] for b in self.target_breached_files]:
                self.target_breached_files.append(breached)

        self.sources.extend(other.sources)
        self.raw_evidence.extend(other.raw_evidence)

        # Keep the most recent collection time
        if other.collection_time > self.collection_time:
            self.collection_time = other.collection_time


def merge_evidence_items(items: list[EvidenceItem]) -> AggregatedEvidence:
    """Merge a list of EvidenceItem objects into an AggregatedEvidence.

    Args:
        items: List of EvidenceItem objects to merge.

    Returns:
        An AggregatedEvidence object containing all merged data.
    """
    aggregated = AggregatedEvidence(target_name="")

    for item in items:
        if item.kind == "fact" and item.predicate == "has_name":
            aggregated.target_name = item.object
        elif item.predicate == "has_email":
            aggregated.target_email = item.object
        elif item.predicate == "has_phone":
            aggregated.target_phone = item.object
        elif item.predicate == "lives_in":
            aggregated.target_location = item.object
        elif item.predicate == "works_at":
            aggregated.target_employer = item.object
        elif item.predicate == "has_social":
            aggregated.target_socials[item.object] = item.excerpt
        elif item.predicate == "has_link":
            aggregated.target_links.append(item.object)
        elif item.kind == "document":
            aggregated.target_documents.append({
                "filename": item.object,
                "excerpt": item.excerpt,
                "sensitivity": item.sensitivity,
                "confidence": item.confidence,
            })
        elif item.kind == "breach":
            aggregated.target_breached_files.append({
                "filename": item.object,
                "excerpt": item.excerpt,
                "sensitivity": item.sensitivity,
                "confidence": item.confidence,
            })

    return aggregated
