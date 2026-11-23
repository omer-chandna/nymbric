"""Lure generator for creating phishing lure artifacts.

This module generates deployable phishing lure artifacts including:
- Email content (subject, body, headers)
- Attachment files (flag files, PDFs, etc.)
- Metadata for tracking and analysis
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .templates import LURE_TEMPLATES

logger = logging.getLogger(__name__)


@dataclass
class LureArtifact:
    """Represents a generated lure artifact."""

    lure_id: str
    template_name: str
    subject: str
    body: str
    sender_name: str
    sender_email: str
    sender_address: str
    cc: list[str]
    attachments: list[str]
    link_url: str
    urgency: str
    personalization: dict[str, str]
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "lure_id": self.lure_id,
            "template_name": self.template_name,
            "subject": self.subject,
            "body": self.body,
            "sender_name": self.sender_name,
            "sender_email": self.sender_email,
            "sender_address": self.sender_address,
            "cc": self.cc,
            "attachments": self.attachments,
            "link_url": self.link_url,
            "urgency": self.urgency,
            "personalization": self.personalization,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }


class LureGenerator:
    """Generates phishing lure artifacts from templates and OSINT data.

    This class handles:
    - Template selection based on target context
    - Personalization using OSINT data
    - Link URL injection (user-controlled)
    - Attachment generation (flag files)
    - Artifact serialization
    """

    def __init__(self, base_url: str = "https://nymbric.local"):
        self.base_url = base_url
        self._templates = LURE_TEMPLATES

    def generate(
        self,
        target_name: str,
        target_email: str | None = None,
        target_employer: str | None = None,
        target_location: str | None = None,
        link_url: str | None = None,
        template_name: str | None = None,
        template_params: dict[str, Any] | None = None,
    ) -> LureArtifact:
        """Generate a lure artifact from a template.

        Args:
            target_name: The target person's name.
            target_email: The target person's email (for CC).
            target_employer: The target's employer (for sender identity).
            target_location: The target's location (for sender address).
            link_url: The user-controlled link URL to inject.
            template_name: The template name to use. Defaults to "job_offer".
            template_params: Additional template parameters.

        Returns:
            A LureArtifact object.
        """
        # Select template
        template_name = template_name or "job_offer"
        template = self._templates.get(template_name)

        if not template:
            raise ValueError(f"Unknown template: {template_name}")

        # Build personalization dict
        personalization = {
            "target_name": target_name,
            "target_email": target_email or "john.doe@example.com",
            "company": target_employer or "Nymbric",
            "company_domain": target_employer.lower().replace(" ", "-") if target_employer else "nymbric",
            "target_location": target_location or "San Francisco, CA",
            "position": "Senior Engineer",
            "skills": "Python, JavaScript, and system design",
            "link_url": link_url or self.base_url + "/lure/" + self.lure_id,
            "invoice_id": f"INV-{uuid.uuid4().hex[:8].upper()}",
            "invoice_amount": f"{1000 + len(target_name) * 100:.0f}",
            "due_date": datetime.now().strftime("%B %d, %Y"),
            "meeting_date": datetime.now().strftime("%B %d, %Y"),
            "meeting_time": "2:00 PM PST",
            "meeting_location": "Zoom",
            "meeting_id": f"{uuid.uuid4().hex[:8].upper()}",
            "meeting_password": f"{uuid.uuid4().hex[:4].upper()}",
            "organizer_name": target_name,
            "organizer_email": target_email or "manager@nymbric.com",
            "company_support_email": target_email or "support@nymbric.com",
            "alert_id": f"ALERT-{uuid.uuid4().hex[:8].upper()}",
            "alert_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tracking_number": f"TRK-{uuid.uuid4().hex[:8].upper()}",
            "delivery_date": datetime.now().strftime("%B %d, %Y"),
            "carrier": "FedEx",
            "plan_name": "Pro Plan",
            "billing_cycle": "Monthly",
            "amount_due": f"{99.99:.2f}",
            "expiry_date": (datetime.now() + timedelta(days=30)).strftime("%B %d, %Y"),
        }

        # Apply template
        subject = template["subject"].format(**personalization)
        body = template["body"].format(**personalization)
        sender_name = template["sender_name"].format(**personalization)
        sender_email = template["sender_email"].format(**personalization)
        sender_address = template["sender_address"].format(**personalization)
        cc = template["cc"]
        attachments = template["attachments"]
        urgency = template["urgency"]
        personalization_dict = template["personalization"]

        # Build metadata
        metadata = {
            "target_name": target_name,
            "target_email": target_email,
            "target_employer": target_employer,
            "target_location": target_location,
            "template": template_name,
            "generated_at": datetime.now().isoformat(),
            "lure_type": "phishing",
            "delivery_method": "email",
        }

        # Generate lure ID
        lure_id = f"lure-{uuid.uuid4().hex[:8].upper()}"

        artifact = LureArtifact(
            lure_id=lure_id,
            template_name=template_name,
            subject=subject,
            body=body,
            sender_name=sender_name,
            sender_email=sender_email,
            sender_address=sender_address,
            cc=cc,
            attachments=attachments,
            link_url=personalization["link_url"],
            urgency=urgency,
            personalization=personalization_dict,
            metadata=metadata,
        )
        return [artifact]

    def generate_all(self, target_name: str, **kwargs) -> list[LureArtifact]:
        """Generate all available lure types for a target.

        Args:
            target_name: The target person's name.
            **kwargs: Additional parameters passed to generate().

        Returns:
            A list of LureArtifact objects.
        """
        artifacts = []
        for template_name in self._templates.keys():
            artifact = self.generate(target_name=target_name, template_name=template_name, **kwargs)
            artifacts.append(artifact)
        return artifacts


# Import timedelta for the template params
from datetime import timedelta
