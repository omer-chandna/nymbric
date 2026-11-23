"""Lure renderer for generating deployable artifacts.

This module handles:
- Email message rendering (MIME format)
- Attachment file generation (flag files, PDFs)
- Artifact serialization (JSON, YAML)
- Artifact packaging (ZIP archives)
"""

from __future__ import annotations

import json
import logging
import zipfile
from dataclasses import asdict
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class LureRenderer:
    """Renders lure artifacts into deployable formats.

    This class handles:
    - Converting LureArtifact to MIME email messages
    - Generating attachment files (flag files, PDFs)
    - Serializing artifacts to JSON/YAML
    - Packaging artifacts into ZIP archives
    """

    def __init__(self, output_dir: str | Path = "lure_artifacts"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def render_email(self, artifact) -> MIMEMultipart:
        """Render a LureArtifact as a MIME email message.

        Args:
            artifact: A LureArtifact object.

        Returns:
            A MIMEMultipart message ready for delivery.
        """
        msg = MIMEMultipart()
        msg["From"] = f"{artifact.sender_name} <{artifact.sender_email}>"
        msg["To"] = artifact.personalization.get("target_email", "target@example.com")
        msg["Subject"] = artifact.subject
        msg["X-Lure-ID"] = artifact.lure_id
        msg["X-Lure-Template"] = artifact.template_name
        msg["X-Lure-Urgency"] = artifact.urgency

        # Body
        msg.attach(MIMEText(artifact.body, "plain", "utf-8"))

        # Attachments
        for attachment in artifact.attachments:
            attachment_path = self.output_dir / attachment
            if not attachment_path.exists():
                attachment_path = self._generate_attachment(attachment)
            with open(attachment_path, "rb") as f:
                part = MIMEApplication(f.read(), Name=attachment)
                part["Content-Disposition"] = f'attachment; filename="{attachment}"'
                msg.attach(part)

        return msg

    def render_json(self, artifact) -> str:
        """Render a LureArtifact as a JSON string.

        Args:
            artifact: A LureArtifact object.

        Returns:
            A JSON string representation.
        """
        return json.dumps(asdict(artifact), indent=2, default=str)

    def render_yaml(self, artifact) -> str:
        """Render a LureArtifact as a YAML string.

        Args:
            artifact: A LureArtifact object.

        Returns:
            A YAML string representation.
        """
        import yaml
        return yaml.dump(asdict(artifact), default_flow_style=False)

    def package(self, artifact) -> str:
        """Package a LureArtifact into a ZIP archive.

        Args:
            artifact: A LureArtifact object.

        Returns:
            Path to the ZIP archive.
        """
        archive_path = self.output_dir / f"{artifact.lure_id}.zip"

        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # Add email source
            zf.writestr(f"{artifact.lure_id}.json", self.render_json(artifact))
            zf.writestr(f"{artifact.lure_id}.yaml", self.render_yaml(artifact))

            # Add email message
            msg = self.render_email(artifact)
            zf.writestr(f"{artifact.lure_id}.eml", msg.as_string())

            # Add attachments
            for attachment in artifact.attachments:
                attachment_path = self.output_dir / attachment
                if attachment_path.exists():
                    zf.write(attachment_path, f"{artifact.lure_id}/{attachment}")

        return str(archive_path)

    def _generate_attachment(self, attachment_name: str) -> Path:
        """Generate a flag file attachment.

        Args:
            attachment_name: The name of the attachment to generate.

        Returns:
            Path to the generated attachment.
        """
        # Flag file content
        flag_content = "You Got Pwned!\n\nThis is a flag file attachment.\nNo real malicious content here.\n\nNymbric Lure Framework v1.0"

        # Generate filename
        filename = attachment_name

        # Write flag file
        path = self.output_dir / filename
        path.write_text(flag_content, encoding="utf-8")

        logger.info(f"Generated flag file: {path}")
        return path
