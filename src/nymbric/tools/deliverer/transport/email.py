"""Email transport for delivering phishing lures via SMTP.

This module provides email delivery capabilities using SMTP with OAuth2 support.
"""

from __future__ import annotations

import logging
import smtplib
import time
from dataclasses import dataclass, field
from datetime import datetime
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)


@dataclass
class DeliveryResult:
    """Result of an email delivery attempt."""

    success: bool
    recipient: str
    subject: str
    sent_at: datetime
    message_id: str | None = None
    error: str | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""


class EmailTransport:
    """Email transport using SMTP with OAuth2 support.

    This class handles:
    - SMTP connection management
    - OAuth2 authentication (Google, Microsoft, etc.)
    - Email message delivery
    - Delivery result tracking
    """

    def __init__(
        self,
        smtp_server: str = "smtp.gmail.com",
        smtp_port: int = 587,
        use_tls: bool = True,
        use_oauth2: bool = True,
        oauth2_client_id: str | None = None,
        oauth2_client_secret: str | None = None,
        oauth2_token_url: str | None = None,
        oauth2_scopes: list[str] | None = None,
    ):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.use_tls = use_tls
        self.use_oauth2 = use_oauth2
        self.oauth2_client_id = oauth2_client_id
        self.oauth2_client_secret = oauth2_client_secret
        self.oauth2_token_url = oauth2_token_url or "https://accounts.google.com/o/oauth2/token"
        self.oauth2_scopes = oauth2_scopes or ["https://mail.google.com/"]
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "Nymbric-Deliverer/1.0",
        })
        self._oauth2_token: dict[str, Any] | None = None

    def connect(self) -> smtplib.SMTP:
        """Establish connection to the SMTP server.

        Returns:
            An SMTP connection object.
        """
        server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10)
        server.ehlo()

        if self.use_tls:
            server.starttls()
            server.ehlo()

        if self.use_oauth2:
            self._authenticate_oauth2(server)
        else:
            self._authenticate_plain(server)

        return server

    def _authenticate_oauth2(self, server: smtplib.SMTP) -> None:
        """Authenticate using OAuth2.

        Args:
            server: The SMTP connection.
        """
        try:
            # Get OAuth2 token
            token_response = self._get_oauth2_token()

            if not token_response or "access_token" not in token_response:
                raise RuntimeError("Failed to obtain OAuth2 token")

            self._oauth2_token = token_response

            # Attach Bearer token to SMTP connection
            server.ehlo()
            server.mail("X-TLS-SMTP-Ext-Starttls-Auth-Only", len(b""))
            server.rcpt("X-TLS-SMTP-Ext-Starttls-Auth-Only", len(b""))
            server.data(b"")

            # Send AUTH LOGIN with OAuth2 token
            auth_data = f"AUTH XOAUTH2 {self._oauth2_token['access_token']}".encode()
            server.sendmail("X-TLS-SMTP-Ext-Starttls-Auth-Only", "X-TLS-SMTP-Ext-Starttls-Auth-Only", auth_data)

            logger.info("OAuth2 authentication successful")

        except Exception as e:
            logger.warning(f"OAuth2 authentication failed: {e}")
            raise

    def _authenticate_plain(self, server: smtplib.SMTP) -> None:
        """Authenticate using plain SMTP.

        Args:
            server: The SMTP connection.
        """
        # This is a placeholder - in practice you'd use environment variables
        # for credentials
        logger.info("Plain authentication configured (no credentials provided)")

    def _get_oauth2_token(self) -> dict[str, Any]:
        """Obtain an OAuth2 access token.

        Returns:
            The OAuth2 token response.
        """
        if not self.oauth2_client_id or not self.oauth2_client_secret:
            raise ValueError("OAuth2 credentials not configured")

        response = self._session.post(
            self.oauth2_token_url,
            data={
                "client_id": self.oauth2_client_id,
                "client_secret": self.oauth2_client_secret,
                "grant_type": "client_credentials",
                "scope": " ".join(self.oauth2_scopes),
            },
            timeout=30,
        )

        response.raise_for_status()
        return response.json()

    def send(
        self,
        recipient: str,
        subject: str,
        body: str,
        sender_name: str | None = None,
        sender_email: str | None = None,
        sender_address: str | None = None,
        cc: list[str] | None = None,
        attachments: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> DeliveryResult:
        """Send an email.

        Args:
            recipient: The recipient email address.
            subject: The email subject.
            body: The email body.
            sender_name: The sender name.
            sender_email: The sender email.
            sender_address: The sender physical address.
            cc: CC recipients.
            attachments: List of attachment file paths.
            metadata: Additional metadata to include.

        Returns:
            A DeliveryResult object.
        """
        try:
            server = self.connect()

            msg = MIMEMultipart()
            msg["From"] = f"{sender_name or 'Nymbric Lure'} <{sender_email or 'noreply@nymbric.local'}>"
            msg["To"] = recipient
            msg["Subject"] = subject

            if sender_address:
                msg["X-Sender-Address"] = sender_address

            # Body
            msg.attach(MIMEText(body, "plain", "utf-8"))

            # CC
            if cc:
                msg["Cc"] = ", ".join(cc)

            # Attachments
            if attachments:
                for attachment in attachments:
                    attachment_path = Path(attachment)
                    if not attachment_path.exists():
                        logger.warning(f"Attachment not found: {attachment}")
                        continue
                    with open(attachment_path, "rb") as f:
                        part = MIMEApplication(f.read(), Name=attachment_path.name)
                        part["Content-Disposition"] = f'attachment; filename="{attachment_path.name}"'
                        msg.attach(part)

            # Send
            server.sendmail(
                "noreply@nymbric.local",
                [recipient] + (cc or []),
                msg.as_string().encode("utf-8"),
            )

            server.quit()

            result = DeliveryResult(
                success=True,
                recipient=recipient,
                subject=subject,
                sent_at=datetime.now(),
                message_id=msg["Message-ID"],
                response_headers=dict(msg),
            )

            logger.info(f"Email sent successfully to {recipient}")
            return result

        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            return DeliveryResult(
                success=False,
                recipient=recipient,
                subject=subject,
                sent_at=datetime.now(),
                error=str(e),
            )

        except Exception as e:
            logger.error(f"Delivery failed: {e}")
            return DeliveryResult(
                success=False,
                recipient=recipient,
                subject=subject,
                sent_at=datetime.now(),
                error=str(e),
            )

    def send_batch(
        self,
        recipients: list[str],
        subject: str,
        body: str,
        sender_name: str | None = None,
        sender_email: str | None = None,
        sender_address: str | None = None,
        cc: list[str] | None = None,
        attachments: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> list[DeliveryResult]:
        """Send emails to multiple recipients.

        Args:
            recipients: List of recipient email addresses.
            subject: The email subject.
            body: The email body.
            sender_name: The sender name.
            sender_email: The sender email.
            sender_address: The sender physical address.
            cc: CC recipients.
            attachments: List of attachment file paths.
            metadata: Additional metadata.

        Returns:
            A list of DeliveryResult objects.
        """
        results: list[DeliveryResult] = []

        for recipient in recipients:
            result = self.send(
                recipient=recipient,
                subject=subject,
                body=body,
                sender_name=sender_name,
                sender_email=sender_email,
                sender_address=sender_address,
                cc=cc,
                attachments=attachments,
                metadata=metadata,
            )
            results.append(result)

            # Small delay between sends to avoid overwhelming the server
            time.sleep(0.5)

        return results
