"""Email transport for delivering phishing lures via SMTP.

This module provides email delivery capabilities using SMTP with OAuth2 support.
"""

from __future__ import annotations

from .email import EmailTransport, DeliveryResult

__all__ = ["EmailTransport", "DeliveryResult"]
