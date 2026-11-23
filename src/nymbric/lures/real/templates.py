"""Lure templates for phishing lure generation.

These templates are used to generate realistic-looking phishing emails
based on OSINT data about a target person.
"""

from __future__ import annotations

from typing import Any

LURE_TEMPLATES: dict[str, dict[str, Any]] = {
    "job_offer": {
        "subject": "Urgent: Your Job Offer at {company} - Action Required - {target_email}",
        "body": """Dear {target_name},

Congratulations! After reviewing your impressive profile on LinkedIn and GitHub,
we are pleased to offer you a position as {position} at {company}.

Your skills in {skills} have caught our attention, and we believe you would
be a great fit for our team.

Please click the link below to complete your onboarding process:

    {link_url}

Your offer is valid for the next 48 hours. Please act quickly to secure
your position.

Best regards,
The {company} Recruitment Team

---
This is an urgent matter. Please respond within 24 hours.
""",
        "sender_name": "{company} Recruitment Team",
        "sender_email": "{company}@{company_domain}.com",
        "sender_address": "{company} HQ, {target_location}",
        "cc": ["hr@{company}.com", "manager@{company}.com"],
        "attachments": ["onboarding_checklist.pdf", "offer_letter.pdf"],
        "urgency": "high",
        "personalization": {
            "greeting": "Dear {target_name},",
            "closing": "Best regards,",
            "signature": "The {company} Recruitment Team",
        },
    },
    "invoice": {
        "subject": "Invoice #INV-{invoice_id} - Payment Due from {company}",
        "body": """Dear {target_name},

This is a reminder that your invoice #INV-{invoice_id} for services
rendered by {company} is now due.

Please find the attached invoice and payment details.

To avoid late fees, please process your payment by clicking the link below:

    {link_url}

If you have any questions, please contact us at {company_support_email}.

Thank you,
{company} Billing Department

---
Invoice #INV-{invoice_id}
Amount Due: ${invoice_amount}
Due Date: {due_date}
""",
        "sender_name": "{company} Billing Department",
        "sender_email": "{company}@{company_domain}.com",
        "sender_address": "{company} HQ, {target_location}",
        "cc": ["billing@{company}.com"],
        "attachments": ["invoice_INV-{invoice_id}.pdf"],
        "urgency": "medium",
        "personalization": {
            "greeting": "Dear {target_name},",
            "closing": "Sincerely,",
            "signature": "{company} Billing Department",
        },
    },
    "meeting_invite": {
        "subject": "Meeting Invitation: Q4 Planning - {company} Team",
        "body": """Dear {target_name},

You are invited to attend our Q4 planning meeting with the {company} team.

Date: {meeting_date}
Time: {meeting_time}
Location: {meeting_location}

Please confirm your attendance by clicking the link below:

    {link_url}

Agenda:
- Review of Q3 performance
- Q4 goals and objectives
- Team updates

Best regards,
{organizer_name}

---
Meeting ID: {meeting_id}
Password: {meeting_password}
""",
        "sender_name": "{organizer_name}",
        "sender_email": "{organizer_email}",
        "sender_address": "{company} HQ, {target_location}",
        "cc": ["team@{company}.com"],
        "attachments": [],
        "urgency": "low",
        "personalization": {
            "greeting": "Dear {target_name},",
            "closing": "Best regards,",
            "signature": "{organizer_name}",
        },
    },
    "security_alert": {
        "subject": "SECURITY ALERT: Your Account Has Been Compromised",
        "body": """Dear {target_name},

Our security team has detected unusual activity on your account at {company}.

Your password has been changed and your 2FA has been disabled. Your account has been compromised.

Please click the link below immediately to secure your account:

    {link_url}

If you did not initiate this change, your account is at risk.

Best regards,
{company} Security Team

---
Alert ID: {alert_id}
Time: {alert_time}
Severity: HIGH
""",
        "sender_name": "{company} Security Team",
        "sender_email": "security@{company}.com",
        "sender_address": "{company} HQ, {target_location}",
        "cc": ["security@{company}.com"],
        "attachments": ["security_report.pdf"],
        "urgency": "critical",
        "personalization": {
            "greeting": "Dear {target_name},",
            "closing": "Urgent - Please act now,",
            "signature": "{company} Security Team",
        },
    },
    "package_delivery": {
        "subject": "Your Package is Out for Delivery - Track Here",
        "body": """Dear {target_name},

Your package from {company} is out for delivery and will arrive today.

Track your package here:

    {link_url}

Delivery details:
- Tracking Number: {tracking_number}
- Estimated Delivery: Today, {delivery_date}
- Carrier: {carrier}

Please ensure someone is available to receive your package.

Thank you,
{company} Delivery Team

---
Tracking: {tracking_number}
Status: Out for Delivery
""",
        "sender_name": "{company} Delivery Team",
        "sender_email": "delivery@{company}.com",
        "sender_address": "{company} Distribution Center, {target_location}",
        "cc": [],
        "attachments": ["tracking_label.pdf"],
        "urgency": "medium",
        "personalization": {
            "greeting": "Dear {target_name},",
            "closing": "Thank you,",
            "signature": "{company} Delivery Team",
        },
    },
    "renewal_notice": {
        "subject": "Service Renewal Notice - Your Subscription Expires Soon",
        "body": """Dear {target_name},

Your subscription to {company}'s premium service will expire on {expiry_date}.

To avoid service interruption, please renew your subscription by clicking the
link below:

    {link_url}

Your current plan: {plan_name}
Current billing cycle: {billing_cycle}
Amount due: ${amount_due}

Best regards,
{company} Customer Service

---
Plan: {plan_name}
Expires: {expiry_date}
""",
        "sender_name": "{company} Customer Service",
        "sender_email": "support@{company}.com",
        "sender_address": "{company} HQ, {target_location}",
        "cc": ["billing@{company}.com"],
        "attachments": ["renewal_notice.pdf"],
        "urgency": "medium",
        "personalization": {
            "greeting": "Dear {target_name},",
            "closing": "Best regards,",
            "signature": "{company} Customer Service",
        },
    },
}
