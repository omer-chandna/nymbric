"""Redact credential-shaped strings before they reach traces or logs."""

from __future__ import annotations

import re
from typing import Any

_SECRET = re.compile(
    r"(?i)(api[_-]?key|secret|token|authorization|bearer)\s*[:=]\s*\S+"
)
_KEYISH = re.compile(r"\b(sk-[A-Za-z0-9]{8,}|sk-ant-[A-Za-z0-9_-]{8,})\b")


def redact_text(value: str) -> str:
    value = _SECRET.sub(r"\1=[REDACTED]", value)
    return _KEYISH.sub("[REDACTED]", value)


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {str(k): redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, tuple):
        return [redact(v) for v in value]
    return value
