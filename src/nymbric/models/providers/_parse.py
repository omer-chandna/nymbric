"""Shared parsing helpers. Invalid JSON stays invalid."""

from __future__ import annotations

import json
import re
from typing import Any

from nymbric.core.errors import StructuredOutputError

_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def tool_arguments(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise StructuredOutputError(f"Tool arguments were not valid JSON: {exc}") from exc
        if isinstance(parsed, dict):
            return parsed
    if value in (None, ""):
        return {}
    raise StructuredOutputError("Tool arguments must be a JSON object.")


def parse_json_object(text: str) -> dict[str, Any]:
    raw = text.strip()
    if not raw:
        raise StructuredOutputError("The model returned an empty response.")
    candidates = [raw]
    fenced = _FENCE.search(raw)
    if fenced:
        candidates.insert(0, fenced.group(1))
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end > start:
        candidates.append(raw[start : end + 1])
    last_error: Exception | None = None
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError as exc:
            last_error = exc
            continue
        if isinstance(parsed, dict):
            return parsed
        last_error = StructuredOutputError("Structured output must be a JSON object.")
    raise StructuredOutputError(f"Structured output was not valid JSON: {last_error}")
