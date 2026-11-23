"""Real lure generation for Nymbric.

This module provides tools for generating deployable phishing lures
based on OSINT data about a target person.
"""

from __future__ import annotations

from .templates import LURE_TEMPLATES
from .generator import LureGenerator
from .renderer import LureRenderer

__all__ = ["LURE_TEMPLATES", "LureGenerator", "LureRenderer"]
