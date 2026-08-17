# -*- coding: utf-8 -*-
from __future__ import annotations
"""TRACE OSINT Copilot - Correlation Package.

Entity resolution, normalization, and cross-linking engine.
"""

from src.correlation.engine import correlate_entities, build_correlation_summary
from src.correlation.normalize import (
    normalize_email,
    normalize_username,
    normalize_url,
    normalize_domain,
    normalize_phone,
    detect_entity_type,
    are_likely_same_entity,
)

__all__ = [
    "correlate_entities",
    "build_correlation_summary",
    "normalize_email",
    "normalize_username",
    "normalize_url",
    "normalize_domain",
    "normalize_phone",
    "detect_entity_type",
    "are_likely_same_entity",
]
