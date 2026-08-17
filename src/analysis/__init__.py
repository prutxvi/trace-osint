# -*- coding: utf-8 -*-
from __future__ import annotations
"""TRACE OSINT Copilot - Analysis Package.

Identity collapse, AI pivots, scoring, and case synthesis.
"""

from src.analysis.identity import IdentityProfile, collapse_identity
from src.analysis.ai_pivot import analyze_findings, suggest_pivots, generate_ai_summary
from src.analysis.exposure import compute_exposure_score, score_to_risk_level, risk_level_label
from src.analysis.confidence import merge_confidences, entity_confidence_from_findings
from src.analysis.synthesis import (
    apply_verification_labels,
    build_canonical_profiles,
    build_investigation_notes,
    build_plain_language_summary,
    build_story_card,
    build_timeline,
    split_findings_by_focus,
    is_infrastructure_finding,
)
from src.analysis.resolver import resolve_primary_target

__all__ = [
    "IdentityProfile",
    "collapse_identity",
    "analyze_findings",
    "suggest_pivots",
    "generate_ai_summary",
    "compute_exposure_score",
    "score_to_risk_level",
    "risk_level_label",
    "merge_confidences",
    "entity_confidence_from_findings",
    "apply_verification_labels",
    "build_canonical_profiles",
    "build_investigation_notes",
    "build_plain_language_summary",
    "build_story_card",
    "build_timeline",
    "split_findings_by_focus",
    "is_infrastructure_finding",
    "resolve_primary_target",
]
