# -*- coding: utf-8 -*-
from __future__ import annotations
"""TRACE OSINT Copilot - Exposure Scoring Module

Risk band mapping (canonical definition):
  0.00-0.25 -> LOW
  0.25-0.50 -> MEDIUM
  0.50-0.75 -> HIGH
  0.75-1.00 -> CRITICAL

All risk-level text and narrative must use this mapping.
"""

from src.models import Finding, Entity


EXPOSURE_FACTORS = {
    "public_search_result": 0.2,
    "public_profile_found": 0.3,
    "email_in_data_breach": 0.8,
    "phone_number_public": 0.4,
    "domain_registered": 0.2,
    "social_media_active": 0.3,
    "real_name_identified": 0.5,
    "location_identified": 0.6,
    "employer_identified": 0.4,
    "financial_info_public": 0.9,
}


def score_to_risk_level(score: float) -> str:
    """Map a 0-1 exposure score to a risk band.

    Risk band mapping:
      0.00-0.25 -> low
      0.25-0.50 -> medium
      0.50-0.75 -> high
      0.75-1.00 -> critical
    """
    if score >= 0.75:
        return "critical"
    if score >= 0.50:
        return "high"
    if score >= 0.25:
        return "medium"
    return "low"


def risk_level_label(risk_level: str) -> str:
    """Return a human-readable label for a risk band."""
    labels = {
        "low": "Low exposure",
        "medium": "Moderate exposure",
        "high": "High exposure",
        "critical": "Critical exposure",
    }
    return labels.get(risk_level, "Unknown exposure")


def compute_exposure_score(findings: list[Finding], entities: list[Entity]) -> dict:
    """Compute an overall exposure assessment based on public findings."""
    signals = {}
    total_score = 0.0
    factor_count = 0

    for finding in findings:
        label = finding.label.lower()
        if "profile" in label or "account" in label:
            signals["public_profile_found"] = True
        if "email" in label:
            signals["email_exposed"] = True
        if "phone" in label:
            signals["phone_exposed"] = True
        if "location" in label or "address" in label:
            signals["location_identified"] = True
        if "employer" in label or "company" in label or "organization" in label:
            signals["employer_identified"] = True
        if "real name" in label or "full name" in label:
            signals["real_name_identified"] = True

    for key, factor in EXPOSURE_FACTORS.items():
        if signals.get(key) or signals.get(f"{key}_exposed"):
            total_score += factor
            factor_count += 1

    unique_entity_types = set(e.type for e in entities)
    if "email" in unique_entity_types:
        total_score += 0.15
    if "phone" in unique_entity_types:
        total_score += 0.1
    if "domain" in unique_entity_types:
        total_score += 0.05

    normalized = min(total_score / max(factor_count, 1), 1.0)
    normalized = round(normalized, 3)

    risk_level = score_to_risk_level(normalized)

    return {
        "score": normalized,
        "risk_level": risk_level,
        "risk_label": risk_level_label(risk_level),
        "signals": list(signals.keys()),
        "factor_count": factor_count,
        "summary": _build_exposure_summary(normalized, risk_level, signals),
    }


def _build_exposure_summary(score: float, risk_level: str, signals: dict) -> str:
    """Build a human-readable exposure summary matching the risk band."""
    label = risk_level_label(risk_level)

    if risk_level == "critical":
        return (
            f"{label}: Multiple public data points identified. "
            "Target has significant public footprint with identifiable personal information."
        )
    elif risk_level == "high":
        return (
            f"{label}: Several public data points found. "
            "Personal information is publicly accessible."
        )
    elif risk_level == "medium":
        return (
            f"{label}: Some public data points found. "
            "Limited personal information is publicly accessible."
        )
    elif risk_level == "low":
        return (
            f"{label}: Few public data points found. "
            "Target has minimal public footprint."
        )
    return (
        "No exposure: No significant public data points identified. "
        "Target has minimal or no public footprint."
    )
