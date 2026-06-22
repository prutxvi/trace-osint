"""TRACE OSINT Copilot - Exposure Scoring Module"""

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

    risk_level = "low"
    if normalized >= 0.7:
        risk_level = "critical"
    elif normalized >= 0.5:
        risk_level = "high"
    elif normalized >= 0.3:
        risk_level = "medium"

    return {
        "score": normalized,
        "risk_level": risk_level,
        "signals": list(signals.keys()),
        "factor_count": factor_count,
        "summary": _build_exposure_summary(normalized, risk_level, signals),
    }


def _build_exposure_summary(score: float, risk_level: str, signals: dict) -> str:
    """Build a human-readable exposure summary."""
    if score >= 0.7:
        return (
            "HIGH EXPOSURE: Multiple public data points identified. "
            "Target has significant public footprint with identifiable personal information."
        )
    elif score >= 0.5:
        return (
            "MODERATE EXPOSURE: Several public data points found. "
            "Some personal information is publicly accessible."
        )
    elif score >= 0.3:
        return (
            "LIMITED EXPOSURE: Few public data points found. "
            "Target has minimal public footprint."
        )
    elif score > 0.0:
        return (
            "MINIMAL EXPOSURE: Very few public data points found. "
            "Target has a limited public presence."
        )
    return (
        "NO EXPOSURE: No significant public data points identified. "
        "Target has minimal or no public footprint."
    )
