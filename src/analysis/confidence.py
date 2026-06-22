"""TRACE OSINT Copilot - Confidence Scoring Module"""

from src.models import Finding, Entity, Confidence
from src.config import CONFIDENCE_THRESHOLDS


def compute_finding_confidence(
    source_reliability: float = 0.5,
    corroboration_count: int = 1,
    recency_factor: float = 1.0,
    specificity_score: float = 0.5,
) -> Confidence:
    """Compute a confidence score for a finding based on multiple factors."""
    base = source_reliability * 0.4
    corroboration = min(corroboration_count / 3.0, 1.0) * 0.3
    recency = recency_factor * 0.15
    specificity = specificity_score * 0.15

    score = base + corroboration + recency + specificity
    score = round(min(max(score, 0.0), 1.0), 3)

    confidence = Confidence(score=score, reasoning=_build_reasoning(
        source_reliability, corroboration_count, recency_factor, specificity_score
    ))
    confidence.compute_level()
    return confidence


def _build_reasoning(
    source_rel: float, corroboration: int, recency: float, specificity: float
) -> str:
    """Build human-readable reasoning for confidence score."""
    parts = []
    if source_rel >= 0.8:
        parts.append("high-reliability source")
    elif source_rel >= 0.5:
        parts.append("moderate-reliability source")
    else:
        parts.append("low-reliability source")

    if corroboration >= 3:
        parts.append("multiple corroborating sources")
    elif corroboration >= 2:
        parts.append("partially corroborated")
    else:
        parts.append("single source")

    if recency >= 0.8:
        parts.append("recent data")
    elif recency >= 0.5:
        parts.append("moderately recent")

    if specificity >= 0.7:
        parts.append("highly specific match")
    elif specificity >= 0.4:
        parts.append("general match")

    return "; ".join(parts)


def merge_confidences(confidences: list[Confidence]) -> Confidence:
    """Merge multiple confidence scores into a combined score."""
    if not confidences:
        return Confidence(score=0.0, reasoning="No sources")

    scores = [c.score for c in confidences]
    max_score = max(scores)
    avg_score = sum(scores) / len(scores)
    count_factor = min(len(scores) / 3.0, 1.0)

    combined = (max_score * 0.5) + (avg_score * 0.3) + (count_factor * 0.2)
    combined = round(min(max(combined, 0.0), 1.0), 3)

    confidence = Confidence(
        score=combined,
        reasoning=f"Merged from {len(scores)} sources (max={max_score:.2f}, avg={avg_score:.2f})",
    )
    confidence.compute_level()
    return confidence


def entity_confidence_from_findings(findings: list[Finding]) -> Confidence:
    """Compute entity-level confidence from its contributing findings."""
    confidences = [f.confidence for f in findings]
    return merge_confidences(confidences)


def classify_confidence(score: float) -> str:
    """Return confidence level label for a score."""
    for level, threshold in sorted(
        CONFIDENCE_THRESHOLDS.items(), key=lambda x: -x[1]
    ):
        if score >= threshold:
            return level
    return "minimal"
