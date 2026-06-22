"""TRACE OSINT - Entity Correlation Engine"""

from src.models import Finding, Entity, EntityType, Confidence
from src.scoring.confidence import merge_confidences


def correlate_entities(findings: list[Finding]) -> list[Entity]:
    """Cross-correlate all findings to build entity relationship graph."""
    entity_map: dict[str, Entity] = {}

    for finding in findings:
        value = _extract_primary_entity(finding)
        if not value:
            continue

        etype = _detect_type(value)
        canonical = _canonicalize(value, etype)

        matched = _find_existing_entity(entity_map, canonical, etype)

        if matched:
            matched.finding_ids.append(finding.id)
            if value not in matched.aliases and value != matched.value:
                matched.aliases.append(value)
        else:
            entity = Entity(
                type=etype,
                value=canonical,
                aliases=[value] if value != canonical else [],
                finding_ids=[finding.id],
            )
            entity_map[entity.id] = entity

    _cross_link_entities(entity_map, findings)
    _compute_confidence(entity_map, findings)

    return list(entity_map.values())


def _extract_primary_entity(finding: Finding) -> str:
    """Extract the primary entity value from a finding."""
    details = finding.details or {}

    if finding.entity_type == EntityType.EMAIL:
        return finding.entity_value

    if finding.entity_type == EntityType.DOMAIN:
        return details.get("domain", finding.entity_value)

    if finding.entity_type == EntityType.USERNAME:
        return details.get("username", finding.entity_value)

    if finding.entity_type == EntityType.URL:
        url = details.get("url", finding.entity_value)
        import re
        match = re.search(r"https?://([^/]+)", url)
        if match:
            return match.group(1)
        return url

    if finding.entity_type == EntityType.IP_ADDRESS:
        return finding.entity_value

    return finding.entity_value


def _detect_type(value: str) -> EntityType:
    """Detect entity type from value."""
    import re
    if re.match(r"^[^@]+@[^@]+\.[^@]+$", value):
        return EntityType.EMAIL
    if re.match(r"^\+?\d[\d\s\-()]{7,}$", value):
        return EntityType.PHONE
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
        return EntityType.IP_ADDRESS
    if re.match(r"^https?://", value):
        return EntityType.URL
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$", value):
        return EntityType.DOMAIN
    if re.match(r"^[a-zA-Z0-9_]{3,}$", value):
        return EntityType.USERNAME
    return EntityType.PERSON


def _canonicalize(value: str, etype: EntityType) -> str:
    """Canonicalize entity value."""
    value = value.strip()
    if etype == EntityType.EMAIL:
        return value.lower()
    if etype == EntityType.DOMAIN:
        return value.lower().lstrip("www.")
    if etype == EntityType.USERNAME:
        return value.lower().lstrip("@")
    if etype == EntityType.IP_ADDRESS:
        return value
    return value


def _find_existing_entity(entity_map: dict, canonical: str, etype: EntityType) -> Entity | None:
    """Find an existing entity that matches."""
    for entity in entity_map.values():
        if entity.type != etype:
            continue
        if entity.value == canonical:
            return entity
        if canonical in [a.lower() for a in entity.aliases]:
            return entity
    return None


def _cross_link_entities(entity_map: dict, findings: list[Finding]):
    """Cross-link entities that appear in the same findings."""
    finding_entity_map = {}
    for entity in entity_map.values():
        for fid in entity.finding_ids:
            if fid not in finding_entity_map:
                finding_entity_map[fid] = []
            finding_entity_map[fid].append(entity.id)


def _compute_confidence(entity_map: dict, findings: list[Finding]):
    """Compute confidence for each entity based on contributing findings."""
    finding_map = {f.id: f for f in findings}

    for entity in entity_map.values():
        contributing = [finding_map[fid] for fid in entity.finding_ids if fid in finding_map]
        if contributing:
            confidences = [f.confidence for f in contributing]
            entity.confidence = merge_confidences(confidences)
        else:
            entity.confidence = Confidence(score=0.1, reasoning="No contributing findings")


def build_correlation_summary(entities: list[Entity], findings: list[Finding]) -> dict:
    """Build a summary of entity correlations."""
    type_counts = {}
    for e in entities:
        type_counts[e.type.value] = type_counts.get(e.type.value, 0) + 1

    return {
        "total_entities": len(entities),
        "total_findings": len(findings),
        "type_distribution": type_counts,
        "high_confidence": sum(1 for e in entities if e.confidence.level == "high"),
        "medium_confidence": sum(1 for e in entities if e.confidence.level == "medium"),
        "low_confidence": sum(1 for e in entities if e.confidence.level == "low"),
    }
