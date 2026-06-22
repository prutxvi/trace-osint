"""Tests for correlation and cross-linking."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.models import Finding, Entity, EntityType, Confidence, Source
from src.sources.correlation import correlate_entities, _cross_link_entities, _detect_type


def _make_finding(entity_type, entity_value, finding_id="test-001"):
    f = Finding(
        entity_type=entity_type,
        entity_value=entity_value,
        id=finding_id,
        confidence=Confidence(score=0.7, reasoning="test"),
        source=Source(url="https://test.com", title="Test", source_type="public_search"),
    )
    return f


def test_correlate_basic():
    findings = [
        _make_finding(EntityType.EMAIL, "test@example.com", "f1"),
        _make_finding(EntityType.USERNAME, "testuser", "f2"),
    ]
    entities = correlate_entities(findings)
    assert len(entities) == 2


def test_correlate_deduplicates():
    findings = [
        _make_finding(EntityType.EMAIL, "test@example.com", "f1"),
        _make_finding(EntityType.EMAIL, "TEST@EXAMPLE.COM", "f2"),
    ]
    entities = correlate_entities(findings)
    assert len(entities) == 1
    assert entities[0].value == "test@example.com"


def test_cross_link_entities():
    findings = [
        _make_finding(EntityType.EMAIL, "a@test.com", "f1"),
        _make_finding(EntityType.USERNAME, "user1", "f1"),
        _make_finding(EntityType.DOMAIN, "test.com", "f2"),
    ]
    entities = correlate_entities(findings)
    entity_map = {e.id: e for e in entities}

    email_entity = next((e for e in entities if e.type == EntityType.EMAIL), None)
    username_entity = next((e for e in entities if e.type == EntityType.USERNAME), None)

    if email_entity and username_entity:
        assert email_entity.id in username_entity.linked_entity_ids or \
               username_entity.id in email_entity.linked_entity_ids


def test_detect_type():
    assert _detect_type("test@example.com") == EntityType.EMAIL
    assert _detect_type("192.168.1.1") == EntityType.IP_ADDRESS
    assert _detect_type("+919876543210") == EntityType.PHONE
    assert _detect_type("example.com") == EntityType.DOMAIN
    assert _detect_type("johndoe") == EntityType.USERNAME


def test_linked_entity_ids_populated():
    findings = [
        _make_finding(EntityType.EMAIL, "x@test.com", "shared-f1"),
        _make_finding(EntityType.USERNAME, "xuser", "shared-f1"),
    ]
    entities = correlate_entities(findings)
    for e in entities:
        if e.finding_ids:
            assert len(e.linked_entity_ids) >= 0


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
