"""Tests for identity collapse engine."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.models import Finding, EntityType, Confidence, Source
from src.sources.identity_collapse import IdentityProfile


def _make_finding(entity_type, entity_value, details=None, fid=None):
    f = Finding(
        entity_type=entity_type,
        entity_value=entity_value,
        details=details or {},
        confidence=Confidence(score=0.8, reasoning="test"),
        source=Source(url="https://test.com", title="Test", source_type="public_search"),
    )
    if fid:
        f.id = fid
    return f


def test_identity_profile_basic():
    profile = IdentityProfile("test@example.com")
    assert profile.primary_clue == "test@example.com"
    assert profile.identity_type == "email"


def test_add_email_finding():
    profile = IdentityProfile("test@example.com")
    finding = _make_finding(EntityType.EMAIL, "test@example.com")
    profile.add_finding(finding)
    assert "test@example.com" in profile.emails
    assert len(profile.raw_findings) == 1


def test_add_username_finding():
    profile = IdentityProfile("johndoe")
    finding = _make_finding(EntityType.USERNAME, "johndoe", details={"platform": "Twitter"})
    profile.add_finding(finding)
    assert "johndoe" in profile.usernames
    assert "Twitter" in profile.social_profiles


def test_add_phone_finding():
    profile = IdentityProfile("+919876543210")
    finding = _make_finding(EntityType.PHONE, "+919876543210")
    profile.add_finding(finding)
    assert "+919876543210" in profile.phones


def test_add_domain_finding():
    profile = IdentityProfile("example.com")
    finding = _make_finding(EntityType.DOMAIN, "example.com")
    profile.add_finding(finding)
    assert "example.com" in profile.domains


def test_deduplication():
    profile = IdentityProfile("test@test.com")
    f1 = _make_finding(EntityType.EMAIL, "test@test.com", fid="f1")
    f2 = _make_finding(EntityType.EMAIL, "test@test.com", fid="f2")
    profile.add_finding(f1)
    profile.add_finding(f2)
    assert len(profile.emails) == 1
    assert len(profile.raw_findings) == 2


def test_identity_type_detection():
    assert IdentityProfile("user@domain.com").identity_type == "email"
    assert IdentityProfile("+1234567890").identity_type == "phone"
    assert IdentityProfile("8.8.8.8").identity_type == "ip"
    assert IdentityProfile("https://example.com").identity_type == "url"
    assert IdentityProfile("example.com").identity_type == "domain"
    assert IdentityProfile("johndoe").identity_type == "username"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
