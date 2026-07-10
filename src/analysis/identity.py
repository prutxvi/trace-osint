from __future__ import annotations
"""TRACE OSINT - Identity Collapse Engine

Builds a complete digital footprint from a single clue.
Combines all sources into one unified identity profile.
"""

import json
from datetime import datetime, timezone
from typing import Optional

from src.models import Finding, Entity, EntityType, Confidence


class IdentityProfile:
    """Unified identity profile built from all available sources."""

    def __init__(self, primary_clue: str):
        self.primary_clue = primary_clue
        self.identity_type = self._detect_type(primary_clue)
        self.real_name = ""
        self.aliases = []
        self.emails = []
        self.phones = []
        self.usernames = []
        self.domains = []
        self.ips = []
        self.social_profiles = {}
        self.companies = []
        self.locations = []
        self.occupations = []
        self.breaches = []
        self.risk_score = 0.0
        self.exposure_level = "unknown"
        self.timeline = []
        self.raw_findings = []
        self.confidence = 0.0

    def _detect_type(self, clue: str) -> str:
        import re
        if re.match(r"^[^@]+@[^@]+\.[^@]+$", clue):
            return "email"
        if re.match(r"^\+?[\d\s\-()]{10,}$", clue):
            return "phone"
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clue):
            return "ip"
        if re.match(r"^https?://", clue):
            return "url"
        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$", clue):
            return "domain"
        return "username"

    def add_finding(self, finding: Finding):
        """Add a finding to the profile and extract relevant data."""
        self.raw_findings.append(finding)
        self._extract_from_finding(finding)

    def _extract_from_finding(self, finding: Finding):
        """Extract identity data from a finding."""
        details = finding.details or {}
        source_url = finding.source.url or ""

        if finding.entity_type == EntityType.EMAIL:
            if finding.entity_value not in self.emails:
                self.emails.append(finding.entity_value)

        elif finding.entity_type == EntityType.PHONE:
            if finding.entity_value not in self.phones:
                self.phones.append(finding.entity_value)

        elif finding.entity_type == EntityType.USERNAME:
            if finding.entity_value not in self.usernames:
                self.usernames.append(finding.entity_value)
            if "platform" in details:
                self.social_profiles[details["platform"]] = details.get("url", "")

        elif finding.entity_type == EntityType.DOMAIN:
            if finding.entity_value not in self.domains:
                self.domains.append(finding.entity_value)

        elif finding.entity_type == EntityType.IP_ADDRESS:
            if finding.entity_value not in self.ips:
                self.ips.append(finding.entity_value)
            if "city" in details:
                loc = f"{details.get('city', '')}, {details.get('country_code', '')}"
                if loc not in self.locations:
                    self.locations.append(loc)
            if "org" in details:
                org = details.get("org", "")
                if org and org not in self.companies:
                    self.companies.append(org)

        elif finding.entity_type == EntityType.PERSON:
            if details.get("name") and not self.real_name:
                self.real_name = details["name"]
            if details.get("age"):
                self.age = details["age"]
            if details.get("location"):
                loc = details["location"]
                if loc not in self.locations:
                    self.locations.append(loc)

        elif finding.entity_type == EntityType.ORGANIZATION:
            name = details.get("name", finding.entity_value)
            if name not in self.companies:
                self.companies.append(name)
            if details.get("officers"):
                for officer in details["officers"]:
                    officer_name = officer.get("name", "")
                    if officer_name and officer_name not in self.aliases:
                        self.aliases.append(officer_name)

        if "claims" in details:
            claims = details["claims"]
            if "occupation" in claims:
                for occ in claims["occupation"]:
                    if occ not in self.occupations:
                        self.occupations.append(occ)
            if "employer" in claims:
                for emp in claims["employer"]:
                    if emp not in self.companies:
                        self.companies.append(emp)
            if "place of birth" in claims:
                for loc in claims["place of birth"]:
                    if loc not in self.locations:
                        self.locations.append(loc)
            if "country of citizenship" in claims:
                for country in claims["country of citizenship"]:
                    if country not in self.locations:
                        self.locations.append(country)

        if "social_profiles" in details:
            for platform, handle in details["social_profiles"].items():
                if handle:
                    self.social_profiles[platform] = handle[0] if isinstance(handle, list) else handle

        if "breaches" in details:
            for breach in details["breaches"]:
                if isinstance(breach, dict):
                    self.breaches.append(breach)
                elif isinstance(breach, str):
                    self.breaches.append({"name": breach})

        self.timeline.append({
            "timestamp": finding.created_at,
            "source": finding.source.source_type,
            "label": finding.label,
            "confidence": finding.confidence.score,
        })

    def compute_risk_score(self):
        """Calculate overall risk/exposure score."""
        score = 0.0

        if self.emails:
            score += 0.1
        if self.phones:
            score += 0.1
        if len(self.usernames) > 5:
            score += 0.15
        elif self.usernames:
            score += 0.05
        if self.social_profiles:
            score += min(len(self.social_profiles) * 0.05, 0.2)
        if self.breaches:
            score += min(len(self.breaches) * 0.1, 0.3)
        if self.domains:
            score += 0.05
        if self.locations:
            score += 0.05
        if self.companies:
            score += 0.05
        if self.real_name:
            score += 0.1

        self.risk_score = round(min(score, 1.0), 3)

        if self.risk_score >= 0.7:
            self.exposure_level = "critical"
        elif self.risk_score >= 0.5:
            self.exposure_level = "high"
        elif self.risk_score >= 0.3:
            self.exposure_level = "medium"
        elif self.risk_score > 0.0:
            self.exposure_level = "low"
        else:
            self.exposure_level = "minimal"

        return self.risk_score

    def compute_confidence(self):
        """Calculate overall confidence in the profile."""
        if not self.raw_findings:
            self.confidence = 0.0
            return 0.0

        high = sum(1 for f in self.raw_findings if f.confidence.level == "high")
        total = len(self.raw_findings)
        self.confidence = round(high / max(total, 1), 3)
        return self.confidence

    def to_dict(self) -> dict:
        """Convert profile to dictionary."""
        return {
            "primary_clue": self.primary_clue,
            "identity_type": self.identity_type,
            "real_name": self.real_name,
            "aliases": self.aliases,
            "emails": self.emails,
            "phones": self.phones,
            "usernames": self.usernames,
            "domains": self.domains,
            "ips": self.ips,
            "social_profiles": self.social_profiles,
            "companies": self.companies,
            "locations": self.locations,
            "occupations": self.occupations,
            "breaches": self.breaches,
            "risk_score": self.risk_score,
            "exposure_level": self.exposure_level,
            "confidence": self.confidence,
            "total_findings": len(self.raw_findings),
            "timeline": self.timeline,
        }

    def to_json(self) -> str:
        """Convert profile to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    def summary(self) -> str:
        """Generate human-readable summary."""
        lines = []
        lines.append(f"IDENTITY PROFILE: {self.primary_clue}")
        lines.append(f"Type: {self.identity_type}")
        lines.append(f"Risk: {self.exposure_level.upper()} ({self.risk_score:.2f})")
        lines.append(f"Confidence: {self.confidence:.2f}")
        lines.append("")

        if self.real_name:
            lines.append(f"Name: {self.real_name}")
        if self.aliases:
            lines.append(f"Aliases: {', '.join(self.aliases[:5])}")
        if self.emails:
            lines.append(f"Emails: {', '.join(self.emails[:5])}")
        if self.phones:
            lines.append(f"Phones: {', '.join(self.phones[:3])}")
        if self.usernames:
            lines.append(f"Usernames: {', '.join(self.usernames[:10])}")
        if self.social_profiles:
            lines.append("Social Profiles:")
            for platform, url in list(self.social_profiles.items())[:10]:
                lines.append(f"  {platform}: {url}")
        if self.domains:
            lines.append(f"Domains: {', '.join(self.domains[:5])}")
        if self.companies:
            lines.append(f"Companies: {', '.join(self.companies[:5])}")
        if self.locations:
            lines.append(f"Locations: {', '.join(self.locations[:5])}")
        if self.occupations:
            lines.append(f"Occupations: {', '.join(self.occupations[:3])}")
        if self.breaches:
            lines.append(f"Breaches: {len(self.breaches)} found")
        lines.append(f"\nTotal Findings: {len(self.raw_findings)}")

        return "\n".join(lines)


def collapse_identity(findings: list[Finding]) -> IdentityProfile:
    """Build a unified identity profile from all findings."""
    primary_clue = findings[0].entity_value if findings else "unknown"
    profile = IdentityProfile(primary_clue)

    for finding in findings:
        profile.add_finding(finding)

    profile.compute_risk_score()
    profile.compute_confidence()

    return profile
