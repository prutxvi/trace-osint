# -*- coding: utf-8 -*-
from __future__ import annotations
"""TRACE OSINT Copilot - Profile Completeness Scorer Plugin.

Example plugin that scores how complete a person's digital profile is.
"""

from src.plugins.base import BasePlugin
from src.models import Case, Finding, EntityType, Confidence, Source


class ProfileCompletenessPlugin(BasePlugin):
    """Scores profile completeness based on available signals."""

    name = "profile_completeness"
    description = "Scores how complete a person's digital profile is"
    version = "1.0.0"

    def collect(self, case: Case) -> list[Finding]:
        """Analyze findings and produce a completeness score."""
        if not case.findings:
            return []

        signals = {
            "email": False,
            "phone": False,
            "username": False,
            "github": False,
            "linkedin": False,
            "domain": False,
            "ip": False,
            "person_name": False,
        }

        for finding in case.findings:
            if finding.entity_type == EntityType.EMAIL:
                signals["email"] = True
            elif finding.entity_type == EntityType.PHONE:
                signals["phone"] = True
            elif finding.entity_type == EntityType.USERNAME:
                signals["username"] = True
            elif finding.entity_type == EntityType.DOMAIN:
                signals["domain"] = True
            elif finding.entity_type == EntityType.IP_ADDRESS:
                signals["ip"] = True
            elif finding.entity_type == EntityType.PERSON:
                signals["person_name"] = True

            details = finding.details or {}
            if "github" in finding.source.url.lower() or "github" in str(details):
                signals["github"] = True
            if "linkedin" in finding.source.url.lower() or "linkedin" in str(details):
                signals["linkedin"] = True

        filled = sum(1 for v in signals.values() if v)
        total = len(signals)
        score = filled / total if total > 0 else 0.0

        finding = Finding(
            entity_type=EntityType.PERSON,
            entity_value=case.name or "target",
            label=f"Profile Completeness: {score:.0%}",
            summary=f"Profile has {filled}/{total} signal types: {', '.join(k for k, v in signals.items() if v)}",
            details={"signals": signals, "score": score, "filled": filled, "total": total},
            source=Source(
                url="internal://plugin/profile_completeness",
                title="Profile Completeness Scorer",
                source_type="internal_plugin",
                reliability=1.0,
            ),
            confidence=Confidence(score=1.0, reasoning="Internal analysis"),
        )
        finding.confidence.compute_level()

        return [finding]

    def on_report(self, case: Case, report: dict) -> dict:
        """Add completeness section to report."""
        for finding in case.findings:
            if finding.label.startswith("Profile Completeness"):
                report["completeness_score"] = finding.details.get("score", 0)
                report["completeness_signals"] = finding.details.get("signals", {})
                break
        return report
