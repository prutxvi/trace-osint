"""TRACE OSINT - PACER Court Records Intelligence"""

import json
import urllib.request
import urllib.parse
from typing import Optional

from src.models import Finding, Source, EntityType, Confidence


def pacer_search(query: str) -> list[dict]:
    """Search PACER for court records."""
    try:
        encoded = urllib.parse.quote(query)
        url = f"https://www.pacer.gov/cgi-bin/login.pl"
        return [{
            "source": "PACER",
            "query": query,
            "note": "PACER requires login for full access",
            "search_url": f"https://ecf.{''}.uscourts.gov/cgi-bin/login.pl",
            "public_url": f"https://www.pacer.gov/previous-versions/free-look",
        }]
    except Exception:
        return []


def indiakanoon_search(query: str, limit: int = 10) -> list[dict]:
    """Search India Kanoon for court judgments."""
    try:
        encoded = urllib.parse.quote(query)
        url = f"https://indiankanoon.org/search/?formInput={encoded}"
        return [{
            "source": "India Kanoon",
            "query": query,
            "url": url,
            "note": "Free access to Indian court judgments",
        }]
    except Exception:
        return []


def get_court_intelligence(query: str) -> list[Finding]:
    """Gather court records intelligence."""
    findings = []

    pacer_results = pacer_search(query)
    if pacer_results:
        finding = Finding(
            entity_type=EntityType.PERSON,
            entity_value=query,
            label=f"Court Records: {query}",
            summary=f"PACER search available for '{query}'",
            details={"pacer": pacer_results},
            source=Source(
                url="https://www.pacer.gov",
                title="PACER Federal Courts",
                source_type="public_registry",
                reliability=0.9,
            ),
            confidence=Confidence(score=0.9, reasoning="Federal court records reference"),
        )
        finding.confidence.compute_level()
        findings.append(finding)

    in_results = indiakanoon_search(query)
    if in_results:
        in_finding = Finding(
            entity_type=EntityType.PERSON,
            entity_value=query,
            label=f"India Kanoon: {query}",
            summary=f"Indian court judgment search available for '{query}'",
            details={"indiakanoon": in_results},
            source=Source(
                url="https://indiankanoon.org",
                title="India Kanoon",
                source_type="public_registry",
                reliability=0.85,
            ),
            confidence=Confidence(score=0.85, reasoning="Indian court judgment search"),
        )
        in_finding.confidence.compute_level()
        findings.append(in_finding)

    return findings
