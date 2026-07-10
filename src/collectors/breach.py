from __future__ import annotations
"""TRACE OSINT - Breach Intelligence"""

import json
import urllib.request
import urllib.parse
from typing import Optional

from src.models import Finding, Source, EntityType, Confidence


def breachdirectory_search(email: str) -> list[dict]:
    """Search BreachDirectory for email breaches."""
    try:
        url = f"https://breachdirectory.org/api/search?email={email}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "TRACE-OSINT/1.0",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("result", [])
    except Exception:
        return []


def leakcheck_search(email: str) -> dict:
    """Check LeakCheck for breaches."""
    try:
        url = f"https://leakcheck.io/api/public?check={email}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "TRACE-OSINT/1.0",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return {
                "found": data.get("found", False),
                "breaches": data.get("breaches", []),
            }
    except Exception:
        return {"found": False, "breaches": []}


def get_breach_intelligence(email: str) -> list[Finding]:
    """Gather breach intelligence on an email."""
    findings = []

    bd_results = breachdirectory_search(email)
    if bd_results:
        finding = Finding(
            entity_type=EntityType.EMAIL,
            entity_value=email,
            label=f"Breach Data: {email}",
            summary=f"Found in {len(bd_results)} breach(es)",
            details={
                "source": "BreachDirectory",
                "breaches": [
                    {
                        "name": b.get("name", ""),
                        "date": b.get("date", ""),
                        "records": b.get("records", ""),
                        "data_classes": b.get("data_classes", []),
                    }
                    for b in bd_results[:10]
                ],
            },
            source=Source(
                url="https://breachdirectory.org",
                title="BreachDirectory",
                source_type="public_api",
                reliability=0.8,
            ),
            confidence=Confidence(score=0.8, reasoning="Breach directory lookup"),
        )
        finding.confidence.compute_level()
        findings.append(finding)

    lc_result = leakcheck_search(email)
    if lc_result.get("found"):
        lc_finding = Finding(
            entity_type=EntityType.EMAIL,
            entity_value=email,
            label=f"LeakCheck: {email}",
            summary=f"Found in {len(lc_result.get('breaches', []))} breach(es)",
            details={
                "source": "LeakCheck",
                "breaches": lc_result.get("breaches", []),
            },
            source=Source(
                url="https://leakcheck.io",
                title="LeakCheck",
                source_type="public_api",
                reliability=0.8,
            ),
            confidence=Confidence(score=0.8, reasoning="LeakCheck breach lookup"),
        )
        lc_finding.confidence.compute_level()
        findings.append(lc_finding)

    return findings
