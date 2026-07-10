from __future__ import annotations
"""TRACE OSINT - Indian Public Records Intelligence"""

import json
import urllib.request
import urllib.parse
from typing import Optional

from src.models import Finding, Source, EntityType, Confidence


def mca_company_search(company_name: str) -> list[dict]:
    """Search Ministry of Corporate Affairs for company info."""
    try:
        url = f"https://www.mca.gov.in/content/mca/global/en/data-and-reports/incorporation.html"
        return [{
            "source": "MCA",
            "query": company_name,
            "note": "Visit mca.gov.in for direct company search",
            "search_url": f"https://www.mca.gov.in/content/mca/global/en/data-and-reports/incorporation/company-llp-find.html",
        }]
    except Exception:
        return []


def search_india_kanoon(query: str, limit: int = 10) -> list[dict]:
    """Search India Kanoon for court judgments."""
    try:
        encoded_query = urllib.parse.quote(query)
        url = f"https://api.indiakanoon.org/search/?formInput={encoded_query}&pagesize={limit}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "TRACE-OSINT/1.0",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            results = data.get("results", [])
            return [
                {
                    "title": r.get("title", ""),
                    "docid": r.get("docid", ""),
                    "doctitle": r.get("doctitle", ""),
                    "publishdate": r.get("publishdate", ""),
                    "source": r.get("source", ""),
                }
                for r in results[:limit]
            ]
    except Exception:
        return []


def search_ecourts(query: str) -> list[dict]:
    """Search eCourts India for case information."""
    try:
        return [{
            "source": "eCourts",
            "query": query,
            "note": "Visit ecourts.gov.in for case search",
            "search_url": f"https://ecourts.gov.in/ecourts_home/",
        }]
    except Exception:
        return []


def indian_phone_lookup(phone: str) -> dict:
    """Lookup Indian phone number details."""
    cleaned = phone.replace("+91", "").replace("91", "").replace("-", "").replace(" ", "")

    carrier_map = {
        "6": "Jio", "7": "Airtel/Vi", "8": "Airtel/Vi", "9": "Airtel/Vi",
    }

    operator_codes = {
        "98": "Airtel", "99": "Airtel", "97": "Airtel", "96": "Airtel",
        "90": "Vi (Vodafone Idea)", "91": "Vi (Vodafone Idea)", "92": "Vi (Vodafone Idea)",
        "93": "BSNL", "94": "BSNL", "95": "BSNL",
        "70": "Jio", "71": "Jio", "72": "Jio", "73": "Jio", "74": "Jio",
        "75": "Jio", "76": "Jio", "77": "Jio", "78": "Jio", "79": "Jio",
    }

    state_codes = {
        "98": "Delhi/NCR", "99": "Delhi/NCR",
        "70": "Multiple States", "71": "Multiple States",
        "90": "Maharashtra", "91": "Maharashtra",
        "92": "Andhra Pradesh/Telangana",
        "93": "Gujarat", "94": "Tamil Nadu", "95": "Karnataka",
        "96": "Rajasthan", "97": "UP/West UP",
        "98": "Delhi/NCR", "99": "Delhi/NCR",
    }

    carrier = "Unknown"
    for prefix, name in operator_codes.items():
        if cleaned.startswith(prefix):
            carrier = name
            break

    state = "Unknown"
    for prefix, name in state_codes.items():
        if cleaned.startswith(prefix):
            state = name
            break

    return {
        "phone": phone,
        "cleaned": cleaned,
        "country": "India",
        "carrier": carrier,
        "state": "Unknown",
        "line_type": "Mobile" if len(cleaned) == 10 else "Unknown",
        "valid": len(cleaned) == 10 and cleaned[0] in "6789",
    }


def get_india_intelligence(query: str, entity_type: str = "person") -> list[Finding]:
    """Gather Indian public records intelligence."""
    findings = []

    court_results = search_india_kanoon(query)
    if court_results:
        court_finding = Finding(
            entity_type=EntityType.PERSON if entity_type == "person" else EntityType.ORGANIZATION,
            entity_value=query,
            label=f"India Kanoon: {query}",
            summary=f"Found {len(court_results)} court judgment(s) matching '{query}'",
            details={"judgments": court_results[:5]},
            source=Source(
                url=f"https://indiahinkanoon.org/search/?formInput={urllib.parse.quote(query)}",
                title="India Kanoon Court Records",
                source_type="public_registry",
                reliability=0.85,
            ),
            confidence=Confidence(score=0.85, reasoning="Public court judgment search"),
        )
        court_finding.confidence.compute_level()
        findings.append(court_finding)

    mca_results = mca_company_search(query)
    if mca_results and entity_type == "organization":
        mca_finding = Finding(
            entity_type=EntityType.ORGANIZATION,
            entity_value=query,
            label=f"MCA Company Search: {query}",
            summary=f"Company search available on MCA portal",
            details={"mca": mca_results},
            source=Source(
                url="https://www.mca.gov.in/content/mca/global/en/data-and-reports/incorporation/company-llp-find.html",
                title="MCA Company Search",
                source_type="public_registry",
                reliability=0.9,
            ),
            confidence=Confidence(score=0.9, reasoning="Government registry reference"),
        )
        mca_finding.confidence.compute_level()
        findings.append(mca_finding)

    ecourt_results = search_ecourts(query)
    if ecourt_results:
        ecourt_finding = Finding(
            entity_type=EntityType.PERSON if entity_type == "person" else EntityType.ORGANIZATION,
            entity_value=query,
            label=f"eCourts: {query}",
            summary=f"eCourts search available for '{query}'",
            details={"ecourts": ecourt_results},
            source=Source(
                url="https://ecourts.gov.in/ecourts_home/",
                title="eCourts India",
                source_type="public_registry",
                reliability=0.9,
            ),
            confidence=Confidence(score=0.9, reasoning="Government court portal reference"),
        )
        ecourt_finding.confidence.compute_level()
        findings.append(ecourt_finding)

    return findings
