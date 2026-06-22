"""TRACE OSINT - TruePeopleSearch Person Intelligence"""

import re
import urllib.request
import urllib.parse
from typing import Optional

from src.models import Finding, Source, EntityType, Confidence


def truepeoplesearch_by_name(name: str) -> list[dict]:
    """Search TruePeopleSearch by name."""
    try:
        encoded = urllib.parse.quote(name.lower().replace(" ", "-"))
        url = f"https://www.truepeoplesearch.com/results?name={encoded}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")
            return _parse_truepeoplesearch_results(html)
    except Exception:
        return []


def truepeoplesearch_by_phone(phone: str) -> list[dict]:
    """Search TruePeopleSearch by phone number."""
    try:
        cleaned = phone.replace("+", "").replace("-", "").replace(" ", "")
        url = f"https://www.truepeoplesearch.com/results?phone={cleaned}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")
            return _parse_truepeoplesearch_results(html)
    except Exception:
        return []


def truepeoplesearch_by_email(email: str) -> list[dict]:
    """Search TruePeopleSearch by email."""
    try:
        encoded = urllib.parse.quote(email)
        url = f"https://www.truepeoplesearch.com/results?email={encoded}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")
            return _parse_truepeoplesearch_results(html)
    except Exception:
        return []


def _parse_truepeoplesearch_results(html: str) -> list[dict]:
    """Parse TruePeopleSearch HTML results."""
    results = []

    name_pattern = r'"name"\s*:\s*"([^"]+)"'
    age_pattern = r'"age"\s*:\s*(\d+)'
    location_pattern = r'"location"\s*:\s*"([^"]+)"'
    relatives_pattern = r'"relatives"\s*:\s*\[([^\]]*)\]'

    names = re.findall(name_pattern, html, re.IGNORECASE)
    ages = re.findall(age_pattern, html)
    locations = re.findall(location_pattern, html, re.IGNORECASE)

    for i in range(min(len(names), 5)):
        result = {
            "name": names[i] if i < len(names) else "",
            "age": ages[i] if i < len(ages) else "",
            "location": locations[i] if i < len(locations) else "",
        }
        results.append(result)

    return results


def get_truepeoplesearch_intelligence(query: str, search_type: str = "auto") -> list[Finding]:
    """Gather TruePeopleSearch intelligence."""
    findings = []

    if search_type == "auto":
        if re.match(r"^[^@]+@[^@]+\.[^@]+$", query):
            search_type = "email"
        elif re.match(r"^\+?[\d\s\-()]{10,}$", query):
            search_type = "phone"
        else:
            search_type = "name"

    if search_type == "email":
        results = truepeoplesearch_by_email(query)
    elif search_type == "phone":
        results = truepeoplesearch_by_phone(query)
    else:
        results = truepeoplesearch_by_name(query)

    if results:
        for person in results[:3]:
            finding = Finding(
                entity_type=EntityType.PERSON,
                entity_value=person.get("name", query),
                label=f"Person: {person.get('name', 'N/A')}",
                summary=f"Age: {person.get('age', 'N/A')} | "
                        f"Location: {person.get('location', 'N/A')}",
                details={
                    "name": person.get("name", ""),
                    "age": person.get("age", ""),
                    "location": person.get("location", ""),
                    "search_type": search_type,
                    "query": query,
                },
                source=Source(
                    url=f"https://www.truepeoplesearch.com/results?name={urllib.parse.quote(query)}",
                    title="TruePeopleSearch",
                    source_type="public_registry",
                    reliability=0.7,
                ),
                confidence=Confidence(score=0.7, reasoning="People search aggregator"),
            )
            finding.confidence.compute_level()
            findings.append(finding)

    return findings
