"""TRACE OSINT - OpenCorporates Company Intelligence"""

import json
import urllib.request
import urllib.parse
from typing import Optional

from src.models import Finding, Source, EntityType, Confidence


def opencorporates_search(query: str, jurisdiction: str = "", page: int = 1) -> list[dict]:
    """Search OpenCorporates for companies."""
    try:
        params = {"q": query, "page": page}
        if jurisdiction:
            params["jurisdiction_code"] = jurisdiction
        url = f"https://api.opencorporates.com/v0.4/companies/search?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers={"User-Agent": "TRACE-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("results", {}).get("companies", [])
    except Exception:
        return []


def opencorporates_company(company_number: str, jurisdiction: str = "in") -> dict:
    """Get company details from OpenCorporates."""
    try:
        url = f"https://api.opencorporates.com/v0.4/companies/{jurisdiction}/{company_number}"
        req = urllib.request.Request(url, headers={"User-Agent": "TRACE-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("results", {}).get("company", {})
    except Exception:
        return {}


def opencorporates_officers(company_number: str, jurisdiction: str = "in") -> list[dict]:
    """Get company officers from OpenCorporates."""
    try:
        url = f"https://api.opencorporates.com/v0.4/companies/{jurisdiction}/{company_number}/officers"
        req = urllib.request.Request(url, headers={"User-Agent": "TRACE-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("results", {}).get("officers", [])
    except Exception:
        return []


def get_opencorporates_intelligence(query: str) -> list[Finding]:
    """Gather OpenCorporates intelligence on a company."""
    findings = []

    companies = opencorporates_search(query)
    if companies:
        for company_data in companies[:5]:
            company = company_data.get("company", {})
            company_number = company.get("company_number", "")
            jurisdiction = company.get("jurisdiction_code", "")

            finding = Finding(
                entity_type=EntityType.ORGANIZATION,
                entity_value=company.get("name", query),
                label=f"Company: {company.get('name', 'N/A')}",
                summary=f"Status: {company.get('current_status', 'N/A')} | "
                        f"Incorporated: {company.get('incorporation_date', 'N/A')} | "
                        f"Jurisdiction: {jurisdiction.upper()} | "
                        f"Number: {company_number}",
                details={
                    "name": company.get("name", ""),
                    "company_number": company_number,
                    "jurisdiction": jurisdiction,
                    "status": company.get("current_status", ""),
                    "incorporation_date": company.get("incorporation_date", ""),
                    "dissolution_date": company.get("dissolution_date", ""),
                    "type": company.get("company_type", ""),
                    "registered_address": company.get("registered_address_in_full", ""),
                    "url": company.get("opencorporates_url", ""),
                },
                source=Source(
                    url=company.get("opencorporates_url", f"https://opencorporates.com/companies/{jurisdiction}/{company_number}"),
                    title=f"OpenCorporates {company.get('name', '')}",
                    source_type="public_registry",
                    reliability=0.9,
                ),
                confidence=Confidence(score=0.9, reasoning="Official company registry data"),
            )
            finding.confidence.compute_level()
            findings.append(finding)

            if company_number and jurisdiction:
                officers = opencorporates_officers(company_number, jurisdiction)
                if officers:
                    officer_finding = Finding(
                        entity_type=EntityType.ORGANIZATION,
                        entity_value=company.get("name", query),
                        label=f"Officers: {company.get('name', 'N/A')}",
                        summary=f"Found {len(officers)} officer(s) for {company.get('name', '')}",
                        details={
                            "company": company.get("name", ""),
                            "officers": [
                                {
                                    "name": o.get("name", ""),
                                    "position": o.get("position", ""),
                                    "start_date": o.get("start_date", ""),
                                    "end_date": o.get("end_date", ""),
                                }
                                for o in officers[:20]
                            ],
                        },
                        source=Source(
                            url=f"https://opencorporates.com/companies/{jurisdiction}/{company_number}/officers",
                            title=f"Officers {company.get('name', '')}",
                            source_type="public_registry",
                            reliability=0.9,
                        ),
                        confidence=Confidence(score=0.9, reasoning="Official company officer records"),
                    )
                    officer_finding.confidence.compute_level()
                    findings.append(officer_finding)

    return findings
