# -*- coding: utf-8 -*-
from __future__ import annotations
"""TRACE OSINT - Wikidata Entity Intelligence"""

import json
import urllib.request
import urllib.parse
from typing import Optional

from src.models import Finding, Source, EntityType, Confidence


WIKIDATA_PROPERTIES = {
    "P31": "instance of",
    "P27": "country of citizenship",
    "P19": "place of birth",
    "P20": "place of death",
    "P26": "spouse",
    "P25": "mother",
    "P22": "father",
    "P3373": "sibling",
    "P106": "occupation",
    "P108": "employer",
    "P69": "educated at",
    "P1412": "languages spoken",
    "P18": "image",
    "P569": "date of birth",
    "P570": "date of death",
    "P147": "website",
    "P2002": "Twitter username",
    "P2003": "Instagram username",
    "P4033": "YouTube channel ID",
    "P2397": "YouTube username",
    "P2600": "Github username",
    "P3984": "Reddit username",
    "P6634": "Facebook username",
    "P4175": "Telegram username",
}


def wikidata_search(query: str, limit: int = 10) -> list[dict]:
    """Search Wikidata for entities."""
    try:
        url = "https://www.wikidata.org/w/api.php"
        params = {
            "action": "wbsearchentities",
            "search": query,
            "language": "en",
            "format": "json",
            "limit": limit,
        }
        full_url = f"{url}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(full_url, headers={"User-Agent": "TRACE-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("search", [])
    except Exception:
        return []


def wikidata_entity(entity_id: str) -> dict:
    """Get full entity data from Wikidata."""
    try:
        url = f"https://www.wikidata.org/w/api.php?action=wbgetentities&ids={entity_id}&format=json&props=labels|descriptions|claims"
        req = urllib.request.Request(url, headers={"User-Agent": "TRACE-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return {}


def _extract_claims(claims: dict) -> dict:
    """Extract human-readable claims from Wikidata."""
    result = {}
    for prop_id, prop_claims in claims.items():
        prop_name = WIKIDATA_PROPERTIES.get(prop_id, prop_id)
        values = []
        for claim in prop_claims[:5]:
            mainsnak = claim.get("mainsnak", {})
            datavalue = mainsnak.get("datavalue", {})
            value = datavalue.get("value", {})

            if datavalue.get("type") == "wikibase-entityid":
                values.append(f"Q{value.get('numeric-id', '')}")
            elif datavalue.get("type") == "string":
                values.append(str(value))
            elif datavalue.get("type") == "time":
                values.append(value.get("time", ""))
            elif datavalue.get("type") == "monolingualtext":
                values.append(value.get("text", ""))

        if values:
            result[prop_name] = values
    return result


def get_wikidata_intelligence(query: str) -> list[Finding]:
    """Gather Wikidata intelligence on a query."""
    findings = []

    results = wikidata_search(query)
    if results:
        for entity_data in results[:3]:
            entity_id = entity_data.get("id", "")
            label = entity_data.get("label", "")
            description = entity_data.get("description", "")
            concept_url = entity_data.get("concepturi", "")

            full_entity = wikidata_entity(entity_id) if entity_id else {}
            entity_info = full_entity.get("entities", {}).get(entity_id, {})
            claims = entity_info.get("claims", {})
            parsed_claims = _extract_claims(claims) if claims else {}

            etype = EntityType.PERSON
            if any(v in str(parsed_claims.get("instance of", [])) for v in ["Q43287", "Q783794"]):
                etype = EntityType.ORGANIZATION

            finding = Finding(
                entity_type=etype,
                entity_value=label,
                label=f"Wikidata: {label}",
                summary=f"{description} | ID: {entity_id}",
                details={
                    "wikidata_id": entity_id,
                    "label": label,
                    "description": description,
                    "concept_uri": concept_url,
                    "url": f"https://www.wikidata.org/wiki/{entity_id}",
                    "claims": parsed_claims,
                    "social_profiles": {
                        "twitter": parsed_claims.get("Twitter username", []),
                        "instagram": parsed_claims.get("Instagram username", []),
                        "github": parsed_claims.get("Github username", []),
                        "reddit": parsed_claims.get("Reddit username", []),
                        "facebook": parsed_claims.get("Facebook username", []),
                        "telegram": parsed_claims.get("Telegram username", []),
                        "youtube": parsed_claims.get("YouTube channel ID", []),
                    },
                    "biographical": {
                        "occupation": parsed_claims.get("occupation", []),
                        "employer": parsed_claims.get("employer", []),
                        "education": parsed_claims.get("educated at", []),
                        "birth_place": parsed_claims.get("place of birth", []),
                        "citizenship": parsed_claims.get("country of citizenship", []),
                        "spouse": parsed_claims.get("spouse", []),
                        "website": parsed_claims.get("website", []),
                    },
                },
                source=Source(
                    url=f"https://www.wikidata.org/wiki/{entity_id}",
                    title=f"Wikidata {label}",
                    source_type="public_api",
                    reliability=0.95,
                ),
                confidence=Confidence(score=0.95, reasoning="Wikidata structured knowledge base"),
            )
            finding.confidence.compute_level()
            findings.append(finding)

    return findings
