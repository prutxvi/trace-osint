"""TRACE OSINT - Public LinkedIn profile extractor."""

from __future__ import annotations

from src.models import Confidence, EntityType, Finding, Source
from src.parsers.metadata_parse import extract_all_metadata
from src.sources.fetch import fetch_public_url
from src.sources.normalize import normalize_url


def get_linkedin_profile_intelligence(url: str) -> list[Finding]:
    """Extract public profile signals from a LinkedIn profile URL."""
    result = fetch_public_url(url)
    if not result:
        return []

    html = result["content"]
    metadata = extract_all_metadata(html)
    meta = metadata.get("meta", {})
    og = metadata.get("open_graph", {})

    title = og.get("title") or metadata.get("title", "")
    details = {
        "url": normalize_url(url),
        "name": _split_title(title, 0),
        "headline": og.get("description") or meta.get("description", ""),
        "company": _extract_company(og.get("description") or meta.get("description", "")),
        "location": _extract_location(meta.get("description", "")),
        "education": "",
        "avatar_url": og.get("image", ""),
        "website_links": [],
        "bio": og.get("description") or meta.get("description", ""),
        "profile_platform": "linkedin",
        "social_profiles": {"linkedin": [normalize_url(url)]},
    }

    finding = Finding(
        entity_type=EntityType.PERSON,
        entity_value=normalize_url(url),
        label=f"LinkedIn Profile: {details['name'] or url}",
        summary=details.get("headline") or "Public LinkedIn profile extracted",
        details=details,
        source=Source(
            url=url,
            title=title or "LinkedIn Profile",
            source_type="public_profile",
            reliability=0.85,
        ),
        confidence=Confidence(score=0.82, reasoning="Direct public LinkedIn profile extraction"),
    )
    finding.confidence.compute_level()
    return [finding]


def _split_title(title: str, index: int) -> str:
    parts = [part.strip() for part in title.split("|") if part.strip()]
    if not parts:
        return ""
    return parts[index] if len(parts) > index else parts[0]


def _extract_company(text: str) -> str:
    if " at " in text:
        return text.split(" at ", 1)[-1].split(".", 1)[0].strip()
    return ""


def _extract_location(text: str) -> str:
    parts = [part.strip() for part in text.split("|") if part.strip()]
    if len(parts) >= 2:
        return parts[-1]
    return ""
