"""TRACE OSINT - Generic public profile and portfolio extractor."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from src.models import Confidence, EntityType, Finding, Source
from src.parsers.metadata_parse import extract_all_metadata
from src.sources.fetch import fetch_public_url
from src.sources.normalize import normalize_url


def extract_profile_page_intelligence(url: str) -> list[Finding]:
    """Extract person-facing signals from a public page."""
    result = fetch_public_url(url)
    if not result:
        return []

    html = result["content"]
    metadata = extract_all_metadata(html)
    details = _extract_profile_details(url, html, metadata)

    finding = Finding(
        entity_type=EntityType.PERSON if details.get("name") else EntityType.URL,
        entity_value=normalize_url(url),
        label=f"Profile Page: {details.get('name') or details.get('title') or url}",
        summary=details.get("summary") or "Public profile-like page extracted",
        details=details,
        source=Source(
            url=url,
            title=details.get("title") or details.get("name") or url,
            source_type="public_profile_page",
            reliability=0.8,
        ),
        confidence=Confidence(score=0.75, reasoning="Structured public profile page extraction"),
    )
    finding.confidence.compute_level()
    return [finding]


def _extract_profile_details(url: str, html: str, metadata: dict) -> dict:
    meta = metadata.get("meta", {})
    og = metadata.get("open_graph", {})
    json_ld = metadata.get("json_ld", [])

    name = (
        og.get("title")
        or meta.get("author")
        or _pick_json_ld_value(json_ld, "name")
        or metadata.get("title", "")
    )
    summary = (
        meta.get("description")
        or og.get("description")
        or _pick_json_ld_value(json_ld, "description")
        or ""
    )
    role = _first_match(html, [r"<h2[^>]*>([^<]{2,80})</h2>", r"<p[^>]*class=\"[^\"]*(headline|role|title)[^\"]*\"[^>]*>([^<]{2,120})</p>"])
    emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", html)
    phones = re.findall(r"\+?\d[\d\s\-()]{7,}\d", html)
    social_links = _extract_social_links(url, html)
    website_links = _extract_external_links(url, html)
    avatar_url = og.get("image") or _pick_json_ld_value(json_ld, "image") or ""
    location = _pick_json_ld_value(json_ld, "addressLocality") or _pick_json_ld_value(json_ld, "addressCountry") or ""

    return {
        "url": normalize_url(url),
        "title": metadata.get("title", ""),
        "name": _clean_text(name),
        "role": _clean_text(role),
        "summary": _clean_text(summary),
        "bio": _clean_text(summary),
        "email": emails[0] if emails else "",
        "emails": list(dict.fromkeys(emails[:5])),
        "phone": phones[0] if phones else "",
        "phones": list(dict.fromkeys(phone.strip() for phone in phones[:5])),
        "location": _clean_text(location),
        "avatar_url": avatar_url,
        "website_links": website_links[:10],
        "social_profiles": social_links,
    }


def _extract_social_links(base_url: str, html: str) -> dict:
    links = _extract_links(base_url, html)
    social = {}
    for link in links:
        if "github.com" in link:
            social.setdefault("github", []).append(link)
        elif "linkedin.com" in link:
            social.setdefault("linkedin", []).append(link)
        elif "twitter.com" in link or "x.com" in link:
            social.setdefault("twitter", []).append(link)
        elif "instagram.com" in link:
            social.setdefault("instagram", []).append(link)
    return social


def _extract_external_links(base_url: str, html: str) -> list[str]:
    base_host = normalize_url(base_url).split("//", 1)[-1].split("/", 1)[0]
    return [link for link in _extract_links(base_url, html) if base_host not in link]


def _extract_links(base_url: str, html: str) -> list[str]:
    hrefs = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
    output = []
    for href in hrefs:
        if href.startswith("mailto:") or href.startswith("tel:") or href.startswith("#"):
            continue
        absolute = urljoin(base_url, href)
        output.append(absolute)
    return list(dict.fromkeys(output))


def _pick_json_ld_value(items: list[dict], key: str) -> str:
    for item in items:
        if isinstance(item, dict):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, dict):
                for nested in ("url", "name"):
                    nested_value = value.get(nested)
                    if isinstance(nested_value, str) and nested_value.strip():
                        return nested_value.strip()
    return ""


def _first_match(html: str, patterns: list[str]) -> str:
    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            groups = [group for group in match.groups() if group and group.lower() not in {"headline", "role", "title"}]
            if groups:
                return groups[-1]
    return ""


def _clean_text(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()
