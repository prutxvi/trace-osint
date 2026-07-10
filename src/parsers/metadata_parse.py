from __future__ import annotations
"""TRACE OSINT Copilot - Metadata Parsing Module"""

import re
import json
from typing import Optional


def extract_meta_tags(html: str) -> dict[str, str]:
    """Extract meta tag key-value pairs from HTML."""
    meta = {}
    pattern = r'<meta\s+[^>]*?name=["\']([^"\']+)["\'][^>]*?content=["\']([^"\']+)["\']'
    for match in re.finditer(pattern, html, re.IGNORECASE):
        meta[match.group(1).lower()] = match.group(2)

    pattern2 = r'<meta\s+[^>]*?content=["\']([^"\']+)["\'][^>]*?name=["\']([^"\']+)["\']'
    for match in re.finditer(pattern2, html, re.IGNORECASE):
        meta[match.group(2).lower()] = match.group(1)

    return meta


def extract_open_graph(html: str) -> dict[str, str]:
    """Extract Open Graph metadata."""
    og = {}
    pattern = r'<meta\s+[^>]*?property=["\']og:([^"\']+)["\'][^>]*?content=["\']([^"\']+)["\']'
    for match in re.finditer(pattern, html, re.IGNORECASE):
        og[match.group(1)] = match.group(2)
    return og


def extract_twitter_card(html: str) -> dict[str, str]:
    """Extract Twitter Card metadata."""
    tc = {}
    pattern = r'<meta\s+[^>]*?name=["\']twitter:([^"\']+)["\'][^>]*?content=["\']([^"\']+)["\']'
    for match in re.finditer(pattern, html, re.IGNORECASE):
        tc[match.group(1)] = match.group(2)
    return tc


def extract_json_ld(html: str) -> list[dict]:
    """Extract JSON-LD structured data."""
    pattern = r'<script\s+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>'
    matches = re.findall(pattern, html, re.DOTALL | re.IGNORECASE)
    results = []
    for match in matches:
        try:
            data = json.loads(match)
            results.append(data)
        except json.JSONDecodeError:
            continue
    return results


def extract_page_title(html: str) -> str:
    """Extract page title."""
    match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def extract_canonical_url(html: str) -> str:
    """Extract canonical URL."""
    pattern = r'<link\s+[^>]*?rel=["\']canonical["\'][^>]*?href=["\']([^"\']+)["\']'
    match = re.search(pattern, html, re.IGNORECASE)
    return match.group(1) if match else ""


def extract_robots_meta(html: str) -> dict[str, str]:
    """Extract robots directives."""
    meta = extract_meta_tags(html)
    robots = {}
    for key in ["robots", "googlebot", "bingbot"]:
        if key in meta:
            robots[key] = meta[key]
    return robots


def extract_language(html: str) -> str:
    """Extract document language."""
    match = re.search(r'<html[^>]*\slang=["\']([^"\']+)["\']', html, re.IGNORECASE)
    return match.group(1) if match else ""


def extract_all_metadata(html: str) -> dict:
    """Extract all available metadata from HTML."""
    return {
        "title": extract_page_title(html),
        "canonical": extract_canonical_url(html),
        "language": extract_language(html),
        "meta": extract_meta_tags(html),
        "open_graph": extract_open_graph(html),
        "twitter_card": extract_twitter_card(html),
        "json_ld": extract_json_ld(html),
        "robots": extract_robots_meta(html),
    }
