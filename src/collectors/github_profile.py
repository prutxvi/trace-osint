# -*- coding: utf-8 -*-
"""TRACE OSINT - GitHub profile extractor."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

from src.models import Confidence, EntityType, Finding, Source
from src.sources.normalize import normalize_url, normalize_username


def get_github_profile_intelligence(value: str) -> list[Finding]:
    """Extract a public GitHub profile into structured person fields."""
    username = _extract_username(value)
    if not username:
        return []

    user = _fetch_json(f"https://api.github.com/users/{urllib.parse.quote(username)}")
    if not user:
        return []

    repos = _fetch_json(f"https://api.github.com/users/{urllib.parse.quote(username)}/repos?per_page=6&sort=updated") or []
    details = {
        "username": user.get("login", username),
        "name": user.get("name", ""),
        "display_name": user.get("name", ""),
        "avatar_url": user.get("avatar_url", ""),
        "bio": user.get("bio", ""),
        "location": user.get("location", ""),
        "website": user.get("blog", ""),
        "profile_url": user.get("html_url", f"https://github.com/{username}"),
        "company": user.get("company", ""),
        "main_handle": user.get("login", username),
        "repos": [repo.get("full_name", "") for repo in repos],
        "projects": [repo.get("full_name", "") for repo in repos],
        "languages": sorted({repo.get("language") for repo in repos if repo.get("language")}),
        "topics": sorted({topic for repo in repos for topic in repo.get("topics", [])}),
        "social_profiles": {"github": [user.get("html_url", f"https://github.com/{username}")]},
        "website_links": [user.get("blog")] if user.get("blog") else [],
    }

    finding = Finding(
        entity_type=EntityType.PERSON,
        entity_value=user.get("html_url", f"https://github.com/{username}"),
        label=f"GitHub Profile: {user.get('login', username)}",
        summary=user.get("bio") or f"GitHub profile for {user.get('login', username)}",
        details=details,
        source=Source(
            url=user.get("html_url", f"https://github.com/{username}"),
            title=f"GitHub Profile {user.get('login', username)}",
            source_type="public_api",
            reliability=0.95,
        ),
        confidence=Confidence(score=0.92, reasoning="Direct GitHub profile API extraction"),
    )
    finding.confidence.compute_level()
    return [finding]


def _extract_username(value: str) -> str:
    value = value.strip()
    if value.startswith("http"):
        normalized = normalize_url(value)
        parts = [part for part in normalized.split("github.com/")[-1].split("/") if part]
        return normalize_username(parts[0]) if parts else ""
    return normalize_username(value)


def _fetch_json(url: str):
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "TRACE-OSINT/1.0",
            "Accept": "application/vnd.github+json",
        })
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None
