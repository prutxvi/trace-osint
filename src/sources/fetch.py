# -*- coding: utf-8 -*-
from __future__ import annotations
"""TRACE OSINT Copilot - Public Web Fetch Module"""

import json
import urllib.parse
import urllib.request
from typing import Optional

from src.config import get_env, REQUEST_TIMEOUT_SECONDS, MAX_RETRIES, RETRY_DELAY_SECONDS
from src.models import Finding, Source, EntityType, Confidence


def fetch_public_url(url: str) -> Optional[dict]:
    """
    Fetch a public URL using ScraperAPI or direct request.
    Returns dict with 'content' and 'status' or None on failure.
    """
    scraper_key = get_env("SCRAPERAPI_KEY")
    browserless_token = get_env("BROWSERLESS_TOKEN")

    target_url = url

    if scraper_key:
        target_url = (
            f"https://api.scraperapi.com/"
            f"?api_key={scraper_key}"
            f"&url={urllib.parse.quote(url)}"
            f"&render=false"
        )
    elif browserless_token:
        target_url = f"https://wss.browserless.io/content?token={browserless_token}"

    headers = {
        "User-Agent": "TRACE-OSINT/1.0 (Public Source Research Tool)",
        "Accept": "text/html,application/json",
    }

    if browserless_token:
        headers["Content-Type"] = "application/json"

    for attempt in range(MAX_RETRIES):
        try:
            data = None
            if browserless_token:
                payload = json.dumps({
                    "url": url,
                    "waitFor": 2000,
                }).encode("utf-8")
            else:
                payload = None

            req = urllib.request.Request(
                target_url,
                data=payload,
                headers=headers,
                method="POST" if browserless_token else "GET",
            )
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                content = resp.read().decode("utf-8", errors="replace")
                return {
                    "content": content,
                    "status": resp.status,
                    "url": url,
                }
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                import time
                time.sleep(RETRY_DELAY_SECONDS)
            else:
                return None

    return None


def fetch_url_as_finding(
    url: str,
    entity_type: EntityType = EntityType.URL,
    entity_value: str = "",
) -> Optional[Finding]:
    """Fetch a URL and return it as a structured Finding."""
    result = fetch_public_url(url)
    if not result:
        return None

    content = result["content"]
    title = _extract_title(content)
    summary = _extract_meta_description(content)

    finding = Finding(
        entity_type=entity_type,
        entity_value=entity_value or url,
        label=f"Fetched: {title[:60] if title else url[:60]}",
        summary=summary[:300] if summary else f"Page retrieved successfully ({len(content)} bytes)",
        details={
            "url": url,
            "title": title,
            "content_length": len(content),
            "status_code": result["status"],
            "content_preview": content[:500],
        },
        source=Source(
            url=url,
            title=title,
            source_type="public_webpage",
            reliability=0.7,
        ),
        confidence=Confidence(
            score=0.7,
            reasoning="Directly fetched from public URL",
        ),
    )
    finding.confidence.compute_level()
    return finding


def _extract_title(html: str) -> str:
    """Extract title from HTML content."""
    import re
    match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _extract_meta_description(html: str) -> str:
    """Extract meta description from HTML content."""
    import re
    match = re.search(
        r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    )
    if not match:
        match = re.search(
            r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']description["\']',
            html,
            re.IGNORECASE,
        )
    return match.group(1).strip() if match else ""
