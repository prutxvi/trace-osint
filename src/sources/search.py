from __future__ import annotations
"""TRACE OSINT Copilot - Public Search Module"""

import json
import re
import urllib.parse
import urllib.request
from typing import Optional

from src.config import get_env, MAX_RETRIES, RETRY_DELAY_SECONDS, DEFAULT_SEARCH_RESULTS
from src.models import Finding, Source, EntityType, Confidence


def _search_via_scraperapi(query: str, num_results: int = DEFAULT_SEARCH_RESULTS) -> list[dict]:
    """Use ScraperAPI to scrape Google search results."""
    scraper_key = get_env("SCRAPERAPI_KEY")
    if not scraper_key:
        return []

    search_url = f"https://www.google.com/search?q={urllib.parse.quote(query)}&num={num_results}"
    api_url = (
        f"https://api.scraperapi.com/"
        f"?api_key={scraper_key}"
        f"&url={urllib.parse.quote(search_url)}"
        f"&render=false"
    )

    for attempt in range(MAX_RETRIES):
        try:
            req = urllib.request.Request(
                api_url,
                headers={"User-Agent": "TRACE-OSINT/1.0"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                html = resp.read().decode("utf-8", errors="replace")
                return _parse_google_html(html)
        except Exception:
            if attempt < MAX_RETRIES - 1:
                import time
                time.sleep(RETRY_DELAY_SECONDS)
    return []


def _parse_google_html(html: str) -> list[dict]:
    """Parse Google search results from HTML."""
    results = []

    div_pattern = r'<div[^>]*class="[^"]*"[^>]*><div[^>]*><a[^>]*href="(/url\?q=([^&"]+)[^"]*)"[^>]*><[^>]*><[^>]*>(.*?)</(?:h3|div)>'
    matches = re.findall(div_pattern, html, re.DOTALL)

    for _, url, title in matches:
        clean_title = re.sub(r"<[^>]+>", "", title).strip()
        if url and clean_title:
            decoded_url = urllib.parse.unquote(url)
            if not decoded_url.startswith("http"):
                decoded_url = "https://" + decoded_url
            results.append({
                "title": clean_title,
                "link": decoded_url,
                "snippet": "",
            })

    if not results:
        a_pattern = r'<a[^>]*href="(https?://[^"]+)"[^>]*><(?:h3|span)[^>]*>(.*?)</(?:h3|span)>'
        a_matches = re.findall(a_pattern, html, re.DOTALL)
        for url, title in a_matches:
            clean_title = re.sub(r"<[^>]+>", "", title).strip()
            if clean_title and "google.com" not in url:
                results.append({
                    "title": clean_title,
                    "link": url,
                    "snippet": "",
                })

    return results[:DEFAULT_SEARCH_RESULTS]


def _search_via_serper(query: str, num_results: int = DEFAULT_SEARCH_RESULTS) -> list[dict]:
    """Search using SerpAPI-style key if applicable."""
    search_key = get_env("SEARCH_API_KEY")
    if not search_key:
        return []

    url = "https://serpapi.com/search.json"
    params = urllib.parse.urlencode({
        "q": query,
        "num": num_results,
        "api_key": search_key,
        "engine": "google",
    })

    try:
        req = urllib.request.Request(
            f"{url}?{params}",
            headers={"User-Agent": "TRACE-OSINT/1.0"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            organic = data.get("organic_results", [])
            return [
                {"title": r.get("title", ""), "link": r.get("link", ""), "snippet": r.get("snippet", "")}
                for r in organic[:num_results]
            ]
    except Exception:
        return []


def _execute_search(query: str, num_results: int = DEFAULT_SEARCH_RESULTS) -> list[dict]:
    """Execute a search query using available providers."""
    results = _search_via_serper(query, num_results)
    if results:
        return results

    results = _search_via_scraperapi(query, num_results)
    return results


def public_search(
    query: str,
    num_results: int = DEFAULT_SEARCH_RESULTS,
    entity_type: EntityType = EntityType.UNKNOWN,
) -> list[Finding]:
    """Perform a public search and return structured findings."""
    raw_results = _execute_search(query, num_results)
    findings = []

    for i, result in enumerate(raw_results):
        title = result.get("title", "")
        link = result.get("link", result.get("url", ""))
        snippet = result.get("snippet", result.get("description", ""))

        finding = Finding(
            entity_type=entity_type,
            entity_value=query,
            label=f"Search Result: {title[:60]}",
            summary=snippet[:300] if snippet else "",
            details={
                "title": title,
                "url": link,
                "snippet": snippet,
                "rank": i + 1,
                "query": query,
            },
            source=Source(
                url=link,
                title=title,
                source_type="public_search",
                reliability=0.7,
            ),
            confidence=Confidence(
                score=0.6,
                reasoning="Public search result from indexed web content",
            ),
        )
        finding.confidence.compute_level()
        findings.append(finding)

    return findings


def search_username(username: str) -> list[Finding]:
    """Search for a username across public sources."""
    queries = [
        f'"{username}" site:github.com OR site:twitter.com OR site:linkedin.com',
        f'"{username}" profile OR account OR user',
    ]
    all_findings = []
    for q in queries:
        all_findings.extend(public_search(q, entity_type=EntityType.USERNAME))
    return all_findings


def search_email(email: str) -> list[Finding]:
    """Search for an email address in public sources."""
    queries = [
        f'"{email}"',
        f'"{email}" site:pastebin.com OR site:reddit.com',
    ]
    all_findings = []
    for q in queries:
        all_findings.extend(public_search(q, entity_type=EntityType.EMAIL))
    return all_findings


def search_domain(domain: str) -> list[Finding]:
    """Search for domain-related intelligence."""
    queries = [
        f'site:{domain}',
        f'"{domain}" WHOIS OR DNS OR certificate',
    ]
    all_findings = []
    for q in queries:
        all_findings.extend(public_search(q, entity_type=EntityType.DOMAIN))
    return all_findings
