from __future__ import annotations
"""TRACE OSINT - Commit Author Unmasker

Extracts real names and emails from public Git commit history.
"""

import json
import re
import urllib.request
import urllib.parse
from typing import Optional

from src.models import Finding, Source, EntityType, Confidence


def get_github_commits(repo: str, limit: int = 50) -> list[dict]:
    """Get commits from a GitHub repository."""
    try:
        url = f"https://api.github.com/repos/{repo}/commits?per_page={limit}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "TRACE-OSINT/1.0",
            "Accept": "application/vnd.github.v3+json",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return []


def search_commit_authors(query: str) -> list[dict]:
    """Search for commit authors matching a query."""
    try:
        encoded = urllib.parse.quote(query)
        url = f"https://api.github.com/search/commits?q={encoded}&per_page=20"
        req = urllib.request.Request(url, headers={
            "User-Agent": "TRACE-OSINT/1.0",
            "Accept": "application/vnd.github.cloak-preview+json",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("items", [])
    except Exception:
        return []


def get_commit_author_intelligence(query: str) -> list[Finding]:
    """Gather intelligence from Git commit history."""
    findings = []

    commits = search_commit_authors(query)
    if commits:
        authors = {}
        for commit in commits[:20]:
            commit_data = commit.get("commit", {})
            author = commit_data.get("author", {})
            name = author.get("name", "")
            email = author.get("email", "")
            date = author.get("date", "")

            if name and name not in authors:
                authors[name] = {
                    "name": name,
                    "email": email,
                    "first_seen": date,
                    "repo": commit.get("repository", {}).get("full_name", ""),
                }

        if authors:
            for author_name, author_data in list(authors.items())[:5]:
                finding = Finding(
                    entity_type=EntityType.PERSON,
                    entity_value=author_data.get("email", author_name),
                    label=f"Git Author: {author_name}",
                    summary=f"Name: {author_name} | Email: {author_data.get('email', 'N/A')} | Repo: {author_data.get('repo', 'N/A')}",
                    details=author_data,
                    source=Source(
                        url=f"https://github.com/search?q={urllib.parse.quote(query)}&type=commits",
                        title="GitHub Commit Author",
                        source_type="public_api",
                        reliability=0.85,
                    ),
                    confidence=Confidence(score=0.85, reasoning="Git commit author metadata"),
                )
                finding.confidence.compute_level()
                findings.append(finding)

    return findings
