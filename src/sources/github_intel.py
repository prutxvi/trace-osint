from __future__ import annotations
"""TRACE OSINT - GitHub Code Search & Secrets Leak Scanner"""

import json
import re
import urllib.request
import urllib.parse
from typing import Optional

from src.models import Finding, Source, EntityType, Confidence


SECRET_PATTERNS = [
    {"name": "AWS Access Key", "pattern": r"AKIA[0-9A-Z]{16}", "severity": "high"},
    {"name": "AWS Secret Key", "pattern": r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", "severity": "high"},
    {"name": "GitHub Token", "pattern": r"ghp_[A-Za-z0-9]{36}", "severity": "high"},
    {"name": "GitHub OAuth", "pattern": r"gho_[A-Za-z0-9]{36}", "severity": "high"},
    {"name": "GitLab Token", "pattern": r"glpat-[A-Za-z0-9\-_]{20,}", "severity": "high"},
    {"name": "Slack Token", "pattern": r"xox[bpsar]-[0-9]{10,}-[a-zA-Z0-9-]+", "severity": "high"},
    {"name": "Slack Webhook", "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", "severity": "medium"},
    {"name": "Stripe Key", "pattern": r"sk_live_[0-9a-zA-Z]{24,}", "severity": "high"},
    {"name": "Google API Key", "pattern": r"AIza[0-9A-Za-z\-_]{35}", "severity": "medium"},
    {"name": "Google OAuth", "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "severity": "medium"},
    {"name": "Private Key", "pattern": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "severity": "critical"},
    {"name": "Password in Code", "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]+)['\"]", "severity": "high"},
    {"name": "API Key", "pattern": r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"]([A-Za-z0-9\-_]{20,})['\"]", "severity": "medium"},
    {"name": "Bearer Token", "pattern": r"(?i)bearer\s+[A-Za-z0-9\-_\.]+", "severity": "medium"},
    {"name": "MySQL Connection", "pattern": r"mysql://[^:]+:[^@]+@[^/]+/\w+", "severity": "critical"},
    {"name": "PostgreSQL Connection", "pattern": r"postgresql://[^:]+:[^@]+@[^/]+/\w+", "severity": "critical"},
    {"name": "MongoDB Connection", "pattern": r"mongodb(\+srv)?://[^:]+:[^@]+@[^/]+", "severity": "critical"},
    {"name": "Redis Connection", "pattern": r"redis://[^:]+:[^@]+@[^/]+", "severity": "high"},
    {"name": "AWS RDS URL", "pattern": r"(?i)rds\.amazonaws\.com", "severity": "high"},
]


def search_github_code(query: str, per_page: int = 30) -> list[dict]:
    """Search GitHub public code."""
    try:
        encoded_query = urllib.parse.quote(query)
        url = f"https://api.github.com/search/code?q={encoded_query}&per_page={per_page}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "TRACE-OSINT/1.0",
            "Accept": "application/vnd.github.v3+json",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("items", [])
    except Exception:
        return []


def search_github_repos(query: str, per_page: int = 20) -> list[dict]:
    """Search GitHub repositories."""
    try:
        encoded_query = urllib.parse.quote(query)
        url = f"https://api.github.com/search/repositories?q={encoded_query}&per_page={per_page}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "TRACE-OSINT/1.0",
            "Accept": "application/vnd.github.v3+json",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("items", [])
    except Exception:
        return []


def search_github_users(query: str, per_page: int = 20) -> list[dict]:
    """Search GitHub users."""
    try:
        encoded_query = urllib.parse.quote(query)
        url = f"https://api.github.com/search/users?q={encoded_query}&per_page={per_page}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "TRACE-OSINT/1.0",
            "Accept": "application/vnd.github.v3+json",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("items", [])
    except Exception:
        return []


def scan_for_secrets(text: str) -> list[dict]:
    """Scan text for exposed secrets and credentials."""
    found_secrets = []
    for pattern_info in SECRET_PATTERNS:
        matches = re.findall(pattern_info["pattern"], text)
        if matches:
            found_secrets.append({
                "type": pattern_info["name"],
                "severity": pattern_info["severity"],
                "count": len(matches),
                "sample": str(matches[0])[:50] if matches else "",
            })
    return found_secrets


def get_github_intelligence(query: str) -> list[Finding]:
    """Full GitHub intelligence gathering."""
    findings = []

    repos = search_github_repos(query)
    if repos:
        repo_finding = Finding(
            entity_type=EntityType.USERNAME,
            entity_value=query,
            label=f"GitHub Repos: {query}",
            summary=f"Found {len(repos)} repository(ies) matching '{query}'",
            details={"repos": [
                {"name": r.get("full_name", ""), "url": r.get("html_url", ""), "description": r.get("description", "")}
                for r in repos[:10]
            ]},
            source=Source(
                url=f"https://github.com/search?q={urllib.parse.quote(query)}&type=repositories",
                title="GitHub Repository Search",
                source_type="public_api",
                reliability=0.9,
            ),
            confidence=Confidence(score=0.9, reasoning="Direct GitHub API search"),
        )
        repo_finding.confidence.compute_level()
        findings.append(repo_finding)

    users = search_github_users(query)
    if users:
        user_finding = Finding(
            entity_type=EntityType.USERNAME,
            entity_value=query,
            label=f"GitHub Users: {query}",
            summary=f"Found {len(users)} user(s) matching '{query}'",
            details={"users": [
                {"login": u.get("login", ""), "url": u.get("html_url", ""), "type": u.get("type", "")}
                for u in users[:10]
            ]},
            source=Source(
                url=f"https://github.com/search?q={urllib.parse.quote(query)}&type=users",
                title="GitHub User Search",
                source_type="public_api",
                reliability=0.9,
            ),
            confidence=Confidence(score=0.9, reasoning="Direct GitHub API search"),
        )
        user_finding.confidence.compute_level()
        findings.append(user_finding)

    code_results = search_github_code(query)
    if code_results:
        secrets_found = []
        for item in code_results[:10]:
            snippet = item.get("text_matches", [{}])[0].get("fragment", "")
            if snippet:
                secrets = scan_for_secrets(snippet)
                secrets_found.extend(secrets)

        code_finding = Finding(
            entity_type=EntityType.USERNAME,
            entity_value=query,
            label=f"GitHub Code: {query}",
            summary=f"Found {len(code_results)} code result(s), {len(secrets_found)} potential secret(s)",
            details={
                "code_results": [
                    {"name": c.get("name", ""), "repo": c.get("repository", {}).get("full_name", ""), "url": c.get("html_url", "")}
                    for c in code_results[:10]
                ],
                "secrets": secrets_found,
            },
            source=Source(
                url=f"https://github.com/search?q={urllib.parse.quote(query)}&type=code",
                title="GitHub Code Search",
                source_type="public_api",
                reliability=0.8,
            ),
            confidence=Confidence(score=0.8, reasoning="GitHub code search results"),
        )
        code_finding.confidence.compute_level()
        findings.append(code_finding)

    return findings
