"""TRACE OSINT - Secret Leak Hunter

Scans GitHub, Pastebin, Gists for exposed secrets linked to a target.
"""

import json
import re
import urllib.request
import urllib.parse
from typing import Optional

from src.models import Finding, Source, EntityType, Confidence


SECRET_PATTERNS = [
    {"name": "AWS Access Key", "pattern": r"AKIA[0-9A-Z]{16}", "severity": "critical"},
    {"name": "AWS Secret Key", "pattern": r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", "severity": "critical"},
    {"name": "GitHub Token", "pattern": r"ghp_[A-Za-z0-9]{36}", "severity": "critical"},
    {"name": "GitHub OAuth", "pattern": r"gho_[A-Za-z0-9]{36}", "severity": "critical"},
    {"name": "GitLab Token", "pattern": r"glpat-[A-Za-z0-9\-_]{20,}", "severity": "critical"},
    {"name": "Slack Token", "pattern": r"xox[bpsar]-[0-9]{10,}-[a-zA-Z0-9-]+", "severity": "critical"},
    {"name": "Slack Webhook", "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", "severity": "high"},
    {"name": "Stripe Key", "pattern": r"sk_live_[0-9a-zA-Z]{24,}", "severity": "critical"},
    {"name": "Google API Key", "pattern": r"AIza[0-9A-Za-z\-_]{35}", "severity": "high"},
    {"name": "Google OAuth", "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "severity": "high"},
    {"name": "Private Key", "pattern": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "severity": "critical"},
    {"name": "Password in Code", "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]+)['\"]", "severity": "high"},
    {"name": "API Key", "pattern": r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"]([A-Za-z0-9\-_]{20,})['\"]", "severity": "medium"},
    {"name": "Bearer Token", "pattern": r"(?i)bearer\s+[A-Za-z0-9\-_\.]+", "severity": "medium"},
    {"name": "MySQL Connection", "pattern": r"mysql://[^:]+:[^@]+@[^/]+/\w+", "severity": "critical"},
    {"name": "PostgreSQL Connection", "pattern": r"postgresql://[^:]+:[^@]+@[^/]+/\w+", "severity": "critical"},
    {"name": "MongoDB Connection", "pattern": r"mongodb(\+srv)?://[^:]+:[^@]+@[^/]+", "severity": "critical"},
    {"name": "Redis Connection", "pattern": r"redis://[^:]+:[^@]+@[^/]+", "severity": "high"},
    {"name": "AWS RDS URL", "pattern": r"(?i)rds\.amazonaws\.com", "severity": "high"},
    {"name": "Docker Hub Token", "pattern": r"dckr_pat_[A-Za-z0-9\-_]{36,}", "severity": "critical"},
    {"name": "npm Token", "pattern": r"npm_[A-Za-z0-9]{36}", "severity": "critical"},
    {"name": "PyPI Token", "pattern": r"pypi-[A-Za-z0-9\-_]{50,}", "severity": "critical"},
    {"name": "Heroku API Key", "pattern": r"(?i)heroku.*api.key\s*[=:]\s*['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]", "severity": "critical"},
    {"name": "Twilio API Key", "pattern": r"SK[0-9a-fA-F]{32}", "severity": "critical"},
    {"name": "SendGrid Key", "pattern": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "severity": "critical"},
    {"name": "Mailgun Key", "pattern": r"key-[0-9a-zA-Z]{32}", "severity": "critical"},
]


def scan_text_for_secrets(text: str) -> list[dict]:
    """Scan text for exposed secrets."""
    found = []
    for pattern_info in SECRET_PATTERNS:
        matches = re.findall(pattern_info["pattern"], text)
        if matches:
            found.append({
                "type": pattern_info["name"],
                "severity": pattern_info["severity"],
                "count": len(matches),
                "sample": str(matches[0])[:60] if matches else "",
            })
    return found


def search_github_code(query: str, per_page: int = 30) -> list[dict]:
    """Search GitHub public code."""
    try:
        encoded = urllib.parse.quote(query)
        url = f"https://api.github.com/search/code?q={encoded}&per_page={per_page}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "TRACE-OSINT/1.0",
            "Accept": "application/vnd.github.v3+json",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("items", [])
    except Exception:
        return []


def search_github_gists(query: str) -> list[dict]:
    """Search GitHub Gists for a query."""
    try:
        encoded = urllib.parse.quote(query)
        url = f"https://api.github.com/search/gists?q={encoded}&per_page=20"
        req = urllib.request.Request(url, headers={
            "User-Agent": "TRACE-OSINT/1.0",
            "Accept": "application/vnd.github.v3+json",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("items", [])
    except Exception:
        return []


def search_pastebin(query: str) -> list[dict]:
    """Search Pastebin for public pastes."""
    try:
        encoded = urllib.parse.quote(query)
        url = f"https://scrapetools.kwiatekmiki.com/api/search/pastebin?query={encoded}&limit=20"
        req = urllib.request.Request(url, headers={"User-Agent": "TRACE-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("results", [])
    except Exception:
        return []


def get_secret_leak_intelligence(target: str, is_domain: bool = False) -> list[Finding]:
    """Hunt for leaked secrets related to a target."""
    findings = []

    code_results = search_github_code(target)
    if code_results:
        secrets_found = []
        for item in code_results[:15]:
            snippet = ""
            if "text_matches" in item:
                for tm in item["text_matches"]:
                    fragment = tm.get("fragment", "")
                    if fragment:
                        secrets = scan_text_for_secrets(fragment)
                        secrets_found.extend(secrets)

        if secrets_found:
            finding = Finding(
                entity_type=EntityType.DOMAIN if is_domain else EntityType.USERNAME,
                entity_value=target,
                label=f"Secrets Found: {target}",
                summary=f"Found {len(secrets_found)} potential secret(s) in {len(code_results)} code result(s)",
                details={
                    "source": "GitHub Code Search",
                    "secrets": secrets_found[:20],
                    "code_results": [
                        {"name": c.get("name", ""), "repo": c.get("repository", {}).get("full_name", ""), "url": c.get("html_url", "")}
                        for c in code_results[:10]
                    ],
                },
                source=Source(
                    url=f"https://github.com/search?q={urllib.parse.quote(target)}&type=code",
                    title="GitHub Secret Hunter",
                    source_type="public_api",
                    reliability=0.85,
                ),
                confidence=Confidence(score=0.85, reasoning="GitHub code scan for secrets"),
            )
            finding.confidence.compute_level()
            findings.append(finding)

    gist_results = search_github_gists(target)
    if gist_results:
        gist_secrets = []
        for gist in gist_results[:10]:
            files = gist.get("files", {})
            for filename, file_data in files.items():
                content = file_data.get("content", "")
                if content:
                    secrets = scan_text_for_secrets(content)
                    gist_secrets.extend(secrets)

        if gist_secrets:
            gist_finding = Finding(
                entity_type=EntityType.DOMAIN if is_domain else EntityType.USERNAME,
                entity_value=target,
                label=f"Gist Secrets: {target}",
                summary=f"Found {len(gist_secrets)} potential secret(s) in {len(gist_results)} gist(s)",
                details={
                    "source": "GitHub Gists",
                    "secrets": gist_secrets[:20],
                    "gists": [
                        {"description": g.get("description", ""), "url": g.get("html_url", "")}
                        for g in gist_results[:10]
                    ],
                },
                source=Source(
                    url=f"https://gist.github.com/search?q={urllib.parse.quote(target)}",
                    title="GitHub Gist Secret Hunter",
                    source_type="public_api",
                    reliability=0.8,
                ),
                confidence=Confidence(score=0.8, reasoning="GitHub gist scan for secrets"),
            )
            gist_finding.confidence.compute_level()
            findings.append(gist_finding)

    pastes = search_pastebin(target)
    if pastes:
        paste_finding = Finding(
            entity_type=EntityType.DOMAIN if is_domain else EntityType.USERNAME,
            entity_value=target,
            label=f"Pastebin Mentions: {target}",
            summary=f"Found {len(pastes)} paste(s) mentioning '{target}'",
            details={"source": "Pastebin", "pastes": pastes[:10]},
            source=Source(
                url=f"https://pastebin.com/search?q={urllib.parse.quote(target)}",
                title="Pastebin Search",
                source_type="public_api",
                reliability=0.7,
            ),
            confidence=Confidence(score=0.7, reasoning="Pastebin public search"),
        )
        paste_finding.confidence.compute_level()
        findings.append(paste_finding)

    return findings
