from __future__ import annotations
"""TRACE OSINT Copilot - Text Extraction Module"""

import re
from typing import Optional


def extract_emails(text: str) -> list[str]:
    """Extract email addresses from text."""
    pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    matches = re.findall(pattern, text)
    return list(set(matches))


def extract_urls(text: str) -> list[str]:
    """Extract URLs from text."""
    pattern = r"https?://[^\s<>\[\]\"'\)]+"
    matches = re.findall(pattern, text)
    return list(set(matches))


def extract_domains(text: str) -> list[str]:
    """Extract domain names from text."""
    url_pattern = r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    domains = re.findall(url_pattern, text)
    plain_pattern = r"\b([a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,})\b"
    more_domains = re.findall(plain_pattern, text)
    domains.extend([d[0] for d in more_domains])
    return list(set(domains))


def extract_usernames(text: str) -> list[str]:
    """Extract potential usernames from text."""
    patterns = [
        r"@([a-zA-Z0-9_]{3,20})",
        r"username[:\s]+([a-zA-Z0-9_]{3,20})",
        r"user[:\s]+([a-zA-Z0-9_]{3,20})",
        r"handle[:\s]+@?([a-zA-Z0-9_]{3,20})",
    ]
    usernames = []
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        usernames.extend(matches)
    return list(set(usernames))


def extract_ips(text: str) -> list[str]:
    """Extract IPv4 addresses from text."""
    pattern = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
    matches = re.findall(pattern, text)
    valid = []
    for ip in matches:
        octets = ip.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            valid.append(ip)
    return list(set(valid))


def extract_phones(text: str) -> list[str]:
    """Extract phone numbers from text."""
    pattern = r"(\+?\d[\d\s\-()]{7,}\d)"
    matches = re.findall(pattern, text)
    return list(set(m.strip() for m in matches))


def extract_all_entities(text: str) -> dict[str, list[str]]:
    """Extract all recognized entity types from text."""
    return {
        "emails": extract_emails(text),
        "urls": extract_urls(text),
        "domains": extract_domains(text),
        "usernames": extract_usernames(text),
        "ips": extract_ips(text),
        "phones": extract_phones(text),
    }


def clean_html(html: str) -> str:
    """Strip HTML tags and return plain text."""
    text = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_text_content(html: str) -> str:
    """Extract readable text content from HTML."""
    cleaned = clean_html(html)
    cleaned = re.sub(r"&amp;", "&", cleaned)
    cleaned = re.sub(r"&lt;", "<", cleaned)
    cleaned = re.sub(r"&gt;", ">", cleaned)
    cleaned = re.sub(r"&quot;", '"', cleaned)
    cleaned = re.sub(r"&#\d+;", "", cleaned)
    return cleaned.strip()
