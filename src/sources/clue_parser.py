"""TRACE OSINT - Explicit clue parser."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from src.models import ClueType, ParsedClue
from src.sources.normalize import (
    normalize_domain,
    normalize_email,
    normalize_phone,
    normalize_url,
    normalize_username,
)


COMMON_NAME_TOKENS = {
    "raj", "singh", "patel", "kumar", "john", "mohammed", "mohammad",
    "sharma", "gupta", "reddy", "das", "ali", "khan", "prasad",
}


def parse_clues(values: list[str]) -> list[ParsedClue]:
    return [classify_clue(value) for value in values]


def classify_clue(value: str) -> ParsedClue:
    raw = value.strip()
    if not raw:
        return ParsedClue(raw=value, type=ClueType.UNKNOWN, normalized="", label="UNKNOWN", confidence=0.0)

    if re.match(r"^[\w.+-]+@[\w-]+\.[\w.]+$", raw):
        normalized = normalize_email(raw)
        return ParsedClue(raw=raw, type=ClueType.EMAIL, normalized=normalized, label=f"EMAIL: {normalized}", confidence=0.99)

    if re.match(r"^\+?\d[\d\s\-()]{7,}$", raw):
        normalized = normalize_phone(raw)
        return ParsedClue(raw=raw, type=ClueType.PHONE, normalized=normalized, label=f"PHONE: {normalized}", confidence=0.95)

    if re.match(r"^https?://", raw):
        return _classify_url(raw)

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", raw):
        return ParsedClue(raw=raw, type=ClueType.IP_ADDRESS, normalized=raw, label=f"IP: {raw}", confidence=0.95)

    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$", raw):
        normalized = normalize_domain(raw)
        return ParsedClue(raw=raw, type=ClueType.DOMAIN, normalized=normalized, label=f"DOMAIN: {normalized}", confidence=0.95)

    if raw.startswith("@") or re.match(r"^[a-zA-Z0-9_\-.]{3,39}$", raw):
        normalized = normalize_username(raw)
        if normalized:
            return ParsedClue(raw=raw, type=ClueType.USERNAME, normalized=normalized, label=f"USERNAME: {normalized}", confidence=0.8)

    if _looks_like_name(raw):
        normalized = " ".join(part.capitalize() for part in re.split(r"\s+", raw.strip()) if part)
        return ParsedClue(raw=raw, type=ClueType.NAME, normalized=normalized, label=f"NAME CANDIDATE: {normalized}", confidence=0.65)

    return ParsedClue(raw=raw, type=ClueType.UNKNOWN, normalized=raw, label=f"UNKNOWN: {raw}", confidence=0.3)


def detect_case_mode(parsed_clues: list[ParsedClue]) -> str:
    person_types = {
        ClueType.EMAIL,
        ClueType.PHONE,
        ClueType.GITHUB_PROFILE,
        ClueType.GITHUB_USERNAME,
        ClueType.LINKEDIN_PROFILE,
        ClueType.NAME,
        ClueType.USERNAME,
    }
    asset_types = {ClueType.DOMAIN, ClueType.IP_ADDRESS}

    if any(clue.type in person_types for clue in parsed_clues):
        return "person"
    if any(clue.type in asset_types for clue in parsed_clues):
        return "asset"
    return "person"


def _classify_url(raw: str) -> ParsedClue:
    normalized = normalize_url(raw)
    parsed = urlparse(normalized)
    host = parsed.netloc.lower()
    path = parsed.path.strip("/")

    if "github.com" in host:
        parts = [part for part in path.split("/") if part]
        if len(parts) == 1:
            username = normalize_username(parts[0])
            return ParsedClue(raw=raw, type=ClueType.GITHUB_PROFILE, normalized=normalized, label=f"GITHUB PROFILE: {username}", confidence=0.99)
        if parts:
            username = normalize_username(parts[0])
            return ParsedClue(raw=raw, type=ClueType.GITHUB_PROFILE, normalized=normalized, label=f"GITHUB PROFILE: {username}", confidence=0.95)

    if "linkedin.com" in host and "/in/" in parsed.path:
        slug = path.split("/")[-1]
        return ParsedClue(raw=raw, type=ClueType.LINKEDIN_PROFILE, normalized=normalized, label=f"LINKEDIN PROFILE: {slug}", confidence=0.99)

    return ParsedClue(raw=raw, type=ClueType.URL, normalized=normalized, label=f"URL: {normalized}", confidence=0.9)


def _looks_like_name(raw: str) -> bool:
    if " " not in raw.strip():
        return False
    if re.search(r"\d", raw):
        return False
    tokens = [token for token in re.split(r"\s+", raw.strip()) if token]
    if len(tokens) < 2 or len(tokens) > 4:
        return False
    if any(len(token) < 2 for token in tokens):
        return False
    return True


def is_common_name(name: str) -> bool:
    tokens = {token.lower() for token in re.split(r"\s+", name.strip()) if token}
    return bool(tokens) and tokens.issubset(COMMON_NAME_TOKENS)
