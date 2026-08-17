# -*- coding: utf-8 -*-
from __future__ import annotations
"""TRACE OSINT Copilot - Entity Normalization Module"""

import re
from urllib.parse import urlparse, parse_qs, urlencode


def normalize_email(email: str) -> str:
    """Normalize an email address to canonical form."""
    email = email.strip().lower()
    if "@" not in email:
        return email
    local, domain = email.rsplit("@", 1)
    domain = domain.lower().lstrip(".")
    local = local.strip(".")
    return f"{local}@{domain}"


def normalize_username(username: str) -> str:
    """Normalize a username to canonical form."""
    username = username.strip().lower()
    username = re.sub(r"^[@#]+", "", username)
    username = re.sub(r"[/\\]+", "", username)
    return username.strip()


def normalize_url(url: str) -> str:
    """Normalize a URL to canonical form."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/") or "/"

    netloc = re.sub(r"^www\.", "", netloc)

    query_params = parse_qs(parsed.query)
    tracking_params = {
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source",
    }
    filtered_params = {
        k: v for k, v in query_params.items() if k.lower() not in tracking_params
    }
    filtered_query = urlencode(filtered_params, doseq=True) if filtered_params else ""

    return f"{scheme}://{netloc}{path}" + (f"?{filtered_query}" if filtered_query else "")


def normalize_domain(domain: str) -> str:
    """Normalize a domain name."""
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = re.sub(r"^www\.", "", domain)
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    return domain.strip(".")


def normalize_phone(phone: str) -> str:
    """Normalize a phone number to digits-only form."""
    digits = re.sub(r"[^\d+]", "", phone)
    return digits


def normalize_name(name: str) -> str:
    """Normalize a personal or organization name."""
    name = name.strip()
    name = re.sub(r"\s+", " ", name)
    name = name.lower()
    return name


def detect_entity_type(value: str) -> str:
    """Auto-detect the type of an entity value."""
    value = value.strip()

    if re.match(r"^[\w.+-]+@[\w-]+\.[\w.]+$", value):
        return "email"

    if re.match(r"^\+?\d[\d\s\-()]{7,}$", value):
        return "phone"

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
        return "ip_address"

    if re.match(r"^https?://", value):
        return "url"

    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$", value):
        return "domain"

    if re.match(r"^[a-zA-Z0-9_]{3,}$", value):
        return "username"

    return "person"


def are_likely_same_entity(val1: str, val2: str, entity_type: str) -> bool:
    """Determine if two values likely refer to the same entity."""
    if entity_type == "email":
        return normalize_email(val1) == normalize_email(val2)
    if entity_type == "username":
        return normalize_username(val1) == normalize_username(val2)
    if entity_type == "url":
        return normalize_url(val1) == normalize_url(val2)
    if entity_type == "domain":
        return normalize_domain(val1) == normalize_domain(val2)
    if entity_type == "phone":
        return normalize_phone(val1) == normalize_phone(val2)
    return normalize_name(val1) == normalize_name(val2)
