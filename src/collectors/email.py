# -*- coding: utf-8 -*-
from __future__ import annotations
"""TRACE OSINT - Email SMTP Verification & Intelligence"""

import smtplib
import socket
import dns.resolver
import re
import json
import urllib.request
from typing import Optional

from src.models import Finding, Source, EntityType, Confidence


FREE_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "aol.com", "icloud.com", "mail.com", "protonmail.com", "proton.me",
    "zoho.com", "yandex.com", "gmx.com", "fastmail.com", "tutanota.com",
    "rediffmail.com", "inbox.com", "lycos.com", "netscape.net",
]


def check_mx_records(domain: str) -> list[dict]:
    """Check MX records for a domain."""
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        return [{"priority": str(r.preference), "host": str(r.exchange)} for r in mx_records]
    except Exception:
        return []


def check_dns_records(domain: str) -> dict:
    """Get all DNS records for a domain."""
    records = {}

    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []

    return records


def verify_email_smtp(email: str) -> dict:
    """Verify email via SMTP (checks if mailbox exists)."""
    domain = email.split("@")[-1]
    result = {
        "email": email,
        "valid_format": bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", email)),
        "domain": domain,
        "is_free": domain.lower() in FREE_EMAIL_PROVIDERS,
        "mx_found": False,
        "smtp_valid": False,
        "catch_all": False,
        "disposable": False,
    }

    mx_records = check_mx_records(domain)
    if not mx_records:
        return result

    result["mx_found"] = True
    result["mx_records"] = mx_records

    mx_host = mx_records[0]["host"].rstrip(".")

    try:
        smtp = smtplib.SMTP(timeout=10)
        smtp.connect(mx_host, 25)
        smtp.helo("trace-osint.local")
        smtp.mail("trace@trace-osint.local")
        code, _ = smtp.rcpt(email)
        result["smtp_valid"] = code == 250

        smtp.mail("trace@trace-osint.local")
        code2, _ = smtp.rcpt("nonexistent@trace-osint.local")
        result["catch_all"] = code2 == 250

        smtp.quit()
    except Exception:
        pass

    return result


def check_email_breach(email: str) -> dict:
    """Check email against known breach patterns (free check)."""
    breaches = []

    try:
        url = f"https://haveibeenpwned.com/api/v2/breachedaccount/{email}?truncateResponse=false"
        req = urllib.request.Request(url, headers={
            "User-Agent": "TRACE-OSINT/1.0",
            "hibp-api-key": "",
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            breaches = [b.get("Name", "") for b in data]
    except Exception:
        pass

    return {
        "email": email,
        "breaches": breaches,
        "breach_count": len(breaches),
    }


def get_email_intelligence(email: str) -> list[Finding]:
    """Full email intelligence gathering."""
    findings = []
    domain = email.split("@")[-1]

    verification = verify_email_smtp(email)

    finding = Finding(
        entity_type=EntityType.EMAIL,
        entity_value=email,
        label=f"Email Verification: {email}",
        summary=f"Email {'valid' if verification['smtp_valid'] else 'invalid'} | "
                f"Free: {verification['is_free']} | "
                f"MX: {verification['mx_found']} | "
                f"Catch-all: {verification['catch_all']}",
        details=verification,
        source=Source(
            url=f"smtp://{domain}",
            title="SMTP Verification",
            source_type="public_api",
            reliability=0.9,
        ),
        confidence=Confidence(
            score=0.9 if verification["smtp_valid"] else 0.3,
            reasoning="SMTP verification result",
        ),
    )
    finding.confidence.compute_level()
    findings.append(finding)

    dns_records = check_dns_records(domain)
    if any(dns_records.values()):
        dns_finding = Finding(
            entity_type=EntityType.DOMAIN,
            entity_value=domain,
            label=f"DNS Records: {domain}",
            summary=f"A: {len(dns_records.get('A', []))} | "
                    f"MX: {len(dns_records.get('MX', []))} | "
                    f"TXT: {len(dns_records.get('TXT', []))}",
            details=dns_records,
            source=Source(
                url=f"dns://{domain}",
                title="DNS Enumeration",
                source_type="public_dns_record",
                reliability=0.95,
            ),
            confidence=Confidence(
                score=0.95,
                reasoning="Direct DNS query results",
            ),
        )
        dns_finding.confidence.compute_level()
        findings.append(dns_finding)

    breaches = check_email_breach(email)
    if breaches["breach_count"] > 0:
        breach_finding = Finding(
            entity_type=EntityType.EMAIL,
            entity_value=email,
            label=f"Breaches Found: {email}",
            summary=f"Found in {breaches['breach_count']} data breach(es): {', '.join(breaches['breaches'][:5])}",
            details=breaches,
            source=Source(
                url="https://haveibeenpwned.com",
                title="Have I Been Pwned",
                source_type="public_api",
                reliability=0.95,
            ),
            confidence=Confidence(
                score=0.95,
                reasoning="Verified breach database check",
            ),
        )
        breach_finding.confidence.compute_level()
        findings.append(breach_finding)

    return findings
