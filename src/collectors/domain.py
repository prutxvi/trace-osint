"""TRACE OSINT - WHOIS & Domain Intelligence"""

import json
import urllib.request
import re
from typing import Optional

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

from src.models import Finding, Source, EntityType, Confidence


def whois_lookup(domain: str) -> dict:
    """Perform WHOIS lookup on a domain."""
    if not WHOIS_AVAILABLE:
        return _whois_via_api(domain)

    try:
        w = whois.whois(domain)
        return {
            "domain": domain,
            "registrar": str(w.registrar) if w.registrar else "",
            "creation_date": str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date),
            "expiration_date": str(w.expiration_date[0]) if isinstance(w.expiration_date, list) else str(w.expiration_date),
            "name_servers": [str(ns) for ns in (w.name_servers or [])],
            "registrant": str(w.org) if w.org else "",
            "country": str(w.country) if w.country else "",
            "state": str(w.state) if w.state else "",
            "emails": [str(e) for e in (w.emails or [])],
            "status": [str(s) for s in (w.status or [])],
        }
    except Exception as e:
        return {"domain": domain, "error": str(e)}


def _whois_via_api(domain: str) -> dict:
    """Fallback WHOIS via free API."""
    try:
        url = f"https://rdap.verisign.com/com/v1/domain/{domain}"
        req = urllib.request.Request(url, headers={"User-Agent": "TRACE-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return {
                "domain": domain,
                "ldh_name": data.get("ldhName", ""),
                "status": [s.get("status", "") for s in data.get("status", [])],
                "events": [
                    {"action": e.get("eventAction", ""), "date": e.get("eventDate", "")}
                    for e in data.get("events", [])
                ],
                "nameservers": [ns.get("ldhName", "") for ns in data.get("nameservers", [])],
            }
    except Exception:
        return {"domain": domain, "error": "WHOIS lookup failed"}


def certificate_transparency(domain: str) -> list[dict]:
    """Query crt.sh for certificate transparency logs."""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "TRACE-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        certs = []
        seen = set()
        for entry in data:
            name = entry.get("name_value", "")
            if name and name not in seen:
                seen.add(name)
                certs.append({
                    "name": name,
                    "issuer": entry.get("issuer_name", ""),
                    "not_before": entry.get("not_before", ""),
                    "not_after": entry.get("not_after", ""),
                    "serial": entry.get("serial_number", ""),
                })
        return certs
    except Exception:
        return []


def subdomain_enum(domain: str) -> list[str]:
    """Enumerate subdomains via certificate transparency."""
    certs = certificate_transparency(domain)
    subdomains = set()
    for cert in certs:
        name = cert.get("name", "")
        if name.endswith(f".{domain}") or name == domain:
            subdomains.add(name)
    return sorted(subdomains)


def get_domain_intelligence(domain: str) -> list[Finding]:
    """Full domain intelligence gathering."""
    findings = []

    whois_data = whois_lookup(domain)
    if not whois_data.get("error"):
        finding = Finding(
            entity_type=EntityType.DOMAIN,
            entity_value=domain,
            label=f"WHOIS: {domain}",
            summary=f"Registrar: {whois_data.get('registrar', 'N/A')} | "
                    f"Created: {whois_data.get('creation_date', 'N/A')} | "
                    f"Country: {whois_data.get('country', 'N/A')}",
            details=whois_data,
            source=Source(
                url=f"https://who.is/whois/{domain}",
                title=f"WHOIS {domain}",
                source_type="public_whois_record",
                reliability=0.9,
            ),
            confidence=Confidence(score=0.9, reasoning="Direct WHOIS query"),
        )
        finding.confidence.compute_level()
        findings.append(finding)

    certs = certificate_transparency(domain)
    if certs:
        cert_finding = Finding(
            entity_type=EntityType.DOMAIN,
            entity_value=domain,
            label=f"CT Logs: {domain}",
            summary=f"Found {len(certs)} certificate(s) in CT logs",
            details={"certificates": certs[:20], "total": len(certs)},
            source=Source(
                url=f"https://crt.sh/?q=%.{domain}",
                title=f"CT Logs {domain}",
                source_type="public_certificate_transparency",
                reliability=0.95,
            ),
            confidence=Confidence(score=0.95, reasoning="Certificate transparency logs"),
        )
        cert_finding.confidence.compute_level()
        findings.append(cert_finding)

    subdomains = subdomain_enum(domain)
    if subdomains:
        sub_finding = Finding(
            entity_type=EntityType.DOMAIN,
            entity_value=domain,
            label=f"Subdomains: {domain}",
            summary=f"Discovered {len(subdomains)} subdomain(s): {', '.join(subdomains[:10])}",
            details={"subdomains": subdomains},
            source=Source(
                url=f"https://crt.sh/?q=%.{domain}",
                title=f"Subdomains {domain}",
                source_type="public_certificate_transparency",
                reliability=0.9,
            ),
            confidence=Confidence(score=0.9, reasoning="CT log subdomain enumeration"),
        )
        sub_finding.confidence.compute_level()
        findings.append(sub_finding)

    return findings
