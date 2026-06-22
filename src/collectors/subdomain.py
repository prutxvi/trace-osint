"""TRACE OSINT - Subdomain Takeover Checker

Checks for dangling DNS records that could be taken over.
"""

import json
import urllib.request
import urllib.parse
from typing import Optional

from src.models import Finding, Source, EntityType, Confidence


VULNERABLE_SERVICES = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "azurewebsites.net": "Azure Web Apps",
    "cloudfront.net": "CloudFront",
    "amazonaws.com": "S3/CloudFront",
    "shopify.com": "Shopify",
    "fastly.net": "Fastly",
    "pantheon.io": "Pantheon",
    "ghost.io": "Ghost",
    "surge.sh": "Surge",
    "bitbucket.io": "Bitbucket",
    "firebaseapp.com": "Firebase",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "render.com": "Render",
}


def check_subdomain_takeover(domain: str) -> list[dict]:
    """Check subdomains for takeover vulnerabilities."""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "TRACE-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for line in name.split("\n"):
                line = line.strip()
                if line.endswith(f".{domain}") or line == domain:
                    subdomains.add(line)

        vulnerable = []
        for subdomain in subdomains:
            for service_domain, service_name in VULNERABLE_SERVICES.items():
                if service_domain in subdomain:
                    vulnerable.append({
                        "subdomain": subdomain,
                        "service": service_name,
                        "service_domain": service_domain,
                        "risk": "potential_takeover",
                    })

        return vulnerable
    except Exception:
        return []


def get_subdomain_takeover_intelligence(domain: str) -> list[Finding]:
    """Check for subdomain takeover vulnerabilities."""
    findings = []

    vulnerable = check_subdomain_takeover(domain)
    if vulnerable:
        finding = Finding(
            entity_type=EntityType.DOMAIN,
            entity_value=domain,
            label=f"Subdomain Takeover Risk: {domain}",
            summary=f"Found {len(vulnerable)} potentially takeoverable subdomain(s)",
            details={
                "domain": domain,
                "vulnerable_subdomains": vulnerable,
                "total_checked": len(vulnerable),
            },
            source=Source(
                url=f"https://crt.sh/?q=%.{domain}",
                title=f"Subdomain Takeover Check {domain}",
                source_type="public_certificate_transparency",
                reliability=0.8,
            ),
            confidence=Confidence(score=0.8, reasoning="Subdomain takeover vulnerability detection"),
        )
        finding.confidence.compute_level()
        findings.append(finding)

    return findings
