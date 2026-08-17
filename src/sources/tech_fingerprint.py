# -*- coding: utf-8 -*-
from __future__ import annotations
"""TRACE OSINT - Tech Stack Fingerprinting

Detects technology stack from domain: CMS, frameworks, CDNs, versions.
"""

import json
import re
import urllib.request
from typing import Optional

from src.models import Finding, Source, EntityType, Confidence


TECH_SIGNATURES = {
    "WordPress": {"headers": ["x-powered-by: WordPress"], "html": ["wp-content", "wp-includes"]},
    "Drupal": {"headers": ["x-drupal-cache", "x-generator: Drupal"], "html": ["Drupal.settings", "sites/default/files"]},
    "Joomla": {"headers": ["x-content-encoded-by: Joomla"], "html": ["/media/jui/", "Joomla!"]},
    "Laravel": {"headers": ["x-powered-by: Laravel"], "html": []},
    "Django": {"headers": ["x-frame-options: DENY"], "html": ["csrfmiddlewaretoken", "django"]},
    "Rails": {"headers": ["x-powered-by: Phusion Passenger"], "html": ["csrf-token", "authenticity_token"]},
    "Next.js": {"headers": ["x-powered-by: Next.js"], "html": ["__NEXT_DATA__", "_next/static"]},
    "Nuxt.js": {"headers": [], "html": ["__NUXT__", "_nuxt/"]},
    "React": {"headers": [], "html": ["react", "_reactRoot"]},
    "Vue.js": {"headers": [], "html": ["vue", "__vue__"]},
    "Angular": {"headers": [], "html": ["ng-version", "angular"]},
    "Bootstrap": {"headers": [], "html": ["bootstrap.min.css", "bootstrap.min.js"]},
    "Tailwind CSS": {"headers": [], "html": ["tailwindcss", "tailwind"]},
    "jQuery": {"headers": [], "html": ["jquery.min.js", "jquery-"]},
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "html": []},
    "AWS": {"headers": ["x-amz-request-id", "server: AmazonS3"], "html": ["aws", "amazonaws"]},
    "Google Analytics": {"headers": [], "html": ["google-analytics.com", "gtag", "ga.js"]},
    "Google Tag Manager": {"headers": [], "html": ["googletagmanager.com", "gtm.js"]},
    "Facebook Pixel": {"headers": [], "html": ["connect.facebook.net", "fbq("]},
    "Hotjar": {"headers": [], "html": ["hotjar.com", "hj("]},
    "Stripe": {"headers": [], "html": ["stripe.com", "Stripe("]},
    "PayPal": {"headers": [], "html": ["paypal.com", "paypalobjects"]},
    "Nginx": {"headers": ["server: nginx"], "html": []},
    "Apache": {"headers": ["server: Apache"], "html": []},
    "IIS": {"headers": ["server: Microsoft-IIS"], "html": []},
    "Vercel": {"headers": ["x-vercel-id", "server: Vercel"], "html": []},
    "Netlify": {"headers": ["server: Netlify"], "html": []},
    "Heroku": {"headers": ["server: Cowboy"], "html": []},
}


def fingerprint_domain(domain: str) -> dict:
    """Fingerprint the technology stack of a domain."""
    url = f"https://{domain}"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            headers = dict(resp.headers)
            html = resp.read().decode("utf-8", errors="replace")

            detected = {}
            for tech, signatures in TECH_SIGNATURES.items():
                found = False
                for header_sig in signatures.get("headers", []):
                    key, _, value = header_sig.partition(":")
                    header_value = headers.get(key.strip().lower(), "")
                    if value.strip().lower() in header_value.lower():
                        found = True
                        break
                for html_sig in signatures.get("html", []):
                    if html_sig.lower() in html.lower():
                        found = True
                        break
                if found:
                    detected[tech] = True

            server = headers.get("server", "")
            powered_by = headers.get("x-powered-by", "")

            return {
                "domain": domain,
                "technologies": list(detected.keys()),
                "server": server,
                "powered_by": powered_by,
                "headers": {k: v for k, v in headers.items()},
            }
    except Exception:
        return {"domain": domain, "technologies": [], "error": "Failed to fetch"}


def get_tech_stack_intelligence(domain: str) -> list[Finding]:
    """Gather technology stack intelligence."""
    findings = []

    tech_data = fingerprint_domain(domain)
    if tech_data.get("technologies"):
        finding = Finding(
            entity_type=EntityType.DOMAIN,
            entity_value=domain,
            label=f"Tech Stack: {domain}",
            summary=f"Detected {len(tech_data['technologies'])} technologies: {', '.join(tech_data['technologies'][:8])}",
            details=tech_data,
            source=Source(
                url=f"https://{domain}",
                title=f"Tech Stack {domain}",
                source_type="public_webpage",
                reliability=0.8,
            ),
            confidence=Confidence(score=0.8, reasoning="Technology fingerprinting via HTTP headers and HTML analysis"),
        )
        finding.confidence.compute_level()
        findings.append(finding)

    return findings
