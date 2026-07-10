from __future__ import annotations
"""TRACE OSINT - Shodan Infrastructure Intelligence"""

import json
import urllib.request
import urllib.parse
from typing import Optional

from src.config import get_env
from src.models import Finding, Source, EntityType, Confidence


def shodan_host_lookup(ip: str) -> dict:
    """Look up a host on Shodan."""
    api_key = get_env("SHODAN_API_KEY")
    if not api_key:
        return {"error": "No Shodan API key configured"}

    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        req = urllib.request.Request(url, headers={"User-Agent": "TRACE-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}


def shodan_domain_lookup(domain: str) -> dict:
    """Look up a domain on Shodan."""
    api_key = get_env("SHODAN_API_KEY")
    if not api_key:
        return {"error": "No Shodan API key configured"}

    try:
        url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
        req = urllib.request.Request(url, headers={"User-Agent": "TRACE-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}


def shodan_search(query: str, limit: int = 20) -> list[dict]:
    """Search Shodan for a query."""
    api_key = get_env("SHODAN_API_KEY")
    if not api_key:
        return []

    try:
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={urllib.parse.quote(query)}&limit={limit}"
        req = urllib.request.Request(url, headers={"User-Agent": "TRACE-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("matches", [])
    except Exception:
        return []


def shodan_reverse_ip(ip: str) -> list[dict]:
    """Reverse IP lookup on Shodan."""
    api_key = get_env("SHODAN_API_KEY")
    if not api_key:
        return []

    try:
        url = f"https://api.shodan.io/dns/reverse?host={ip}&key={api_key}"
        req = urllib.request.Request(url, headers={"User-Agent": "TRACE-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("domains", [])
    except Exception:
        return []


def get_shodan_intelligence(target: str, is_ip: bool = False) -> list[Finding]:
    """Gather Shodan intelligence on a target."""
    findings = []

    if is_ip:
        host = shodan_host_lookup(target)
        if not host.get("error"):
            ports = [str(p) for p in host.get("ports", [])]
            vulns = list(host.get("vulns", {}).keys()) if isinstance(host.get("vulns"), dict) else host.get("vulns", [])

            finding = Finding(
                entity_type=EntityType.IP_ADDRESS,
                entity_value=target,
                label=f"Shodan Host: {target}",
                summary=f"Org: {host.get('org', 'N/A')} | "
                        f"OS: {host.get('os', 'N/A')} | "
                        f"Ports: {', '.join(ports[:10])} | "
                        f"Vulns: {len(vulns)}",
                details={
                    "ip": target,
                    "org": host.get("org", ""),
                    "isp": host.get("isp", ""),
                    "os": host.get("os", ""),
                    "ports": ports,
                    "vulns": vulns[:20],
                    "hostnames": host.get("hostnames", []),
                    "country_code": host.get("country_code", ""),
                    "city": host.get("city", ""),
                    "last_update": host.get("last_update", ""),
                    "services": [
                        {
                            "port": s.get("port"),
                            "protocol": s.get("transport", ""),
                            "product": s.get("product", ""),
                            "version": s.get("version", ""),
                            "banner": s.get("data", "")[:200],
                        }
                        for s in host.get("data", [])[:15]
                    ],
                },
                source=Source(
                    url=f"https://www.shodan.io/host/{target}",
                    title=f"Shodan {target}",
                    source_type="public_api",
                    reliability=0.95,
                ),
                confidence=Confidence(score=0.95, reasoning="Shodan infrastructure scan data"),
            )
            finding.confidence.compute_level()
            findings.append(finding)

        reverse = shodan_reverse_ip(target)
        if reverse:
            reverse_finding = Finding(
                entity_type=EntityType.IP_ADDRESS,
                entity_value=target,
                label=f"Reverse DNS: {target}",
                summary=f"Hostnames: {', '.join(reverse[:10])}",
                details={"hostnames": reverse},
                source=Source(
                    url=f"https://www.shodan.io/host/{target}",
                    title="Reverse DNS",
                    source_type="public_api",
                    reliability=0.9,
                ),
                confidence=Confidence(score=0.9, reasoning="Shodan reverse DNS"),
            )
            reverse_finding.confidence.compute_level()
            findings.append(reverse_finding)

    else:
        domain_data = shodan_domain_lookup(target)
        if not domain_data.get("error"):
            subdomains = domain_data.get("subdomains", [])
            a_records = domain_data.get("data", [])

            dns_finding = Finding(
                entity_type=EntityType.DOMAIN,
                entity_value=target,
                label=f"Shodan DNS: {target}",
                summary=f"Subdomains: {len(subdomains)} | Records: {len(a_records)}",
                details={
                    "domain": target,
                    "subdomains": subdomains[:50],
                    "a_records": a_records[:20],
                },
                source=Source(
                    url=f"https://www.shodan.io/domain/{target}",
                    title=f"Shodan DNS {target}",
                    source_type="public_api",
                    reliability=0.9,
                ),
                confidence=Confidence(score=0.9, reasoning="Shodan DNS enumeration"),
            )
            dns_finding.confidence.compute_level()
            findings.append(dns_finding)

        search_results = shodan_search(f"hostname:{target}")
        if search_results:
            search_finding = Finding(
                entity_type=EntityType.DOMAIN,
                entity_value=target,
                label=f"Shodan Search: {target}",
                summary=f"Found {len(search_results)} host(s) matching '{target}'",
                details={"hosts": [
                    {
                        "ip": h.get("ip_str", ""),
                        "org": h.get("org", ""),
                        "ports": h.get("ports", []),
                        "os": h.get("os", ""),
                    }
                    for h in search_results[:10]
                ]},
                source=Source(
                    url=f"https://www.shodan.io/search?query=hostname:{target}",
                    title=f"Shodan Search {target}",
                    source_type="public_api",
                    reliability=0.85,
                ),
                confidence=Confidence(score=0.85, reasoning="Shodan search results"),
            )
            search_finding.confidence.compute_level()
            findings.append(search_finding)

    return findings
