# -*- coding: utf-8 -*-
from __future__ import annotations
"""TRACE OSINT - IP Geolocation & Infrastructure Intelligence"""

import json
import urllib.request
from typing import Optional

from src.models import Finding, Source, EntityType, Confidence


def ip_geolocation(ip: str) -> dict:
    """Get geolocation data for an IP address."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        req = urllib.request.Request(url, headers={"User-Agent": "TRACE-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return {"query": ip, "status": "fail"}


def reverse_dns(ip: str) -> str:
    """Perform reverse DNS lookup on an IP."""
    try:
        import socket
        result = socket.gethostbyaddr(ip)
        return result[0]
    except Exception:
        return ""


def get_ip_intelligence(ip: str) -> list[Finding]:
    """Gather intelligence on an IP address."""
    findings = []

    geo = ip_geolocation(ip)
    if geo.get("status") == "success":
        finding = Finding(
            entity_type=EntityType.IP_ADDRESS,
            entity_value=ip,
            label=f"IP Geolocation: {ip}",
            summary=f"{geo.get('city', 'N/A')}, {geo.get('regionName', 'N/A')}, {geo.get('country', 'N/A')} | "
                    f"ISP: {geo.get('isp', 'N/A')} | "
                    f"Hosting: {geo.get('hosting', False)} | "
                    f"Proxy: {geo.get('proxy', False)}",
            details=geo,
            source=Source(
                url=f"http://ip-api.com/json/{ip}",
                title="IP Geolocation",
                source_type="public_api",
                reliability=0.8,
            ),
            confidence=Confidence(score=0.8, reasoning="IP geolocation API"),
        )
        finding.confidence.compute_level()
        findings.append(finding)

    rdns = reverse_dns(ip)
    if rdns:
        rdns_finding = Finding(
            entity_type=EntityType.IP_ADDRESS,
            entity_value=ip,
            label=f"Reverse DNS: {ip}",
            summary=f"Hostname: {rdns}",
            details={"ip": ip, "hostname": rdns},
            source=Source(
                url=f"dns://{ip}",
                title="Reverse DNS",
                source_type="public_dns_record",
                reliability=0.85,
            ),
            confidence=Confidence(score=0.85, reasoning="Reverse DNS lookup"),
        )
        rdns_finding.confidence.compute_level()
        findings.append(rdns_finding)

    return findings
