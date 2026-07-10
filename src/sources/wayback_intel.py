from __future__ import annotations
"""TRACE OSINT - Wayback Machine & Web Archive Intelligence"""

import json
import urllib.request
from typing import Optional

from src.models import Finding, Source, EntityType, Confidence


def wayback_check(url: str) -> dict:
    """Check Wayback Machine for archived snapshots of a URL."""
    try:
        api_url = f"https://archive.org/wayback/available?url={url}"
        req = urllib.request.Request(api_url, headers={"User-Agent": "TRACE-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            snapshots = data.get("archived_snapshots", {})
            closest = snapshots.get("closest", {})
            return {
                "url": url,
                "available": closest.get("available", False),
                "timestamp": closest.get("timestamp", ""),
                "status": closest.get("status", ""),
                "snapshot_url": closest.get("url", ""),
            }
    except Exception:
        return {"url": url, "available": False}


def wayback_list(url: str, limit: int = 50) -> list[dict]:
    """List all Wayback Machine snapshots for a URL."""
    try:
        api_url = f"https://web.archive.org/cdx/search/cdx?url={url}&output=json&limit={limit}"
        req = urllib.request.Request(api_url, headers={"User-Agent": "TRACE-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
            if len(data) < 2:
                return []
            headers = data[0]
            snapshots = []
            for row in data[1:]:
                snapshot = dict(zip(headers, row))
                snapshots.append({
                    "timestamp": snapshot.get("timestamp", ""),
                    "original": snapshot.get("original", ""),
                    "statuscode": snapshot.get("statuscode", ""),
                    "mimetype": snapshot.get("mimetype", ""),
                })
            return snapshots
    except Exception:
        return []


def get_wayback_intelligence(url: str) -> list[Finding]:
    """Gather intelligence from Wayback Machine."""
    findings = []

    check = wayback_check(url)
    if check.get("available"):
        finding = Finding(
            entity_type=EntityType.URL,
            entity_value=url,
            label=f"Wayback Machine: {url}",
            summary=f"Archived on {check['timestamp']} | Status: {check['status']}",
            details=check,
            source=Source(
                url=check.get("snapshot_url", ""),
                title="Wayback Machine Snapshot",
                source_type="public_archive",
                reliability=0.9,
            ),
            confidence=Confidence(score=0.9, reasoning="Wayback Machine archive confirmed"),
        )
        finding.confidence.compute_level()
        findings.append(finding)

    snapshots = wayback_list(url)
    if snapshots:
        history_finding = Finding(
            entity_type=EntityType.URL,
            entity_value=url,
            label=f"Archive History: {url}",
            summary=f"Found {len(snapshots)} archived snapshot(s)",
            details={"snapshots": snapshots[:20], "total": len(snapshots)},
            source=Source(
                url=f"https://web.archive.org/web/*/{url}",
                title="Wayback Machine History",
                source_type="public_archive",
                reliability=0.9,
            ),
            confidence=Confidence(score=0.9, reasoning="Historical archive data"),
        )
        history_finding.confidence.compute_level()
        findings.append(history_finding)

    return findings
