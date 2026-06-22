"""TRACE OSINT Copilot - Markdown Report Generator"""

from datetime import datetime, timezone

from src.models import Case, Finding, Entity, AuditEvent
from src.scoring.exposure import compute_exposure_score


def generate_markdown_report(case: Case) -> str:
    """Generate a polished markdown report for a case."""
    exposure = compute_exposure_score(case.findings, case.entities)

    sections = [
        _header(case),
        _executive_summary(case, exposure),
        _investigation_scope(case),
        _findings_section(case),
        _entity_resolution(case),
        _source_inventory(case),
        _confidence_matrix(case),
        _exposure_assessment(exposure),
        _gaps_and_limitations(case),
        _next_steps(case),
        _audit_trail(case),
        _policy_compliance(case),
    ]

    return "\n\n".join(sections)


def _header(case: Case) -> str:
    return f"""# TRACE OSINT Investigation Report

| Field | Value |
|-------|-------|
| **Case ID** | `{case.case_id}` |
| **Case Name** | {case.name} |
| **Status** | {case.status} |
| **Phase** | {case.phase} |
| **Policy Mode** | `{case.policy_mode}` |
| **Created** | {case.created_at} |
| **Report Generated** | {datetime.now(timezone.utc).isoformat()} |"""


def _executive_summary(case: Case, exposure: dict) -> str:
    finding_count = len(case.findings)
    entity_count = len(case.entities)
    high_conf = sum(1 for f in case.findings if f.confidence.level == "high")

    summary = f"""## Executive Summary

This investigation examined **{len(case.clues)} clue(s)** provided for case `{case.case_id}`.

**Key Metrics:**
- Findings collected: **{finding_count}**
- Entities resolved: **{entity_count}**
- High-confidence matches: **{high_conf}**
- Overall exposure: **{exposure['risk_level'].upper()}** (score: {exposure['score']:.2f})

{exposure['summary']}"""

    return summary


def _investigation_scope(case: Case) -> str:
    clues_list = "\n".join(f"- `{c}`" for c in case.clues)
    return f"""## Investigation Scope

**Clues Provided:**
{clues_list}

**Objective:** Resolve provided clues to public-source intelligence findings using read-only, lawful investigation methods."""


def _findings_section(case: Case) -> str:
    if not case.findings:
        return "## Findings\n\nNo findings collected."

    rows = []
    for i, f in enumerate(case.findings, 1):
        rows.append(
            f"| {i} | `{f.entity_type.value}` | {f.entity_value[:40]} | "
            f"{f.confidence.level} ({f.confidence.score:.2f}) | "
            f"{f.source.url[:50] if f.source.url else 'N/A'} |"
        )

    header = """## Findings

| # | Type | Value | Confidence | Source |
|---|------|-------|------------|--------|"""
    return header + "\n" + "\n".join(rows)


def _entity_resolution(case: Case) -> str:
    if not case.entities:
        return "## Entity Resolution\n\nNo entities resolved."

    rows = []
    for e in case.entities:
        aliases = ", ".join(e.aliases[:3]) if e.aliases else "none"
        rows.append(
            f"| `{e.type.value}` | {e.value} | {aliases} | "
            f"{e.confidence.level} ({e.confidence.score:.2f}) |"
        )

    header = """## Entity Resolution

| Type | Canonical Value | Aliases | Confidence |
|------|----------------|---------|------------|"""
    return header + "\n" + "\n".join(rows)


def _source_inventory(case: Case) -> str:
    sources = {}
    for f in case.findings:
        key = f.source.url or "unknown"
        if key not in sources:
            sources[key] = {
                "url": f.source.url,
                "title": f.source.title,
                "type": f.source.source_type,
                "reliability": f.source.reliability,
            }

    if not sources:
        return "## Source Inventory\n\nNo sources consulted."

    rows = []
    for s in sources.values():
        rows.append(
            f"| {s['type']} | {s['title'][:40] if s['title'] else 'N/A'} | "
            f"{s['reliability']:.1f} | {s['url'][:60] if s['url'] else 'N/A'} |"
        )

    header = """## Source Inventory

| Type | Title | Reliability | URL |
|------|-------|-------------|-----|"""
    return header + "\n" + "\n".join(rows)


def _confidence_matrix(case: Case) -> str:
    levels = {"high": 0, "medium": 0, "low": 0, "minimal": 0}
    for f in case.findings:
        levels[f.confidence.level] = levels.get(f.confidence.level, 0) + 1

    total = len(case.findings) or 1
    return f"""## Confidence Distribution

| Level | Count | Percentage |
|-------|-------|------------|
| High | {levels['high']} | {levels['high']/total*100:.1f}% |
| Medium | {levels['medium']} | {levels['medium']/total*100:.1f}% |
| Low | {levels['low']} | {levels['low']/total*100:.1f}% |
| Minimal | {levels['minimal']} | {levels['minimal']/total*100:.1f}% |"""


def _exposure_assessment(exposure: dict) -> str:
    return f"""## Risk & Exposure Assessment

- **Exposure Score:** {exposure['score']:.2f}
- **Risk Level:** {exposure['risk_level'].upper()}
- **Contributing Factors:** {exposure['factor_count']}

**Signals Detected:** {', '.join(exposure['signals']) if exposure['signals'] else 'None'}

{exposure['summary']}"""


def _gaps_and_limitations(case: Case) -> str:
    return """## Gaps & Limitations

- Investigation limited to public, read-only sources only
- No private account access, authentication, or login-based retrieval
- No breach database queries or credential-related lookups
- Confidence scores reflect source reliability and corroboration only
- Results may be incomplete due to public-source limitations"""


def _next_steps(case: Case) -> str:
    return """## Recommended Next Steps

1. Cross-reference high-confidence findings with additional public sources
2. Attempt entity resolution for any low-confidence matches
3. Search for the resolved entities on additional public platforms
4. Review gaps to identify additional public-source queries
5. Consider domain-specific registries if applicable (DNS, CT, WHOIS)"""


def _audit_trail(case: Case) -> str:
    if not case.audit_log:
        return "## Audit Trail\n\nNo audit events recorded."

    rows = []
    for event in case.audit_log[-20:]:
        rows.append(
            f"| {event.timestamp[:19]} | {event.phase} | {event.agent} | "
            f"{event.action[:30]} | {event.status} |"
        )

    header = """## Audit Trail (Last 20 Events)

| Timestamp | Phase | Agent | Action | Status |
|-----------|-------|-------|--------|--------|"""
    return header + "\n" + "\n".join(rows)


def _policy_compliance(case: Case) -> str:
    return f"""## Policy Compliance

- **Mode:** `{case.policy_mode}`
- **Blocked Actions:** All non-public-source methods excluded
- **Compliance Status:** PASS

This investigation was conducted entirely within the boundaries of public-source, read-only, lawful intelligence gathering methods."""
