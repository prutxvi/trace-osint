"""TRACE OSINT Copilot - Markdown Report Generator

Report layout (person-first):
  1. Person Card + Plain Summary (Story Card)
  2. Canonical Person Profiles
  3. Key Findings (person/email focused)
  4. Timeline
  5. Source Inventory
  6. Infrastructure Context (domains, DNS, WHOIS, generic provider info)
  7. Risk & Exposure
  8. Gaps & Limitations
  9. Recommended Next Steps

Infrastructure findings are separated from person-level findings
to keep the dossier focused on the target individual.
"""

from datetime import datetime, timezone

from src.models import Case, Finding, Entity, AuditEvent
from src.scoring.exposure import compute_exposure_score, risk_level_label
from src.sources.case_synthesis import split_findings_by_focus


def generate_markdown_report(case: Case) -> str:
    """Generate a polished markdown report for a case."""
    exposure = compute_exposure_score(case.findings, case.entities)
    person_findings, infra_findings = split_findings_by_focus(case.findings)

    sections = [
        _header(case),
        _person_card(case),
        _story_summary(case),
        _executive_summary(case, exposure),
        _canonical_profiles(case),
        _person_findings_section(person_findings),
        _timeline_section(case),
        _source_inventory(case),
        _infrastructure_context(infra_findings),
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
| **Case Mode** | {case.case_mode} |
| **Status** | {case.status} |
| **Phase** | {case.phase} |
| **Policy Mode** | `{case.policy_mode}` |
| **Created** | {case.created_at} |
| **Report Generated** | {datetime.now(timezone.utc).isoformat()} |"""


def _person_card(case: Case) -> str:
    if case.case_mode != "person" or not case.canonical_profiles:
        return "## Primary Target\n\nNo person card available."

    profile = case.canonical_profiles[0]
    return f"""## Primary Target

| Field | Value |
|-------|-------|
| Name | {profile.display_name or 'Unknown'} |
| Main Handle | {profile.main_handle or 'Unknown'} |
| Location | {profile.location or 'Unknown'} |
| Verification | {profile.verification} |
| Confidence | {profile.confidence_score:.2f} |
| Avatar | {profile.avatar_url or 'N/A'} |

{profile.summary or case.plain_language_summary}"""


def _story_summary(case: Case) -> str:
    """Render the Plain Summary / Story Card section."""
    if not case.story_card:
        if not case.plain_language_summary:
            return "## Plain Summary\n\nNo summary available."
        return f"## Plain Summary\n\n{case.plain_language_summary}"

    card = case.story_card
    lines = []
    lines.append(f"**Who:** {card.who_is_this}")
    lines.append(f"**IDs:** {card.main_ids}")
    if card.top_traces:
        lines.append(f"**Key traces:** {', '.join(card.top_traces[:5])}")
    lines.append(f"**Risk:** {card.risk_summary}")
    lines.append(f"**Verdict:** {card.verdict}")

    return f"## Plain Summary\n\n" + "\n\n".join(lines)


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


def _canonical_profiles(case: Case) -> str:
    if not case.canonical_profiles:
        return "## Canonical Profiles\n\nNo merged canonical profiles available."

    rows = []
    for profile in case.canonical_profiles[:10]:
        rel = profile.relationship_to_primary.upper()
        rows.append(
            f"| {profile.display_name} | {rel} | {profile.verification} | {profile.confidence_score:.2f} | "
            f"{profile.summary[:80]} |"
        )

    header = """## Canonical Person Profiles

| Profile | Relation | Verification | Confidence | Why It Matters |
|---------|----------|--------------|------------|----------------|"""
    return header + "\n" + "\n".join(rows)


def _person_findings_section(findings: list[Finding]) -> str:
    if not findings:
        return "## Key Findings\n\nNo person-level findings collected."

    rows = []
    for i, f in enumerate(findings[:50], 1):
        rows.append(
            f"| {i} | `{f.entity_type.value}` | {f.entity_value[:40]} | "
            f"{f.verification} / {f.confidence.level} ({f.confidence.score:.2f}) | "
            f"{f.source.url[:50] if f.source.url else 'N/A'} |"
        )

    header = """## Key Findings (Person-Focused)

| # | Type | Value | Confidence | Source |
|---|------|-------|------------|--------|"""
    return header + "\n" + "\n".join(rows)


def _timeline_section(case: Case) -> str:
    if not case.timeline:
        return "## Timeline\n\nNo timeline events were extracted."

    rows = []
    for event in case.timeline[:20]:
        rows.append(
            f"| {event.timestamp[:19]} | {event.title[:40]} | {event.verification} | {event.source[:30]} |"
        )

    header = """## Timeline

| Time | Event | Verification | Source |
|------|-------|--------------|--------|"""
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


def _infrastructure_context(findings: list[Finding]) -> str:
    if not findings:
        return "## Infrastructure Context\n\nNo generic infrastructure findings."

    rows = []
    for i, f in enumerate(findings[:30], 1):
        rows.append(
            f"| {i} | `{f.entity_type.value}` | {f.entity_value[:40]} | "
            f"{f.confidence.level} | {f.source.url[:40] if f.source.url else 'N/A'} |"
        )

    header = """## Infrastructure Context

> Generic domain, DNS, WHOIS, and provider-level data. These are not person-specific.

| # | Type | Value | Confidence | Source |
|---|------|-------|------------|--------|"""
    return header + "\n" + "\n".join(rows)


def _exposure_assessment(exposure: dict) -> str:
    return f"""## Risk & Exposure Assessment

- **Exposure Score:** {exposure['score']:.2f}
- **Risk Level:** {exposure['risk_level'].upper()}
- **Risk Label:** {exposure.get('risk_label', 'Unknown')}
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
