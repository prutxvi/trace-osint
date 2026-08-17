# -*- coding: utf-8 -*-
"""TRACE OSINT - Guided case synthesis helpers."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Iterable

from src.models import CanonicalProfile, Case, Entity, Finding, InvestigationNote, StoryCard, TimelineEvent


def apply_verification_labels(findings: list[Finding], entities: list[Entity]) -> None:
    """Assign user-facing verification labels to findings and entities."""
    corroboration = defaultdict(int)
    for finding in findings:
        corroboration[_key_for_value(finding.entity_value)] += 1

    for finding in findings:
        matches = corroboration[_key_for_value(finding.entity_value)]
        score = finding.confidence.score
        reliability = finding.source.reliability

        if score >= 0.8 and matches >= 2:
            finding.verification = "confirmed"
            finding.verification_reason = "Strong confidence with corroboration from multiple public findings"
        elif score >= 0.55 or matches >= 2 or reliability >= 0.8:
            finding.verification = "probable"
            finding.verification_reason = "Useful overlap exists, but at least one key attribute still needs confirmation"
        elif score >= 0.3:
            finding.verification = "weak"
            finding.verification_reason = "Public signal exists, but overlap is limited or indirect"
        else:
            finding.verification = "unrelated"
            finding.verification_reason = "Insufficient corroboration to treat this as part of the same target"

    finding_map = {finding.id: finding for finding in findings}
    for entity in entities:
        linked = [finding_map[fid] for fid in entity.finding_ids if fid in finding_map]
        strongest = max((rank_verification(item.verification) for item in linked), default=0)
        entity.verification = verification_label_from_rank(strongest)
        if linked:
            entity.verification_reason = linked[0].verification_reason
        else:
            entity.verification_reason = "No supporting findings were available"


def build_timeline(findings: list[Finding]) -> list[TimelineEvent]:
    """Build a chronology from source dates and collected findings."""
    events: list[TimelineEvent] = []
    for finding in findings:
        extracted = _extract_dates(finding)
        if not extracted:
            extracted = [(finding.created_at, finding.label or finding.entity_value, finding.summary or "Finding collected")]

        for timestamp, title, description in extracted:
            events.append(TimelineEvent(
                timestamp=timestamp,
                title=title[:100],
                description=description[:240],
                source=finding.source.title or finding.source.source_type,
                confidence=finding.confidence.level,
                verification=finding.verification,
            ))

    return sorted(events, key=lambda event: _safe_sort_key(event.timestamp))


def build_canonical_profiles(case: Case) -> list[CanonicalProfile]:
    """Merge corroborated public fragments into canonical profiles."""
    profiles: list[CanonicalProfile] = []
    for finding in sorted(case.findings, key=lambda item: item.confidence.score, reverse=True):
        fragment = _profile_fragment(finding)
        if not fragment["identifiers"]:
            continue

        profile = _find_matching_profile(profiles, fragment["identifiers"])
        if profile is None:
            profile = CanonicalProfile()
            profiles.append(profile)

        _merge_profile(profile, fragment, finding)

    for profile in profiles:
        profile.display_name = profile.display_name or (profile.names[0] if profile.names else (profile.identifiers[0] if profile.identifiers else "Candidate profile"))
        evidence_count = max(len(profile.evidence_finding_ids), 1)
        profile.confidence_score = round(min(1.0, profile.confidence_score / evidence_count), 3)
        if profile.confidence_score >= 0.8 and len(profile.identifiers) >= 2:
            profile.verification = "confirmed"
        elif profile.confidence_score >= 0.55:
            profile.verification = "probable"
        else:
            profile.verification = "weak"
        profile.summary = _profile_summary(profile)

    return sorted(profiles, key=lambda item: item.confidence_score, reverse=True)


def build_investigation_notes(case: Case) -> list[InvestigationNote]:
    """Create short, user-facing notes that explain the workflow."""
    notes: list[InvestigationNote] = []
    notes.append(InvestigationNote(
        stage="planning",
        message=f"Started from {len(case.clues)} clue(s) and built a public-source collection plan.",
    ))

    confirmed = sum(1 for finding in case.findings if finding.verification == "confirmed")
    probable = sum(1 for finding in case.findings if finding.verification == "probable")
    notes.append(InvestigationNote(
        stage="verifying",
        message=f"Confirmed {confirmed} findings and marked {probable} as probable after overlap checks.",
        confidence_impact="positive" if confirmed else "neutral",
    ))

    if case.canonical_profiles:
        top_profile = case.canonical_profiles[0]
        notes.append(InvestigationNote(
            stage="resolving",
            message=f"Built {'person' if top_profile.mode == 'person' else 'asset'} profile '{top_profile.display_name}' with {top_profile.verification} confidence.",
            confidence_impact="positive" if top_profile.verification in {"confirmed", "probable"} else "neutral",
        ))

    if case.recommended_pivots:
        notes.append(InvestigationNote(
            stage="analyzing",
            message=f"Next best pivot: {case.recommended_pivots[0]}",
        ))

    weak_count = sum(1 for finding in case.findings if finding.verification == "weak")
    if weak_count:
        notes.append(InvestigationNote(
            stage="analyzing",
            message=f"{weak_count} weak matches were kept separate instead of being merged into the main profile.",
            confidence_impact="guardrail",
        ))

    return notes


def build_plain_language_summary(case: Case) -> str:
    """Summarize what is known in plain language."""
    top_profile = case.canonical_profiles[0] if case.canonical_profiles else None
    confirmed = sum(1 for finding in case.findings if finding.verification == "confirmed")
    probable = sum(1 for finding in case.findings if finding.verification == "probable")
    weak = sum(1 for finding in case.findings if finding.verification == "weak")

    if top_profile:
        return (
            f"TRACE found a strongest {top_profile.mode} profile for this case: {top_profile.display_name}. "
            f"That profile is currently rated {top_profile.verification} based on {len(top_profile.evidence_finding_ids)} supporting public findings. "
            f"Across the full case, {confirmed} findings are confirmed, {probable} are probable, and {weak} remain weak or incomplete."
        )

    return (
        f"TRACE did not find a single merged target profile yet. "
        f"Across the current case, {confirmed} findings are confirmed, {probable} are probable, and {weak} remain weak or incomplete."
    )


def _profile_fragment(finding: Finding) -> dict:
    details = finding.details or {}
    linked_accounts = []
    social_profiles = details.get("social_profiles", {})
    for platform, value in social_profiles.items():
        if isinstance(value, list):
            linked_accounts.extend([f"{platform}:{item}" for item in value if item])
        elif value:
            linked_accounts.append(f"{platform}:{value}")

    project_refs = []
    for key in ("projects", "repositories", "repos"):
        raw = details.get(key, [])
        if isinstance(raw, list):
            project_refs.extend(str(item) for item in raw[:8])

    activity = []
    for key in ("recent_activity", "activity", "commits", "events"):
        raw = details.get(key, [])
        if isinstance(raw, list):
            activity.extend(str(item) for item in raw[:5])

    names = _collect_values(details, "name", "full_name", "display_name", "real_name")
    roles = _collect_values(details, "role", "title", "occupation")
    bios = _collect_values(details, "bio", "description", "summary")
    websites = _collect_values(details, "website", "blog", "html_url", "url")
    companies = _collect_values(details, "company", "organization", "employer")
    profile_urls = _collect_values(details, "profile_url", "url")
    locations = _collect_values(details, "location")
    avatars = _collect_values(details, "avatar_url")
    handles = _collect_values(details, "username", "main_handle")
    mode = "person" if names or handles or details.get("avatar_url") else "asset"

    identifiers = {
        _key_for_value(finding.entity_value),
        *(_key_for_value(item) for item in names),
        *(_key_for_value(item) for item in websites),
        *(_key_for_value(item) for item in profile_urls),
        *(_key_for_value(item) for item in handles),
        *(_key_for_value(item) for item in linked_accounts),
    }
    identifiers.discard("")

    return {
        "names": names,
        "roles": roles,
        "bios": bios,
        "websites": websites,
        "profile_urls": profile_urls,
        "linked_accounts": linked_accounts,
        "project_references": project_refs,
        "activity_clues": activity,
        "companies": companies,
        "avatar_url": avatars[0] if avatars else "",
        "location": locations[0] if locations else "",
        "main_handle": handles[0] if handles else "",
        "mode": mode,
        "identifiers": sorted(identifiers),
        "confidence_score": finding.confidence.score,
    }


def _collect_values(details: dict, *keys: str) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = details.get(key)
        if isinstance(value, list):
            values.extend(str(item).strip() for item in value if str(item).strip())
        elif value:
            values.append(str(value).strip())
    return _dedupe(values)


def _find_matching_profile(profiles: list[CanonicalProfile], identifiers: Iterable[str]) -> CanonicalProfile | None:
    identifier_set = set(identifiers)
    if not identifier_set:
        return None
    for profile in profiles:
        if identifier_set.intersection(profile.identifiers):
            return profile
    return None


def _merge_profile(profile: CanonicalProfile, fragment: dict, finding: Finding) -> None:
    profile.mode = fragment["mode"] if fragment.get("mode") == "person" else profile.mode
    profile.names = _dedupe(profile.names + fragment["names"])
    profile.roles = _dedupe(profile.roles + fragment["roles"])
    profile.bios = _dedupe(profile.bios + fragment["bios"])
    profile.websites = _dedupe(profile.websites + fragment["websites"])
    profile.profile_urls = _dedupe(profile.profile_urls + fragment.get("profile_urls", []))
    profile.linked_accounts = _dedupe(profile.linked_accounts + fragment["linked_accounts"])
    profile.project_references = _dedupe(profile.project_references + fragment["project_references"])
    profile.activity_clues = _dedupe(profile.activity_clues + fragment["activity_clues"])
    profile.companies = _dedupe(profile.companies + fragment["companies"])
    profile.identifiers = _dedupe(profile.identifiers + fragment["identifiers"])
    profile.evidence_finding_ids = _dedupe(profile.evidence_finding_ids + [finding.id])
    profile.confidence_score += finding.confidence.score
    if fragment.get("avatar_url") and not profile.avatar_url:
        profile.avatar_url = fragment["avatar_url"]
    if fragment.get("location") and not profile.location:
        profile.location = fragment["location"]
    if fragment.get("main_handle") and not profile.main_handle:
        profile.main_handle = fragment["main_handle"]
    if fragment["names"] and not profile.display_name:
        profile.display_name = fragment["names"][0]


def _profile_summary(profile: CanonicalProfile) -> str:
    claims = []
    if profile.roles:
        claims.append(f"roles: {', '.join(profile.roles[:2])}")
    if profile.location:
        claims.append(f"location: {profile.location}")
    if profile.companies:
        claims.append(f"companies: {', '.join(profile.companies[:2])}")
    if profile.main_handle:
        claims.append(f"handle: {profile.main_handle}")
    if profile.linked_accounts:
        claims.append(f"accounts: {', '.join(profile.linked_accounts[:3])}")
    if profile.websites:
        claims.append(f"websites: {', '.join(profile.websites[:2])}")
    return "; ".join(claims) if claims else "Public profile extracted with limited structured detail"


def _extract_dates(finding: Finding) -> list[tuple[str, str, str]]:
    details = finding.details or {}
    events: list[tuple[str, str, str]] = []
    candidate_keys = [
        "date",
        "created_at",
        "updated_at",
        "archived_at",
        "timestamp",
        "published_at",
        "commit_date",
        "breach_date",
        "last_seen",
        "first_seen",
        "not_before",
    ]
    for key in candidate_keys:
        value = details.get(key)
        if isinstance(value, str) and _looks_like_date(value):
            events.append((value, finding.label or key.replace("_", " ").title(), finding.summary or f"Observed via {finding.source.source_type}"))
    return events


def _looks_like_date(value: str) -> bool:
    return any(token in value for token in ("-", "/", "T", ":")) and len(value) >= 8


def _safe_sort_key(value: str) -> tuple[int, str]:
    try:
        return (0, datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat())
    except Exception:
        return (1, value)


def _dedupe(items: list[str]) -> list[str]:
    output: list[str] = []
    seen = set()
    for item in items:
        cleaned = str(item).strip()
        if not cleaned:
            continue
        lowered = cleaned.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        output.append(cleaned)
    return output


def _key_for_value(value: str) -> str:
    return str(value or "").strip().lower()


def rank_verification(label: str) -> int:
    ranks = {
        "unreviewed": 0,
        "unrelated": 1,
        "weak": 2,
        "probable": 3,
        "confirmed": 4,
    }
    return ranks.get(label, 0)


def verification_label_from_rank(rank: int) -> str:
    labels = {
        0: "unreviewed",
        1: "unrelated",
        2: "weak",
        3: "probable",
        4: "confirmed",
    }
    return labels.get(rank, "unreviewed")


# ---------------------------------------------------------------------------
# Story Synthesis - generates the human-readable dossier narrative
# ---------------------------------------------------------------------------

INFRASTRUCTURE_LABELS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
    "yahoo.com", "protonmail.com", "icloud.com", "aol.com",
    "live.com", "msn.com", "mail.com", "gmx.com",
}


def is_infrastructure_finding(finding: Finding) -> bool:
    """Determine if a finding is generic infrastructure rather than person-specific."""
    val = (finding.entity_value or "").lower()
    label = (finding.label or "").lower()
    src_type = (finding.source.source_type or "").lower()

    for infra in INFRASTRUCTURE_LABELS:
        if infra in val or infra in label:
            return True

    if any(k in label for k in ("whois registrant", "dns record", "certificate", "ssl cert")):
        return True
    if src_type in ("dns", "whois", "certificate_transparency"):
        return True

    if finding.entity_type.value in ("domain", "ip_address"):
        person_signals = any(k in label for k in ("profile", "email", "person", "username", "phone", "company", "store", "shop", "portfolio"))
        if not person_signals:
            return True

    return False


def split_findings_by_focus(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    """Split findings into person-centric and infrastructure-centric lists."""
    person_findings = []
    infra_findings = []
    for f in findings:
        if is_infrastructure_finding(f):
            infra_findings.append(f)
        else:
            person_findings.append(f)
    return person_findings, infra_findings


def build_story_card(case: Case, exposure: dict) -> StoryCard:
    """Build a 4-8 line plain-language dossier summary.

    This function is the primary story synthesis entry point.
    It reads the primary target, canonical profiles, key findings, and risk,
    then returns a structured StoryCard for reports.
    """
    primary = None
    for p in case.canonical_profiles:
        if p.is_primary or p.relationship_to_primary == "primary":
            primary = p
            break
    if not primary and case.canonical_profiles:
        primary = case.canonical_profiles[0]

    if not primary:
        return StoryCard(
            who_is_this="No strong profile found.",
            main_ids=", ".join(case.clues[:3]) if case.clues else "Unknown",
            top_traces=[],
            risk_summary=exposure.get("risk_label", "Unknown"),
            verdict="No actionable dossier was built.",
            full_text="TRACE did not find enough corroborated public data to build a person dossier.",
        )

    who_is_this = _describe_person(primary)
    main_ids = _describe_ids(primary, case)
    top_traces = _describe_top_traces(primary)
    risk_summary = _describe_risk(primary, exposure)
    verdict = _describe_verdict(primary, exposure)

    lines = [who_is_this, f"Primary IDs: {main_ids}."]
    if top_traces:
        lines.append(f"Key public traces: {', '.join(top_traces[:5])}.")
    lines.append(f"{risk_summary}.")
    lines.append(verdict)

    full_text = " ".join(lines)

    return StoryCard(
        who_is_this=who_is_this,
        main_ids=main_ids,
        top_traces=top_traces,
        risk_summary=risk_summary,
        verdict=verdict,
        full_text=full_text,
    )


def _describe_person(profile: CanonicalProfile) -> str:
    parts = []
    if profile.display_name:
        parts.append(profile.display_name)
    if profile.roles:
        parts.append(f"appears to be a {profile.roles[0].lower()}")
    elif profile.bios:
        parts.append(f"is described as: {profile.bios[0][:80]}")
    if profile.companies:
        parts.append(f"associated with {profile.companies[0]}")
    if profile.location:
        parts.append(f"based in {profile.location}")

    if not parts:
        return f"Strongest candidate profile: {profile.display_name}"
    return f"{' '.join(parts)}"


def _describe_ids(profile: CanonicalProfile, case: Case) -> str:
    ids = []
    if profile.main_handle:
        ids.append(f"@{profile.main_handle}")
    emails = [clue.normalized for clue in case.parsed_clues if clue.type.value == "email"]
    if emails:
        ids.append(emails[0])
    if not ids and profile.identifiers:
        ids.append(profile.identifiers[0])
    return ", ".join(ids[:3]) if ids else "Unknown"


def _describe_top_traces(profile: CanonicalProfile) -> list[str]:
    traces = []
    for url in profile.profile_urls[:3]:
        traces.append(url)
    for account in profile.linked_accounts[:3]:
        traces.append(account)
    return traces


def _describe_risk(profile: CanonicalProfile, exposure: dict) -> str:
    risk_label = exposure.get("risk_label", "Unknown exposure")
    score = exposure.get("score", 0.0)
    signals = exposure.get("signals", [])
    signal_text = ""
    if "public_profile_found" in signals:
        signal_text = "with public profiles on multiple platforms"
    elif signals:
        signal_text = f"with {len(signals)} public signal type(s) detected"
    else:
        signal_text = "with limited public signals"
    return f"Overall {risk_label.lower()} ({score:.2f}) {signal_text}"


def _describe_verdict(profile: CanonicalProfile, exposure: dict) -> str:
    score = exposure.get("score", 0.0)
    risk_level = exposure.get("risk_level", "low")
    name = profile.display_name or "this target"

    if risk_level == "critical":
        return f"Critical exposure profile for {name}. Immediate review recommended."
    if risk_level == "high":
        return f"High exposure profile for {name}. Significant public footprint identified."
    if risk_level == "medium":
        return f"Moderate exposure profile for {name}. Some public footprint present."
    if risk_level == "low":
        return f"Low exposure profile for {name}. Minimal public footprint."
    return f"Unknown exposure level for {name}."
