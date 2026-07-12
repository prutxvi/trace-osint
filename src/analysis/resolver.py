# -*- coding: utf-8 -*-
"""TRACE OSINT - Primary target selection and noise filtering."""

from __future__ import annotations

from collections import defaultdict

from src.models import CanonicalProfile, Case, ClueType, ParsedClue
from src.sources.clue_parser import is_common_name


def resolve_primary_target(case: Case) -> tuple[list[CanonicalProfile], str]:
    """Choose a single primary target profile and relate others to it."""
    profiles = list(case.canonical_profiles)
    if not profiles:
        case.primary_target_profile_id = ""
        return profiles, "No canonical profiles were strong enough to anchor a primary target."

    anchor_tokens = _build_anchor_tokens(case.parsed_clues)
    scored = []
    for profile in profiles:
        score, reasons = _score_profile(profile, anchor_tokens, case.case_mode)
        scored.append((score, reasons, profile))

    scored.sort(key=lambda item: item[0], reverse=True)
    primary_score, reasons, primary = scored[0]
    primary.is_primary = True
    primary.relationship_to_primary = "primary"
    case.primary_target_profile_id = primary.id

    summary = _relationship_summary(primary, reasons, primary_score)
    primary.summary = summary if summary else primary.summary

    for score, _, profile in scored[1:]:
        profile.is_primary = False
        if _should_mark_unrelated(profile, primary, case.parsed_clues, score):
            profile.relationship_to_primary = "unrelated"
            if profile.verification == "weak":
                profile.verification = "unrelated"
        else:
            profile.relationship_to_primary = "related"

    return [item[2] for item in scored], summary


def _build_anchor_tokens(parsed_clues: list[ParsedClue]) -> dict[str, set[str]]:
    anchors = defaultdict(set)
    for clue in parsed_clues:
        anchors[clue.type.value].add(clue.normalized.lower())
    return anchors


def _score_profile(profile: CanonicalProfile, anchors: dict[str, set[str]], case_mode: str) -> tuple[float, list[str]]:
    score = profile.confidence_score
    reasons: list[str] = []
    identifiers = {item.lower() for item in profile.identifiers + profile.profile_urls + profile.websites + profile.linked_accounts}
    names = {item.lower() for item in profile.names}

    if identifiers.intersection(anchors.get(ClueType.EMAIL.value, set())):
        score += 3.0
        reasons.append("shared email")
    if identifiers.intersection(anchors.get(ClueType.PHONE.value, set())):
        score += 2.5
        reasons.append("shared phone")
    if identifiers.intersection(anchors.get(ClueType.GITHUB_PROFILE.value, set())):
        score += 3.0
        reasons.append("direct GitHub profile")
    if identifiers.intersection(anchors.get(ClueType.LINKEDIN_PROFILE.value, set())):
        score += 3.0
        reasons.append("direct LinkedIn profile")
    if identifiers.intersection(anchors.get(ClueType.USERNAME.value, set())):
        score += 2.0
        reasons.append("shared username")
    if identifiers.intersection(anchors.get(ClueType.GITHUB_USERNAME.value, set())):
        score += 2.5
        reasons.append("shared GitHub username")
    if identifiers.intersection(anchors.get(ClueType.URL.value, set())):
        score += 1.5
        reasons.append("shared profile website")
    if names.intersection(anchors.get(ClueType.NAME.value, set())):
        score += 0.8
        reasons.append("matching name")

    if profile.main_handle:
        score += 0.3
    if profile.avatar_url:
        score += 0.2
    if profile.location:
        score += 0.2

    if case_mode == "person" and profile.mode == "person":
        score += 0.2

    return score, reasons


def _should_mark_unrelated(profile: CanonicalProfile, primary: CanonicalProfile, parsed_clues: list[ParsedClue], score: float) -> bool:
    if score >= 1.5:
        return False

    primary_identifiers = {item.lower() for item in primary.identifiers + primary.profile_urls + primary.websites + primary.linked_accounts}
    profile_identifiers = {item.lower() for item in profile.identifiers + profile.profile_urls + profile.websites + profile.linked_accounts}
    if primary_identifiers.intersection(profile_identifiers):
        return False

    anchor_names = [clue.normalized for clue in parsed_clues if clue.type == ClueType.NAME]
    if profile.names and anchor_names and any(name.lower() in {item.lower() for item in profile.names} for name in anchor_names):
        if is_common_name(anchor_names[0]) or is_common_name(profile.names[0]):
            return True
        if not (profile.location and primary.location and profile.location.lower() == primary.location.lower()):
            return True

    if not profile_identifiers.intersection(primary_identifiers):
        return True
    return False


def _relationship_summary(primary: CanonicalProfile, reasons: list[str], score: float) -> str:
    if not primary.display_name:
        return ""
    if reasons:
        reason_text = ", ".join(reasons[:3])
        return f"Primary target anchored to {primary.display_name} via {reason_text}."
    return f"Primary target anchored to {primary.display_name} with composite confidence {score:.2f}."
