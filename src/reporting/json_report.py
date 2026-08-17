# -*- coding: utf-8 -*-
from __future__ import annotations
"""TRACE OSINT Copilot - JSON Report Generator"""

import json
from datetime import datetime, timezone

from src.models import Case
from src.scoring.exposure import compute_exposure_score
from src.sources.case_synthesis import split_findings_by_focus


def generate_json_report(case: Case) -> str:
    """Generate a structured JSON evidence report."""
    exposure = compute_exposure_score(case.findings, case.entities)
    person_findings, infra_findings = split_findings_by_focus(case.findings)

    report = {
        "case_id": case.case_id,
        "case_name": case.name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy_mode": case.policy_mode,
        "case_mode": case.case_mode,
        "status": case.status,
        "phase": case.phase,
        "story_card": case.story_card.model_dump() if case.story_card else None,
        "plain_language_summary": case.plain_language_summary,
        "executive_summary": _build_summary(case, exposure),
        "clues": case.clues,
        "parsed_clues": [clue.model_dump() for clue in case.parsed_clues],
        "findings": [_serialize_finding(f) for f in person_findings],
        "infrastructure_findings": [_serialize_finding(f) for f in infra_findings],
        "entities": [_serialize_entity(e) for e in case.entities],
        "canonical_profiles": [profile.model_dump() for profile in case.canonical_profiles],
        "primary_target_profile_id": case.primary_target_profile_id,
        "timeline": [event.model_dump() for event in case.timeline],
        "investigation_notes": [note.model_dump() for note in case.investigation_notes],
        "recommended_pivots": case.recommended_pivots,
        "sources": _collect_sources(case),
        "confidence_summary": _confidence_summary(case),
        "exposure_assessment": exposure,
        "gaps": [
            "Limited to public, read-only sources",
            "No private account access",
            "No breach database queries",
            "Results may be incomplete",
        ],
        "next_steps": [
            "Cross-reference high-confidence findings",
            "Resolve low-confidence matches",
            "Search additional public platforms",
            "Review identified gaps",
        ],
        "audit_trail": [_serialize_event(e) for e in case.audit_log],
        "metadata": {
            "created_at": case.created_at,
            "updated_at": case.updated_at,
            "finding_count": len(case.findings),
            "person_finding_count": len(person_findings),
            "infra_finding_count": len(infra_findings),
            "entity_count": len(case.entities),
            "audit_event_count": len(case.audit_log),
        },
    }

    return json.dumps(report, indent=2, default=str)


def _build_summary(case: Case, exposure: dict) -> str:
    return (
        f"Investigation of {len(case.clues)} clue(s) yielded "
        f"{len(case.findings)} findings and {len(case.entities)} resolved entities. "
        f"Exposure level: {exposure['risk_level']} ({exposure['score']:.2f})."
    )


def _serialize_finding(f) -> dict:
    return {
        "id": f.id,
        "entity_type": f.entity_type.value,
        "entity_value": f.entity_value,
        "label": f.label,
        "summary": f.summary,
        "details": f.details,
        "source": {
            "url": f.source.url,
            "title": f.source.title,
            "source_type": f.source.source_type,
            "reliability": f.source.reliability,
            "retrieved_at": f.source.retrieved_at,
        },
        "confidence": {
            "score": f.confidence.score,
            "level": f.confidence.level,
            "reasoning": f.confidence.reasoning,
        },
        "verification": f.verification,
        "verification_reason": f.verification_reason,
        "created_at": f.created_at,
    }


def _serialize_entity(e) -> dict:
    return {
        "id": e.id,
        "type": e.type.value,
        "value": e.value,
        "aliases": e.aliases,
        "confidence": {
            "score": e.confidence.score,
            "level": e.confidence.level,
            "reasoning": e.confidence.reasoning,
        },
        "verification": e.verification,
        "verification_reason": e.verification_reason,
        "finding_ids": e.finding_ids,
    }


def _collect_sources(case: Case) -> list[dict]:
    sources = {}
    for f in case.findings:
        key = f.source.url or f"unknown-{f.id}"
        if key not in sources:
            sources[key] = {
                "url": f.source.url,
                "title": f.source.title,
                "source_type": f.source.source_type,
                "reliability": f.source.reliability,
            }
    return list(sources.values())


def _confidence_summary(case: Case) -> dict:
    levels = {"high": 0, "medium": 0, "low": 0, "minimal": 0}
    for f in case.findings:
        levels[f.confidence.level] = levels.get(f.confidence.level, 0) + 1
    return {
        "distribution": levels,
        "total": len(case.findings),
        "high_confidence_percentage": (
            round(levels["high"] / max(len(case.findings), 1) * 100, 1)
        ),
    }


def _serialize_event(e) -> dict:
    return {
        "timestamp": e.timestamp,
        "trace_id": e.trace_id,
        "phase": e.phase,
        "agent": e.agent,
        "action": e.action,
        "detail": e.detail,
        "status": e.status,
        "source_ref": e.source_ref,
    }
