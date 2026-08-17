# -*- coding: utf-8 -*-
from __future__ import annotations
"""TRACE OSINT - STIX/MISP-Lite Export Module

Generates a simple STIX-compatible JSON export of investigation findings.
This is a lightweight export for interoperability with other OSINT tools.
"""

import json
from datetime import datetime, timezone
from typing import Optional

from src.models import Case, Finding, Entity, EntityType


def export_stix_json(case: Case, output_path: str) -> str:
    """Export case data as a STIX-like JSON bundle.

    Returns the path to the saved file.
    """
    bundle = {
        "type": "bundle",
        "id": f"bundle--{case.case_id}",
        "spec_version": "2.1",
        "created": case.created_at,
        "objects": [],
    }

    identity = _build_identity_object(case)
    bundle["objects"].append(identity)

    for finding in case.findings:
        obs = _finding_to_observed_data(finding, case.case_id)
        if obs:
            bundle["objects"].append(obs)

    for entity in case.entities:
        rels = _entity_to_relationships(entity, case.case_id)
        bundle["objects"].extend(rels)

    if case.story_card:
        note = _story_card_to_note(case)
        bundle["objects"].append(note)

    report = _build_report(case)
    bundle["objects"].append(report)

    with open(output_path, "w") as f:
        json.dump(bundle, f, indent=2, default=str)

    return output_path


def _build_identity_object(case: Case) -> dict:
    """Build a STIX Identity object from the case."""
    name = case.name or "Unknown Target"
    primary = case.canonical_profiles[0] if case.canonical_profiles else None
    if primary and primary.display_name:
        name = primary.display_name

    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": f"identity--{case.case_id}",
        "created": case.created_at,
        "modified": case.updated_at,
        "name": name,
        "identity_class": "individual",
        "description": f"TRACE OSINT investigation: {case.case_mode} mode",
    }

    if primary:
        if primary.location:
            identity["sectors"] = []
            identity["contact_information"] = primary.location
        if primary.profile_urls:
            identity["contact_information"] = ", ".join(primary.profile_urls[:3])

    return identity


def _finding_to_observed_data(finding: Finding, case_id: str) -> Optional[dict]:
    """Convert a Finding to a STIX Observed Data object."""
    if not finding.entity_value:
        return None

    obs = {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": f"observed-data--{finding.id}",
        "created": finding.created_at,
        "modified": finding.created_at,
        "first_observed": finding.created_at,
        "last_observed": finding.created_at,
        "number_observed": 1,
        "created_by_ref": f"identity--{case_id}",
        "objects": {},
    }

    obj_key = "0"
    obj_type = _entity_type_to_stix(finding.entity_type)
    obs["objects"][obj_key] = {
        "type": obj_type,
        "value": finding.entity_value,
    }

    if finding.entity_type == EntityType.EMAIL:
        obs["objects"][obj_key] = {
            "type": "email-addr",
            "value": finding.entity_value,
        }
    elif finding.entity_type == EntityType.DOMAIN:
        obs["objects"][obj_key] = {
            "type": "domain-name",
            "value": finding.entity_value,
        }
    elif finding.entity_type == EntityType.IP_ADDRESS:
        obs["objects"][obj_key] = {
            "type": "ipv4-addr",
            "value": finding.entity_value,
        }
    elif finding.entity_type == EntityType.URL:
        obs["objects"][obj_key] = {
            "type": "url",
            "value": finding.entity_value,
        }

    obs["labels"] = [finding.source.source_type, finding.verification]
    obs["confidence"] = int(finding.confidence.score * 100)

    return obs


def _entity_type_to_stix(entity_type: EntityType) -> str:
    """Map TRACE entity type to STIX object type."""
    mapping = {
        EntityType.EMAIL: "email-addr",
        EntityType.DOMAIN: "domain-name",
        EntityType.IP_ADDRESS: "ipv4-addr",
        EntityType.URL: "url",
        EntityType.USERNAME: "user-account",
        EntityType.PHONE: "phone-number",
        EntityType.PERSON: "identity",
        EntityType.ORGANIZATION: "identity",
    }
    return mapping.get(entity_type, "artifact")


def _entity_to_relationships(entity: Entity, case_id: str) -> list[dict]:
    """Convert entity linked_entity_ids to STIX Relationship objects."""
    relationships = []
    for linked_id in entity.linked_entity_ids:
        rel = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{entity.id}-{linked_id}",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "relationship_type": "related-to",
            "source_ref": f"observed-data--{entity.id}",
            "target_ref": f"observed-data--{linked_id}",
            "confidence": int(entity.confidence.score * 100),
        }
        relationships.append(rel)
    return relationships


def _story_card_to_note(case: Case) -> dict:
    """Convert story card to a STIX Note object."""
    sc = case.story_card
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": f"note--{case.case_id}-story",
        "created": case.updated_at,
        "modified": case.updated_at,
        "created_by_ref": f"identity--{case.case_id}",
        "abstract": "TRACE Story Card",
        "content": (
            f"Who: {sc.who_is_this}\n"
            f"Main IDs: {sc.main_ids}\n"
            f"Risk: {sc.risk_summary}\n"
            f"Verdict: {sc.verdict}"
        ),
        "object_refs": [f"identity--{case.case_id}"],
    }


def _build_report(case: Case) -> dict:
    """Build a STIX Report object summarizing the investigation."""
    return {
        "type": "report",
        "spec_version": "2.1",
        "id": f"report--{case.case_id}",
        "created": case.created_at,
        "modified": case.updated_at,
        "created_by_ref": f"identity--{case.case_id}",
        "name": f"TRACE Investigation: {case.name}",
        "published": case.updated_at,
        "report_types": ["threat-report"],
        "object_refs": [f"identity--{case.case_id}"],
        "description": (
            f"OSINT investigation with {len(case.findings)} findings, "
            f"{len(case.entities)} entities resolved, "
            f"risk level: {getattr(case, 'story_card', None).verdict if case.story_card else 'N/A'}"
        ),
    }


def generate_stix_summary(case: Case) -> str:
    """Generate a human-readable summary of the STIX export."""
    lines = [
        f"STIX Export Summary for {case.case_id}",
        f"  Findings: {len(case.findings)}",
        f"  Entities: {len(case.entities)}",
        f"  Linked pairs: {sum(len(e.linked_entity_ids) for e in case.entities) // 2}",
        f"  Report: TRACE Investigation: {case.name}",
    ]
    return "\n".join(lines)
