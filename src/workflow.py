"""TRACE OSINT Copilot - Investigation Workflow Engine"""

import time
from typing import Optional

from src.models import (
    Case, InvestigationPlan, PlanStep, Finding, Entity,
    EntityType, Confidence, AuditEvent,
)
from src.config import PolicyMode, BLOCKED_ACTIONS
from src.audit.logger import AuditLogger
from src.sources.search import public_search, search_username, search_email, search_domain
from src.sources.fetch import fetch_url_as_finding
from src.sources.normalize import (
    normalize_email, normalize_username, normalize_url,
    normalize_domain, detect_entity_type, are_likely_same_entity,
)
from src.scoring.confidence import merge_confidences, entity_confidence_from_findings
from src.parsers.text_extract import extract_all_entities


class WorkflowEngine:
    """Orchestrates the multi-phase investigation workflow."""

    def __init__(self, case: Case, on_event=None, on_phase=None, on_tool=None):
        self.case = case
        self.audit = AuditLogger(case.case_id)
        self._on_event = on_event or (lambda *a: None)
        self._on_phase = on_phase or (lambda *a: None)
        self._on_tool = on_tool or (lambda *a: None)
        self._collected_findings: list[Finding] = []
        self._resolved_entities: list[Entity] = []

    def _emit_event(self, msg: str):
        self._on_event(msg)

    def _emit_phase(self, phase: str, detail: str = ""):
        self.case.phase = phase
        self._on_phase(phase, detail)

    def _emit_tool(self, name: str, status: str, detail: str = ""):
        self._on_tool(name, status, detail)

    def _check_policy(self, action: str) -> bool:
        action_lower = action.lower()
        for blocked in BLOCKED_ACTIONS:
            if blocked in action_lower:
                self.audit.log_blocked(
                    self.case.phase, "workflow", action,
                    f"Blocked: matches policy violation '{blocked}'"
                )
                self._emit_tool("policy", "blocked", f"Action blocked: {blocked}")
                return False
        return True

    def run(self):
        """Execute the full investigation workflow."""
        self._emit_phase("planning", "Generating investigation plan...")
        self.audit.log(self.case.phase, "workflow", "investigation_start",
                      f"Clues: {len(self.case.clues)}")
        self._emit_event(f"Starting investigation with {len(self.case.clues)} clue(s)")

        plan = self._generate_plan()
        self.case.plan = plan
        self.audit.log(self.case.phase, "planner", "plan_generated",
                      f"Steps: {len(plan.steps)}")
        self._emit_event(f"Plan generated: {len(plan.steps)} steps")

        self._emit_phase("collecting", "Executing collection plan...")
        self._execute_plan(plan)

        self._emit_phase("resolving", "Resolving and normalizing entities...")
        self._resolve_entities()

        self._emit_phase("analyzing", "Analyzing findings...")
        self._analyze()

        self._emit_phase("reporting", "Generating reports...")
        self.case.status = "complete"
        self.audit.log(self.case.phase, "workflow", "investigation_complete",
                      f"Findings: {len(self.case.findings)}, Entities: {len(self.case.entities)}")
        self._emit_event("Investigation complete")

        self._finalize_audit()

    def _generate_plan(self) -> InvestigationPlan:
        """Generate an investigation plan from clues."""
        steps = []
        step_id = 0

        for clue in self.case.clues:
            entity_type = detect_entity_type(clue)

            if entity_type == "email":
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id,
                    action="search_email",
                    description=f"Search for email: {clue}",
                    source="public_search",
                    risk_level="low",
                ))
            elif entity_type == "username":
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id,
                    action="search_username",
                    description=f"Search for username: {clue}",
                    source="public_search",
                    risk_level="low",
                ))
            elif entity_type == "domain":
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id,
                    action="search_domain",
                    description=f"Search for domain: {clue}",
                    source="public_search",
                    risk_level="low",
                ))
            elif entity_type == "url":
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id,
                    action="fetch_url",
                    description=f"Fetch URL content: {clue}",
                    source="public_webpage",
                    risk_level="medium",
                ))
            else:
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id,
                    action="search_person",
                    description=f"Search for person: {clue}",
                    source="public_search",
                    risk_level="low",
                ))

        step_id += 1
        steps.append(PlanStep(
            step_id=step_id,
            action="cross_reference",
            description="Cross-reference all collected findings",
            source="analysis",
            risk_level="low",
        ))

        return InvestigationPlan(
            case_id=self.case.case_id,
            objective=f"Resolve {len(self.case.clues)} clue(s) to public-source intelligence",
            steps=steps,
        )

    def _execute_plan(self, plan: InvestigationPlan):
        """Execute each step in the investigation plan."""
        for step in plan.steps:
            if not self._check_policy(step.action):
                step.status = "blocked"
                continue

            step.status = "running"
            self._emit_tool(step.action, "running", step.description)
            self.audit.log_tool(self.case.phase, "collector", step.action, step.description)

            try:
                if step.action == "search_email":
                    findings = self._collect_email(step)
                elif step.action == "search_username":
                    findings = self._collect_username(step)
                elif step.action == "search_domain":
                    findings = self._collect_domain(step)
                elif step.action == "fetch_url":
                    findings = self._collect_url(step)
                elif step.action == "search_person":
                    findings = self._collect_person(step)
                elif step.action == "cross_reference":
                    findings = self._cross_reference()
                else:
                    findings = []

                self._collected_findings.extend(findings)
                step.status = "complete"
                step.result = f"Collected {len(findings)} finding(s)"
                self._emit_tool(step.action, "ok", f"{len(findings)} finding(s)")
                self._emit_event(f"Step {step.step_id}: {step.action} -> {len(findings)} results")

            except Exception as e:
                step.status = "error"
                step.result = str(e)
                self.audit.log_error(self.case.phase, "collector", step.action, str(e))
                self._emit_tool(step.action, "error", str(e))

            time.sleep(0.3)

        self.case.findings = self._collected_findings

    def _collect_email(self, step: PlanStep) -> list[Finding]:
        clue = step.description.split(": ")[-1]
        return search_email(clue)

    def _collect_username(self, step: PlanStep) -> list[Finding]:
        clue = step.description.split(": ")[-1]
        return search_username(clue)

    def _collect_domain(self, step: PlanStep) -> list[Finding]:
        clue = step.description.split(": ")[-1]
        return search_domain(clue)

    def _collect_url(self, step: PlanStep) -> list[Finding]:
        url = step.description.split(": ")[-1]
        finding = fetch_url_as_finding(url)
        return [finding] if finding else []

    def _collect_person(self, step: PlanStep) -> list[Finding]:
        clue = step.description.split(": ")[-1]
        return public_search(f'"{clue}"', entity_type=EntityType.PERSON)

    def _cross_reference(self) -> list[Finding]:
        """Cross-reference collected findings for additional signals."""
        additional = []
        for finding in self._collected_findings[:5]:
            if finding.summary:
                entities = extract_all_entities(finding.summary)
                for email in entities.get("emails", [])[:2]:
                    extra = search_email(email)
                    additional.extend(extra)
                for url in entities.get("urls", [])[:2]:
                    extra_f = fetch_url_as_finding(url)
                    if extra_f:
                        additional.append(extra_f)
        return additional

    def _resolve_entities(self):
        """Normalize and deduplicate entities from findings."""
        entity_map: dict[str, Entity] = {}

        for finding in self.case.findings:
            entity_type = finding.entity_type
            value = self._extract_clean_value(finding)

            canonical = self._canonicalize(value, entity_type)

            matched = False
            for eid, entity in entity_map.items():
                if entity.type == entity_type and are_likely_same_entity(
                    entity.value, canonical, entity_type.value
                ):
                    if value not in entity.aliases:
                        entity.aliases.append(value)
                    entity.finding_ids.append(finding.id)
                    matched = True
                    break

            if not matched:
                entity = Entity(
                    type=entity_type,
                    value=canonical,
                    aliases=[value] if value != canonical else [],
                    finding_ids=[finding.id],
                )
                entity_map[entity.id] = entity

        for entity in entity_map.values():
            contributing = [
                f for f in self.case.findings
                if f.id in entity.finding_ids
            ]
            entity.confidence = entity_confidence_from_findings(contributing)

        self.case.entities = list(entity_map.values())
        self._resolved_entities = self.case.entities
        self.audit.log(self.case.phase, "resolver", "entities_resolved",
                      f"Resolved {len(self.case.entities)} entities")

    def _extract_clean_value(self, finding) -> str:
        """Extract clean entity value from a finding, using details when available."""
        details = finding.details
        if details.get("url"):
            from src.sources.normalize import normalize_domain, normalize_url
            import re
            url = details["url"]
            domain_match = re.search(r"https?://([^/]+)", url)
            if domain_match:
                return normalize_domain(domain_match.group(1))
            return normalize_url(url)
        if details.get("title"):
            return details["title"][:100]
        return finding.entity_value

    def _canonicalize(self, value: str, entity_type: EntityType) -> str:
        """Canonicalize an entity value based on type."""
        if entity_type == EntityType.EMAIL:
            return normalize_email(value)
        elif entity_type == EntityType.USERNAME:
            return normalize_username(value)
        elif entity_type == EntityType.URL:
            return normalize_url(value)
        elif entity_type == EntityType.DOMAIN:
            return normalize_domain(value)
        return value

    def _analyze(self):
        """Perform analysis on resolved findings."""
        self.audit.log(self.case.phase, "analyst", "analysis_started",
                      f"Analyzing {len(self.case.findings)} findings")

        high_conf = [f for f in self.case.findings if f.confidence.level == "high"]
        self._emit_event(f"Analysis: {len(high_conf)} high-confidence findings")

        self.audit.log(self.case.phase, "analyst", "analysis_complete",
                      f"Completed analysis")

    def _finalize_audit(self):
        """Merge audit events into the case."""
        self.audit.merge_into_case(self.case)
