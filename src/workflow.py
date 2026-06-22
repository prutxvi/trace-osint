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

from src.sources.username_check import check_username_bulk
from src.sources.email_intel import get_email_intelligence
from src.sources.domain_intel import get_domain_intelligence
from src.sources.wayback_intel import get_wayback_intelligence
from src.sources.github_intel import get_github_intelligence
from src.sources.ip_intel import get_ip_intelligence
from src.sources.india_intel import get_india_intelligence
from src.sources.correlation import correlate_entities, build_correlation_summary


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
        """Generate investigation plan from clues."""
        steps = []
        step_id = 0

        for clue in self.case.clues:
            entity_type = detect_entity_type(clue)

            if entity_type == "email":
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="email_intel",
                    description=f"Full email intelligence: {clue}",
                    source="multi_source", risk_level="low",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="search_email",
                    description=f"Search for email: {clue}",
                    source="public_search", risk_level="low",
                ))

            elif entity_type == "username":
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="username_check",
                    description=f"Check username across 400+ platforms: {clue}",
                    source="multi_platform", risk_level="low",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="github_intel",
                    description=f"GitHub intelligence: {clue}",
                    source="github_api", risk_level="low",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="search_username",
                    description=f"Search for username: {clue}",
                    source="public_search", risk_level="low",
                ))

            elif entity_type == "domain":
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="domain_intel",
                    description=f"Full domain intelligence: {clue}",
                    source="multi_source", risk_level="low",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="search_domain",
                    description=f"Search for domain: {clue}",
                    source="public_search", risk_level="low",
                ))

            elif entity_type == "url":
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="fetch_url",
                    description=f"Fetch URL content: {clue}",
                    source="public_webpage", risk_level="medium",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="wayback_intel",
                    description=f"Wayback Machine history: {clue}",
                    source="archive_org", risk_level="low",
                ))

            elif entity_type == "phone":
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="phone_intel",
                    description=f"Phone intelligence: {clue}",
                    source="phone_lookup", risk_level="low",
                ))

            elif entity_type == "ip_address":
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="ip_intel",
                    description=f"IP geolocation: {clue}",
                    source="ip_api", risk_level="low",
                ))

            else:
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="search_person",
                    description=f"Search for person: {clue}",
                    source="public_search", risk_level="low",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="india_intel",
                    description=f"Indian public records: {clue}",
                    source="india_kanoon", risk_level="low",
                ))

        step_id += 1
        steps.append(PlanStep(
            step_id=step_id, action="correlate",
            description="Cross-correlate all findings and resolve entities",
            source="analysis", risk_level="low",
        ))

        return InvestigationPlan(
            case_id=self.case.case_id,
            objective=f"Resolve {len(self.case.clues)} clue(s) to comprehensive intelligence",
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
                findings = self._execute_step(step)
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

            time.sleep(0.2)

        self.case.findings = self._collected_findings

    def _execute_step(self, step: PlanStep) -> list[Finding]:
        """Execute a single investigation step."""
        clue = step.description.split(": ", 1)[-1] if ": " in step.description else ""

        if step.action == "email_intel":
            return get_email_intelligence(clue)
        elif step.action == "username_check":
            return check_username_bulk(clue)
        elif step.action == "github_intel":
            return get_github_intelligence(clue)
        elif step.action == "domain_intel":
            return get_domain_intelligence(clue)
        elif step.action == "wayback_intel":
            return get_wayback_intelligence(clue)
        elif step.action == "ip_intel":
            return get_ip_intelligence(clue)
        elif step.action == "phone_intel":
            return self._phone_intel(clue)
        elif step.action == "india_intel":
            return get_india_intelligence(clue)
        elif step.action == "search_email":
            return search_email(clue)
        elif step.action == "search_username":
            return search_username(clue)
        elif step.action == "search_domain":
            return search_domain(clue)
        elif step.action == "search_person":
            return public_search(f'"{clue}"', entity_type=EntityType.PERSON)
        elif step.action == "fetch_url":
            finding = fetch_url_as_finding(clue)
            return [finding] if finding else []
        elif step.action == "correlate":
            return []
        return []

    def _phone_intel(self, phone: str) -> list[Finding]:
        """Phone intelligence gathering."""
        from src.sources.india_intel import indian_phone_lookup
        from src.sources.search import public_search

        findings = []
        lookup = indian_phone_lookup(phone)
        if lookup.get("valid"):
            finding = Finding(
                entity_type=EntityType.PHONE,
                entity_value=phone,
                label=f"Phone Lookup: {phone}",
                summary=f"Carrier: {lookup['carrier']} | Country: {lookup['country']} | Line: {lookup['line_type']}",
                details=lookup,
                source=Source(
                    url=f"tel:{phone}",
                    title="Phone Intelligence",
                    source_type="public_api",
                    reliability=0.7,
                ),
                confidence=Confidence(score=0.7, reasoning="Phone carrier detection"),
            )
            finding.confidence.compute_level()
            findings.append(finding)

        search_results = public_search(f'"{phone}"', entity_type=EntityType.PHONE)
        findings.extend(search_results)

        return findings

    def _resolve_entities(self):
        """Resolve and deduplicate entities from findings."""
        self._resolved_entities = correlate_entities(self.case.findings)
        self.case.entities = self._resolved_entities
        self.audit.log(self.case.phase, "resolver", "entities_resolved",
                      f"Resolved {len(self.case.entities)} entities")

    def _analyze(self):
        """Analyze findings."""
        self.audit.log(self.case.phase, "analyst", "analysis_started",
                      f"Analyzing {len(self.case.findings)} findings")

        summary = build_correlation_summary(self.case.entities, self.case.findings)
        high_conf = [f for f in self.case.findings if f.confidence.level == "high"]
        self._emit_event(f"Analysis: {len(high_conf)} high-confidence findings, {summary['total_entities']} entities")

        self.audit.log(self.case.phase, "analyst", "analysis_complete",
                      f"Completed analysis")

    def _finalize_audit(self):
        """Merge audit events into the case."""
        self.audit.merge_into_case(self.case)
