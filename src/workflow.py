"""TRACE OSINT Copilot - Investigation Workflow Engine"""

import time
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.models import (
    Case, InvestigationPlan, PlanStep, Finding, Entity,
    EntityType, Confidence, AuditEvent, Source,
)
from src.config import PolicyMode, BLOCKED_ACTIONS, MAX_CONCURRENT_REQUESTS, USE_CONCURRENT
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
from src.sources.shodan_intel import get_shodan_intelligence
from src.sources.opencorporates_intel import get_opencorporates_intelligence
from src.sources.wikidata_intel import get_wikidata_intelligence
from src.sources.people_search import get_truepeoplesearch_intelligence
from src.sources.breach_intel import get_breach_intelligence
from src.sources.court_intel import get_court_intelligence
from src.sources.identity_collapse import collapse_identity, IdentityProfile
from src.sources.secret_hunter import get_secret_leak_intelligence
from src.sources.investigation_graph import generate_interactive_graph, generate_graph_summary
from src.sources.ai_pivot import analyze_findings, suggest_pivots, generate_ai_summary
from src.sources.tech_fingerprint import get_tech_stack_intelligence
from src.sources.subdomain_takeover import get_subdomain_takeover_intelligence
from src.sources.commit_unmasker import get_commit_author_intelligence
from src.sources.clue_parser import detect_case_mode, parse_clues
from src.sources.github_profile_intel import get_github_profile_intelligence
from src.sources.linkedin_profile_intel import get_linkedin_profile_intelligence
from src.sources.profile_page_extract import extract_profile_page_intelligence
from src.reporting.stix_export import export_stix_json
from src.sources.case_memory import (
    save_case_memory, save_finding_memory, update_pattern,
    update_source_effectiveness, get_best_sources, get_case_stats,
)
from src.sources.case_synthesis import (
    apply_verification_labels,
    build_canonical_profiles,
    build_investigation_notes,
    build_plain_language_summary,
    build_story_card,
    build_timeline,
)
from src.scoring.exposure import compute_exposure_score
from src.sources.primary_target_resolver import resolve_primary_target


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

    def _emit_tool_group(self, group_name: str, tools: list[tuple[str, str, str]]):
        """Emit a group of tool activities with a group header."""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        from rich.console import Console
        console = Console()
        console.print(f"  [dim]{timestamp}[/dim] [bold cyan]●[/bold cyan] [bold]{group_name}[/bold]")
        for name, status, detail in tools:
            self._emit_tool(name, status, detail)

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
        self._prepare_case_context()
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

        self._emit_phase("verifying", "Checking which findings are corroborated...")
        self._verify_findings()

        self._emit_phase("resolving", "Resolving and normalizing entities...")
        self._resolve_entities()

        self._emit_phase("analyzing", "Analyzing findings and building identity...")
        self._analyze()

        self._emit_phase("reporting", "Generating reports and graphs...")
        self._generate_advanced_outputs()
        self._synthesize_case()

        self.case.status = "complete"
        self.audit.log(self.case.phase, "workflow", "investigation_complete",
                      f"Findings: {len(self.case.findings)}, Entities: {len(self.case.entities)}")
        self._emit_event("Investigation complete")

        self._finalize_audit()
        self._save_to_memory()

    def _prepare_case_context(self):
        """Normalize clues into typed anchors and select case mode."""
        if not self.case.parsed_clues:
            self.case.parsed_clues = parse_clues(self.case.clues)
        self.case.case_mode = detect_case_mode(self.case.parsed_clues)
        self._emit_event(
            f"NOTE: Case mode set to {self.case.case_mode}. Primary clues: {', '.join(clue.type.value for clue in self.case.parsed_clues[:3])}"
        )

    def _generate_plan(self) -> InvestigationPlan:
        """Generate investigation plan from clues."""
        steps = []
        step_id = 0

        parsed_clues = self.case.parsed_clues or parse_clues(self.case.clues)

        for parsed in parsed_clues:
            clue = parsed.normalized or parsed.raw
            entity_type = parsed.type.value

            if entity_type == "github_profile":
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="github_profile",
                    description=f"Direct GitHub profile extraction: {clue}",
                    source="github_api", risk_level="low",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="profile_page",
                    description=f"Public profile page extraction: {clue}",
                    source="public_webpage", risk_level="low",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="commit_unmask",
                    description=f"Git commit author extraction: {clue}",
                    source="github_api", risk_level="low",
                ))
                continue

            if entity_type == "linkedin_profile":
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="linkedin_profile",
                    description=f"Direct LinkedIn profile extraction: {clue}",
                    source="public_webpage", risk_level="low",
                ))
                continue

            if entity_type == "github_username":
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="github_profile",
                    description=f"Direct GitHub profile extraction: {clue}",
                    source="github_api", risk_level="low",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="github_intel",
                    description=f"GitHub intelligence: {clue}",
                    source="github_api", risk_level="low",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="commit_unmask",
                    description=f"Git commit author extraction: {clue}",
                    source="github_api", risk_level="low",
                ))
                continue

            if entity_type == "email":
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="email_intel",
                    description=f"Full email intelligence: {clue}",
                    source="multi_source", risk_level="low",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="breach_check",
                    description=f"Breach check: {clue}",
                    source="breach_directory", risk_level="low",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="people_search",
                    description=f"People search: {clue}",
                    source="truepeoplesearch", risk_level="low",
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
                    step_id=step_id, action="github_profile",
                    description=f"Direct GitHub profile extraction: {clue}",
                    source="github_api", risk_level="low",
                ))
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
                    step_id=step_id, action="wikidata_intel",
                    description=f"Wikidata entity lookup: {clue}",
                    source="wikidata", risk_level="low",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="people_search",
                    description=f"People search: {clue}",
                    source="truepeoplesearch", risk_level="low",
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
                    step_id=step_id, action="shodan_domain",
                    description=f"Shodan infrastructure scan: {clue}",
                    source="shodan", risk_level="low",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="opencorporates",
                    description=f"Company lookup: {clue}",
                    source="opencorporates", risk_level="low",
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
                    step_id=step_id, action="profile_page",
                    description=f"Profile page extraction: {clue}",
                    source="public_webpage", risk_level="low",
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
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="people_search",
                    description=f"People search by phone: {clue}",
                    source="truepeoplesearch", risk_level="low",
                ))

            elif entity_type == "ip_address":
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="shodan_ip",
                    description=f"Shodan IP scan: {clue}",
                    source="shodan", risk_level="low",
                ))
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
                    step_id=step_id, action="wikidata_intel",
                    description=f"Wikidata lookup: {clue}",
                    source="wikidata", risk_level="low",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="people_search",
                    description=f"People search: {clue}",
                    source="truepeoplesearch", risk_level="low",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="court_intel",
                    description=f"Court records: {clue}",
                    source="pacer", risk_level="low",
                ))
                step_id += 1
                steps.append(PlanStep(
                    step_id=step_id, action="opencorporates",
                    description=f"Company lookup: {clue}",
                    source="opencorporates", risk_level="low",
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
            objective=f"Resolve {len(self.case.clues)} clue(s) to a {self.case.case_mode} dossier",
            steps=steps,
        )

    def _execute_plan(self, plan: InvestigationPlan):
        """Execute each step in the investigation plan.

        When USE_CONCURRENT is enabled, independent source steps run in parallel
        using a ThreadPoolExecutor capped at MAX_CONCURRENT_REQUESTS. Steps that
        depend on prior results (like 'correlate') always run sequentially.
        """
        from datetime import datetime
        from rich.console import Console
        from rich.rule import Rule
        console = Console()

        source_groups = {}
        for step in plan.steps:
            source = step.source or "unknown"
            if source not in source_groups:
                source_groups[source] = []
            source_groups[source].append(step)

        source_labels = {
            "multi_source": "MULTI-SOURCE INTELLIGENCE",
            "multi_platform": "MULTI-PLATFORM RECONNAISSANCE",
            "github_api": "GITHUB INTELLIGENCE",
            "archive_org": "ARCHIVE INTELLIGENCE",
            "shodan": "INFRASTRUCTURE SCANNING",
            "ip_api": "NETWORK INTELLIGENCE",
            "phone_lookup": "TELEPHONY INTELLIGENCE",
            "public_api": "PUBLIC RECORDS",
            "india_kanoon": "INDIAN PUBLIC RECORDS",
            "pacer": "COURT RECORDS",
            "opencorporates": "CORPORATE INTELLIGENCE",
            "wikidata": "KNOWLEDGE BASE",
            "truepeoplesearch": "PEOPLE SEARCH",
            "breach_directory": "BREACH INTELLIGENCE",
            "public_search": "WEB RECONNAISSANCE",
            "public_webpage": "WEB FETCHING",
            "analysis": "CORRELATION ENGINE",
        }

        non_concurrent_actions = {"correlate", "fetch_url", "profile_page"}

        for source_key, steps in source_groups.items():
            group_label = source_labels.get(source_key, source_key.upper())
            timestamp = datetime.now().strftime("%H:%M:%S")
            console.print(f"  [dim]{timestamp}[/dim] [bold cyan]●[/bold cyan] [bold]{group_label}[/bold]")

            concurrent_steps = [s for s in steps if s.action not in non_concurrent_actions]
            sequential_steps = [s for s in steps if s.action in non_concurrent_actions]

            if USE_CONCURRENT and len(concurrent_steps) > 1:
                self._execute_steps_concurrent(concurrent_steps, console)
            else:
                for step in concurrent_steps:
                    self._execute_step_sequential(step, console)

            for step in sequential_steps:
                self._execute_step_sequential(step, console)

            console.print()

        self.case.findings = self._collected_findings

    def _execute_step_sequential(self, step: PlanStep, console):
        """Execute a single step sequentially with policy check."""
        clue = step.description.split(": ", 1)[-1] if ": " in step.description else ""

        if not self._check_policy(step.action):
            step.status = "blocked"
            self._emit_tool(step.action, "blocked", "Policy violation detected")
            return

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
            self._log_step_notes(findings, step, clue)
        except Exception as e:
            step.status = "error"
            step.result = str(e)
            self.audit.log_error(self.case.phase, "collector", step.action, str(e))
            self._emit_tool(step.action, "error", str(e))

        time.sleep(0.15)

    def _execute_steps_concurrent(self, steps: list[PlanStep], console):
        """Execute multiple independent steps in parallel using ThreadPoolExecutor."""
        from datetime import datetime
        to_run = []
        for step in steps:
            clue = step.description.split(": ", 1)[-1] if ": " in step.description else ""
            if not self._check_policy(step.action):
                step.status = "blocked"
                self._emit_tool(step.action, "blocked", "Policy violation detected")
                continue
            step.status = "running"
            self._emit_tool(step.action, "running", step.description)
            self.audit.log_tool(self.case.phase, "collector", step.action, step.description)
            to_run.append((step, clue))

        if not to_run:
            return

        max_workers = min(len(to_run), MAX_CONCURRENT_REQUESTS)

        def _run_step(step, clue):
            try:
                findings = self._execute_step(step)
                return step, findings, None
            except Exception as e:
                return step, [], e

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(_run_step, step, clue): (step, clue)
                for step, clue in to_run
            }
            for future in as_completed(future_map):
                step, findings, error = future.result()
                if error:
                    step.status = "error"
                    step.result = str(error)
                    self.audit.log_error(self.case.phase, "collector", step.action, str(error))
                    self._emit_tool(step.action, "error", str(error))
                else:
                    self._collected_findings.extend(findings)
                    step.status = "complete"
                    step.result = f"Collected {len(findings)} finding(s)"
                    self._emit_tool(step.action, "ok", f"{len(findings)} finding(s)")
                    self._emit_event(f"Step {step.step_id}: {step.action} -> {len(findings)} results")
                    clue = step.description.split(": ", 1)[-1] if ": " in step.description else ""
                    self._log_step_notes(findings, step, clue)

    def _log_step_notes(self, findings: list[Finding], step: PlanStep, clue: str):
        """Emit context notes for notable findings."""
        if findings and step.action == "github_profile":
            profile_name = findings[0].details.get("name") or findings[0].details.get("username") or clue
            self._emit_event(f"NOTE: Found GitHub profile for {profile_name}; extracting name, avatar, bio, website.")
        if findings and step.action == "linkedin_profile":
            profile_name = findings[0].details.get("name") or clue
            self._emit_event(f"NOTE: Found LinkedIn profile for {profile_name}; checking company and location overlap.")
        if findings and step.action == "profile_page":
            page_name = findings[0].details.get("name") or findings[0].details.get("title") or clue
            self._emit_event(f"NOTE: Extracted public profile page signals from {page_name}.")
        if findings and step.action == "commit_unmask":
            author_count = len(findings)
            self._emit_event(f"NOTE: Unmasked {author_count} commit author(s) from public Git history.")

    def _execute_step(self, step: PlanStep) -> list[Finding]:
        """Execute a single investigation step."""
        clue = step.description.split(": ", 1)[-1] if ": " in step.description else ""

        if step.action == "email_intel":
            return get_email_intelligence(clue)
        elif step.action == "username_check":
            return check_username_bulk(clue)
        elif step.action == "github_intel":
            return get_github_intelligence(clue)
        elif step.action == "github_profile":
            return get_github_profile_intelligence(clue)
        elif step.action == "linkedin_profile":
            return get_linkedin_profile_intelligence(clue)
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
        elif step.action == "shodan_ip":
            return get_shodan_intelligence(clue, is_ip=True)
        elif step.action == "shodan_domain":
            return get_shodan_intelligence(clue, is_ip=False)
        elif step.action == "opencorporates":
            return get_opencorporates_intelligence(clue)
        elif step.action == "wikidata_intel":
            return get_wikidata_intelligence(clue)
        elif step.action == "people_search":
            return get_truepeoplesearch_intelligence(clue)
        elif step.action == "breach_check":
            return get_breach_intelligence(clue)
        elif step.action == "court_intel":
            return get_court_intelligence(clue)
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
        elif step.action == "profile_page":
            return extract_profile_page_intelligence(clue)
        elif step.action == "commit_unmask":
            return get_commit_author_intelligence(clue)
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
        from datetime import datetime
        from rich.console import Console
        console = Console()

        timestamp = datetime.now().strftime("%H:%M:%S")
        console.print(f"  [dim]{timestamp}[/dim] [bold cyan]●[/bold cyan] [bold]ENTITY RESOLUTION[/bold]")

        self._emit_tool("correlator", "running", "Cross-referencing and deduplicating entities...")
        self._resolved_entities = correlate_entities(self.case.findings)
        self.case.entities = self._resolved_entities
        self._emit_tool("correlator", "ok", f"Resolved {len(self.case.entities)} unique entities")
        self.audit.log(self.case.phase, "resolver", "entities_resolved",
                      f"Resolved {len(self.case.entities)} entities")

    def _verify_findings(self):
        """Apply plain-language verification states before entity merging."""
        self._emit_tool("verification", "running", "Scoring corroboration across public findings...")
        apply_verification_labels(self.case.findings, [])
        confirmed = sum(1 for finding in self.case.findings if finding.verification == "confirmed")
        probable = sum(1 for finding in self.case.findings if finding.verification == "probable")
        weak = sum(1 for finding in self.case.findings if finding.verification == "weak")
        self._emit_tool("verification", "ok", f"{confirmed} confirmed, {probable} probable, {weak} weak")
        self._emit_event(
            f"NOTE: Verified public evidence. {confirmed} confirmed, {probable} probable, {weak} weak findings."
        )

    def _analyze(self):
        """Analyze findings with AI pivot engine."""
        from datetime import datetime
        from rich.console import Console
        console = Console()
        timestamp = datetime.now().strftime("%H:%M:%S")

        self.audit.log(self.case.phase, "analyst", "analysis_started",
                      f"Analyzing {len(self.case.findings)} findings")

        summary = build_correlation_summary(self.case.entities, self.case.findings)
        high_conf = [f for f in self.case.findings if f.confidence.level == "high"]
        self._emit_event(f"Analysis: {len(high_conf)} high-confidence findings, {summary['total_entities']} entities")

        console.print(f"  [dim]{timestamp}[/dim] [bold cyan]●[/bold cyan] [bold]IDENTITY COLLAPSE ENGINE[/bold]")
        self._emit_tool("identity_collapse", "running", "Building unified digital footprint...")
        self._identity_profile = collapse_identity(self.case.findings)
        self._emit_tool("identity_collapse", "ok", f"Risk: {self._identity_profile.exposure_level} | Score: {self._identity_profile.risk_score:.2f}")

        timestamp = datetime.now().strftime("%H:%M:%S")
        console.print(f"  [dim]{timestamp}[/dim] [bold cyan]●[/bold cyan] [bold]AI PIVOT ENGINE[/bold]")
        self._emit_tool("ai_pivot", "running", "Groq-powered intelligence analysis...")
        self._ai_analysis = analyze_findings(self.case)
        self._emit_tool("ai_pivot", "ok", f"Generated {len(self._ai_analysis.get('next_steps', []))} next steps")

        self._pivots = suggest_pivots(self.case.findings, self.case.entities)
        self.case.recommended_pivots = [pivot.get("reason", "") for pivot in self._pivots[:5] if pivot.get("reason")]
        self._emit_tool("pivot_engine", "ok", f"Found {len(self._pivots)} pivot points")
        if self.case.recommended_pivots:
            self._emit_event(f"NOTE: Next best pivot is {self.case.recommended_pivots[0]}")

        self.audit.log(self.case.phase, "analyst", "analysis_complete",
                      f"Completed analysis with AI pivot engine")

    def _generate_advanced_outputs(self):
        """Generate graph, tech fingerprint, and advanced reports."""
        from datetime import datetime
        from rich.console import Console
        from rich.rule import Rule
        console = Console()

        console.print(Rule(style="green"))
        console.print("[bold green]  REPORT GENERATION[/bold green]")
        console.print(Rule(style="green"))

        timestamp = datetime.now().strftime("%H:%M:%S")
        console.print(f"  [dim]{timestamp}[/dim] [bold cyan]●[/bold cyan] [bold]INVESTIGATION GRAPH[/bold]")
        self._emit_tool("graph_builder", "running", "Building interactive visualization...")
        graph_path = generate_interactive_graph(
            self.case.findings, self.case.entities, self.case.case_id
        )
        if graph_path:
            self._emit_tool("graph_builder", "ok", f"Graph saved: {graph_path}")
        else:
            self._emit_tool("graph_builder", "error", "Graph generation failed")

        timestamp = datetime.now().strftime("%H:%M:%S")
        console.print(f"  [dim]{timestamp}[/dim] [bold cyan]●[/bold cyan] [bold]TECH FINGERPRINTING[/bold]")
        for finding in self.case.findings:
            if finding.entity_type == EntityType.DOMAIN:
                self._emit_tool("tech_fingerprint", "running", f"Scanning {finding.entity_value}...")
                tech_findings = get_tech_stack_intelligence(finding.entity_value)
                self.case.findings.extend(tech_findings)

                timestamp = datetime.now().strftime("%H:%M:%S")
                console.print(f"  [dim]{timestamp}[/dim] [bold cyan]●[/bold cyan] [bold]SUBDOMAIN TAKEOVER CHECK[/bold]")
                self._emit_tool("subdomain_takeover", "running", f"Checking {finding.entity_value}...")
                takeover_findings = get_subdomain_takeover_intelligence(finding.entity_value)
                self.case.findings.extend(takeover_findings)
                break

        timestamp = datetime.now().strftime("%H:%M:%S")
        console.print(f"  [dim]{timestamp}[/dim] [bold cyan]●[/bold cyan] [bold]SECRET LEAK SCANNER[/bold]")
        self._emit_tool("secret_hunter", "running", "Scanning GitHub/Pastebin for leaked secrets...")
        for clue in self.case.clues:
            secret_findings = get_secret_leak_intelligence(clue)
            self.case.findings.extend(secret_findings)
        self._emit_tool("secret_hunter", "ok", "Secret scan complete")

        timestamp = datetime.now().strftime("%H:%M:%S")
        console.print(f"  [dim]{timestamp}[/dim] [bold cyan]●[/bold cyan] [bold]STIX EXPORT[/bold]")
        self._emit_tool("stix_export", "running", "Generating STIX-compatible JSON...")
        try:
            from src.config import CASES_DIR
            stix_path = CASES_DIR / self.case.case_id / "reports" / "stix.json"
            stix_path.parent.mkdir(exist_ok=True)
            export_stix_json(self.case, str(stix_path))
            self._emit_tool("stix_export", "ok", f"STIX export saved: {stix_path}")
        except Exception as e:
            self._emit_tool("stix_export", "error", f"STIX export failed: {e}")

    def _synthesize_case(self):
        """Build guided-case outputs for UI and reports."""
        apply_verification_labels(self.case.findings, self.case.entities)
        self.case.timeline = build_timeline(self.case.findings)
        self.case.canonical_profiles = build_canonical_profiles(self.case)
        self.case.canonical_profiles, anchor_summary = resolve_primary_target(self.case)
        self.case.investigation_notes = build_investigation_notes(self.case)
        self.case.plain_language_summary = build_plain_language_summary(self.case)

        exposure = compute_exposure_score(self.case.findings, self.case.entities)
        self.case.story_card = build_story_card(self.case, exposure)
        self._emit_event(f"NOTE: STORY: {self.case.story_card.verdict}")

        if anchor_summary:
            self._emit_event(f"NOTE: {anchor_summary}")

        if self.case.canonical_profiles:
            top_profile = self.case.canonical_profiles[0]
            self._emit_event(
                f"NOTE: Strongest merged profile is '{top_profile.display_name}' with {top_profile.verification} confidence."
            )

    def _save_to_memory(self):
        """Save investigation data to case memory."""
        try:
            save_case_memory(
                self.case.case_id,
                self.case.clues,
                len(self.case.findings),
                len(self.case.entities),
                getattr(self, '_identity_profile', IdentityProfile("")).risk_score,
            )
            for finding in self.case.findings:
                save_finding_memory(self.case.case_id, finding)
                update_pattern("entity_type", finding.entity_type.value)
                update_source_effectiveness(
                    finding.source.source_type,
                    True,
                    finding.confidence.score,
                )
        except Exception:
            pass

    def _finalize_audit(self):
        """Merge audit events into the case."""
        self.audit.merge_into_case(self.case)
