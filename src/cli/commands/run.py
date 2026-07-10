from __future__ import annotations
"""TRACE OSINT Copilot - Investigation Runner.

Executes the full investigation workflow and renders results.
"""

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

from src.config import CASES_DIR
from src.models import Case
from src.workflow import WorkflowEngine
from src.reporting.markdown_report import generate_markdown_report
from src.reporting.json_report import generate_json_report
from src.reporting.pdf_report import save_pdf_report
from src.reporting.stix_export import export_stix_json
from src.case_store import save_case, save_report
from src.theme import TRACE_THEME

console = Console(theme=TRACE_THEME)


def render_terminal_summary(case: Case, pdf_path=None, md_path=None, json_path=None, stix_path=None):
    """Print the operator-console end-of-run summary panel."""
    from src.analysis.exposure import compute_exposure_score, risk_level_label

    exposure = compute_exposure_score(case.findings, case.entities)
    risk_level = exposure["risk_level"].upper()
    risk_score = exposure["score"]

    primary = case.canonical_profiles[0] if case.canonical_profiles else None
    primary_name = primary.display_name if primary else case.name or "Unknown"
    primary_handle = primary.main_handle if primary else ""
    primary_location = primary.location if primary else ""

    anchor_parts = []
    if primary_handle:
        anchor_parts.append(f"@{primary_handle}")
    if primary_location:
        anchor_parts.append(primary_location)
    if primary and primary.profile_urls:
        anchor_parts.append(primary.profile_urls[0])
    anchor_text = " | ".join(anchor_parts) if anchor_parts else "N/A"

    breach_signals = [s for s in exposure.get("signals", []) if "breach" in s.lower()]
    breach_status = "PRESENT" if breach_signals else "NONE"

    lines = []
    lines.append(f"  PRIMARY:    {primary_name[:30]}       MODE: {case.case_mode}")
    lines.append(f"  ANCHOR:     {anchor_text[:50]}")
    lines.append(f"  EXPOSURE:   {risk_level} ({risk_score:.2f})   BREACH: {breach_status}")
    lines.append("")
    lines.append("  OUTPUTS")
    lines.append(f"    PDF:    {pdf_path or 'N/A'}")
    lines.append(f"    MD:     {md_path or 'N/A'}")
    lines.append(f"    JSON:   {json_path or 'N/A'}")
    lines.append(f"    STIX:   {stix_path or 'N/A'}")

    console.print()
    console.print(Panel(
        "\n".join(lines),
        border_style="green",
        title="[bold green]TRACE SUMMARY[/bold green]",
    ))


def run_investigation(case: Case):
    """Execute the full investigation workflow and generate all reports."""
    from datetime import datetime

    quiet_mode = case.ui_mode == "quiet"
    major_tools = {
        "email_intel", "github_profile", "linkedin_profile", "username_check",
        "domain_intel", "shodan_ip", "shodan_domain", "correlator",
        "identity_collapse", "ai_pivot", "graph_builder", "secret_hunter",
        "commit_unmask", "stix_export",
    }

    activity_log = []

    def on_event(msg):
        activity_log.append(msg)

    def on_phase(phase, detail):
        from src.theme import phase_label
        console.print(phase_label(phase, detail))

    def on_tool(name, status, detail):
        if quiet_mode and name not in major_tools and status not in {"error", "blocked"}:
            return
        from src.ui_helpers import render_tool_activity
        render_tool_activity(name, status, detail)

    engine = WorkflowEngine(
        case=case,
        on_event=on_event,
        on_phase=on_phase,
        on_tool=on_tool,
    )

    console.print()
    engine.run()
    console.print()

    from src.ui_helpers import render_finding_summary, render_case_summary, render_investigation_notes, render_canonical_profiles, render_timeline
    render_finding_summary(len(case.findings), len(case.entities))
    render_case_summary(case)
    render_investigation_notes(case)
    render_canonical_profiles(case)
    render_timeline(case)

    md_report = generate_markdown_report(case)
    json_report = generate_json_report(case)

    md_path = save_report(case.case_id, "report.md", md_report)
    json_path = save_report(case.case_id, "report.json", json_report)
    log_path = save_report(case.case_id, "run_log.txt", "\n".join(activity_log))

    audit_log = "\n".join(
        f"[{e.timestamp}] {e.trace_id} | {e.phase} | {e.agent} | {e.action} | {e.status}"
        for e in case.audit_log
    )
    audit_path = save_report(case.case_id, "audit_log.txt", audit_log)

    pdf_path = CASES_DIR / case.case_id / "reports" / "report.pdf"
    pdf_path.parent.mkdir(exist_ok=True)
    try:
        save_pdf_report(case, str(pdf_path))
    except Exception:
        pdf_path = None

    stix_path = CASES_DIR / case.case_id / "reports" / "stix.json"
    stix_path.parent.mkdir(exist_ok=True)
    try:
        export_stix_json(case, str(stix_path))
    except Exception:
        stix_path = None

    save_case(case)

    report_lines = [
        "[bold green]══════════════════════════════════════════════════════════════════════════════[/bold green]",
        "[bold green]  REPORTS GENERATED[/bold green]",
        "[bold green]══════════════════════════════════════════════════════════════════════════════[/bold green]",
        "",
        f"  PDF Report:      {pdf_path}" if pdf_path else "  PDF generation failed",
        f"  Markdown:        {md_path}",
        f"  JSON Evidence:   {json_path}",
        f"  STIX Bundle:     {stix_path}" if stix_path else "  STIX export skipped",
        f"  Graph:           {CASES_DIR / case.case_id / 'reports' / 'investigation_graph.html'}",
        f"  Run Log:         {log_path}",
        f"  Audit Trail:     {audit_path}",
        "",
        "[bold green]══════════════════════════════════════════════════════════════════════════════[/bold green]",
    ]

    console.print(Panel(
        "\n".join(report_lines),
        border_style="green",
        title="[bold green]MISSION COMPLETE[/bold green]",
    ))

    render_terminal_summary(case, pdf_path=pdf_path, md_path=md_path, json_path=json_path, stix_path=str(stix_path) if stix_path else None)
