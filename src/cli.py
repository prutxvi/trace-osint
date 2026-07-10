from __future__ import annotations
"""TRACE OSINT Copilot - Interactive Chat CLI"""

import re
import sys
import os
import time
from pathlib import Path
from datetime import datetime, timezone

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.columns import Columns
from rich.rule import Rule
from rich.markup import escape

from src.config import PROJECT_ROOT, PolicyMode, CASES_DIR
from src.models import Case, EntityType
from src.case_store import save_case, load_case, list_cases, save_report, get_case_reports
from src.workflow import WorkflowEngine
from src.reporting.markdown_report import generate_markdown_report
from src.reporting.json_report import generate_json_report
from src.reporting.pdf_report import save_pdf_report
from src.theme import TRACE_THEME, phase_label
from src.sources.normalize import detect_entity_type
from src.sources.clue_parser import detect_case_mode, parse_clues
from src.scoring.exposure import compute_exposure_score, risk_level_label

console = Console(theme=TRACE_THEME)

BANNER = r"""
[bold green]
 ████████╗███████╗██████╗ ███╗   ███╗    ████████╗███████╗██████╗ ███╗   ███╗
 ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
    ██║   █████╗  ██████╔╝██╔████╔██║       ██║   █████╗  ██████╔╝██╔████╔██║
    ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║       ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║
    ██║   ███████╗██║  ██║██║ ╚═╝ ██║       ██║   ███████╗██║  ██║██║ ╚═╝ ██║
    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝       ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
[/bold green]
[dim]                                                          v2.0.0[/dim]
[dim]                                          Terminal-native OSINT Copilot[/dim]
[dim]                                      Public-Source Intelligence Framework[/dim]
"""

ADVANCED_HEADER = """
[bold green]╔══════════════════════════════════════════════════════════════════════════════╗[/bold green]
[bold green]║[/bold green]  [bold cyan]TRACE//OSINT[/bold cyan]  [dim]│[/dim]  [bold]SYSTEM:[/bold] OPERATIONAL  [dim]│[/dim]  [bold]POLICY:[/bold] [green]READ_ONLY[/green]  [dim]│[/dim]  [bold]MODE:[/bold] PASSIVE  [dim]│[/dim]  [bold]CLEARANCE:[/bold] PUBLIC  [bold green]║[/bold green]
[bold green]╚══════════════════════════════════════════════════════════════════════════════╝[/bold green]
"""


def render_banner():
    """Render the advanced terminal banner."""
    console.print(BANNER)
    console.print(ADVANCED_HEADER)


def render_header(case=None):
    """Render the advanced session header."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if case:
        mode = getattr(case, "ui_mode", "quiet").upper()
        header = f"""
[bold green]┌──────────────────────────────────────────────────────────────────────────────┐[/bold green]
[bold green]│[/bold green]  [bold cyan]SESSION:[/bold cyan] {case.case_id}  [dim]│[/dim]  [bold]TARGET:[/bold] {case.name[:16]}  [dim]│[/dim]  [bold]MODE:[/bold] {mode}  [dim]│[/dim]  [bold]CLUES:[/bold] {len(case.clues)}  [dim]│[/dim]  [bold]TIME:[/bold] {now}  [bold green]│[/bold green]
[bold green]└──────────────────────────────────────────────────────────────────────────────┘[/bold green]
"""
    else:
        header = f"""
[bold green]┌──────────────────────────────────────────────────────────────────────────────┐[/bold green]
[bold green]│[/bold green]  [bold cyan]SESSION:[/bold cyan] STANDBY  [dim]│[/dim]  [bold]STATUS:[/bold] AWAITING INPUT  [dim]│[/dim]  [bold]POLICY:[/bold] [green]READ_ONLY[/green]  [dim]│[/dim]  [bold]TIME:[/bold] {now}  [bold green]│[/bold green]
[bold green]└──────────────────────────────────────────────────────────────────────────────┘[/bold green]
"""
    console.print(header)


def render_system_info():
    """Render system information panel."""
    info = Table(show_header=False, box=None, padding=(0, 1))
    info.add_column(style="bold green", width=12)
    info.add_column(style="dim", width=20)
    info.add_column(style="bold green", width=12)
    info.add_column(style="dim", width=20)

    info.add_row("VERSION", "2.0.0", "ENGINE", "Multi-Agent")
    info.add_row("SOURCES", "15+", "PLATFORMS", "400+")
    info.add_row("POLICY", "READ_ONLY", "STATUS", "OPERATIONAL")

    console.print(Panel(info, border_style="green", title="[bold green]SYSTEM STATUS[/bold green]", subtitle="[dim]All systems operational[/dim]"))


def render_clues_detected(clues: list[str]):
    """Show detected clues with advanced styling."""
    parsed = parse_clues(clues)
    table = Table(show_header=True, box=None, padding=(0, 2))
    table.add_column("#", style="dim", width=3)
    table.add_column("ENTITY", style="bold cyan")
    table.add_column("CLASSIFIED AS", style="bold green")
    table.add_column("NORMALIZED", style="bold white")

    for i, clue in enumerate(parsed, 1):
        table.add_row(str(i), clue.raw, clue.label.split(":", 1)[0], clue.normalized or clue.raw)

    console.print(Panel(
        table,
        border_style="cyan",
        title="[bold cyan]TARGET ACQUISITION[/bold cyan]",
        subtitle="[dim]Entities detected from input[/dim]",
    ))


def render_phase_transition(phase: str, detail: str = ""):
    """Render an advanced phase transition."""
    phase_order = ["planning", "collecting", "verifying", "resolving", "analyzing", "reporting"]

    phase_labels = {
        "planning": "PHASE 01: RECONNAISSANCE PLANNING",
        "collecting": "PHASE 02: DATA COLLECTION",
        "verifying": "PHASE 03: VERIFICATION",
        "resolving": "PHASE 04: ENTITY RESOLUTION",
        "analyzing": "PHASE 05: INTELLIGENCE ANALYSIS",
        "reporting": "PHASE 06: REPORT GENERATION",
    }

    console.print()
    console.print(Rule(style="green"))
    console.print(f"  [bold]{phase_labels.get(phase, phase.upper())}[/bold]")
    if phase in phase_order:
        index = phase_order.index(phase) + 1
        filled = "#" * index
        empty = "." * (len(phase_order) - index)
        console.print(f"  [bold green][{filled}{empty}][/bold green] [dim]{index}/{len(phase_order)} stages[/dim]")
    if detail:
        console.print(f"  [dim]{detail}[/dim]")
    console.print(Rule(style="green"))
    console.print()


def render_tool_activity(tool_name: str, status: str, detail: str = ""):
    """Render advanced tool activity."""
    icons = {
        "ok": "[bold green]✓[/bold green]",
        "running": "[bold cyan]▶[/bold cyan]",
        "error": "[bold red]✗[/bold red]",
        "blocked": "[bold red]⊘[/bold red]",
        "pending": "[dim]○[/dim]",
    }
    icon = icons.get(status, "[dim]·[/dim]")

    status_colors = {
        "ok": "green",
        "running": "cyan",
        "error": "red",
        "blocked": "red",
    }
    color = status_colors.get(status, "dim")

    timestamp = datetime.now().strftime("%H:%M:%S")
    text = f"  [dim]{timestamp}[/dim] {icon} [bold]{tool_name}[/bold]"
    if detail:
        text += f" [dim]--[/dim] {detail}"
    console.print(text)


def render_live_stats(findings: int, entities: int, sources: int):
    """Render live statistics during investigation."""
    stats = Table(show_header=False, box=None, padding=(0, 2))
    stats.add_column(style="bold green", width=15)
    stats.add_column(style="bold white", width=10)
    stats.add_column(style="bold green", width=15)
    stats.add_column(style="bold white", width=10)
    stats.add_column(style="bold green", width=15)
    stats.add_column(style="bold white", width=10)

    stats.add_row("FINDINGS", str(findings), "ENTITIES", str(entities), "SOURCES", str(sources))

    console.print(Panel(stats, border_style="green", title="[bold green]LIVE STATISTICS[/bold green]"))


def render_finding_summary(finding_count: int, entity_count: int):
    """Render advanced findings summary."""
    console.print(Rule(style="green"))
    console.print("[bold green]  INVESTIGATION COMPLETE[/bold green]")
    console.print(Rule(style="green"))

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold green", width=20)
    table.add_column(style="bold white", width=15)
    table.add_column(style="bold green", width=20)
    table.add_column(style="bold white", width=15)

    table.add_row("TOTAL FINDINGS", str(finding_count), "ENTITIES RESOLVED", str(entity_count))
    table.add_row("HIGH CONFIDENCE", str(finding_count // 3), "SOURCES CONSULTED", "15+")

    console.print(Panel(table, border_style="green", title="[bold green]INTELLIGENCE SUMMARY[/bold green]"))


def render_case_summary(case: Case):
    """Render the guided case summary."""
    if not case.plain_language_summary:
        return

    console.print(Panel(
        case.plain_language_summary,
        border_style="cyan",
        title="[bold cyan]CASE SUMMARY[/bold cyan]",
        subtitle="[dim]Plain-language assessment[/dim]",
    ))


def render_investigation_notes(case: Case):
    """Render short user-facing reasoning notes."""
    if not case.investigation_notes:
        return

    lines = []
    for note in case.investigation_notes[:6]:
        lines.append(f"[{note.stage}] {note.message}")

    console.print(Panel(
        "\n".join(lines),
        border_style="green",
        title="[bold green]AI INVESTIGATION NOTES[/bold green]",
        subtitle="[dim]Short reasoning updates, not raw logs[/dim]",
    ))


def render_canonical_profiles(case: Case):
    """Render merged canonical profiles."""
    if not case.canonical_profiles:
        return

    table = Table(show_header=True, box=None, padding=(0, 1))
    table.add_column("PROFILE", style="bold cyan", width=24)
    table.add_column("REL", style="bold yellow", width=10)
    table.add_column("VERIFICATION", style="bold green", width=12)
    table.add_column("CONF", style="bold white", width=8)
    table.add_column("DETAILS", style="dim", width=48)

    for profile in case.canonical_profiles[:5]:
        table.add_row(
            profile.display_name[:24],
            profile.relationship_to_primary.upper(),
            profile.verification.upper(),
            f"{profile.confidence_score:.2f}",
            profile.summary[:48],
        )

    console.print(Panel(table, border_style="cyan", title="[bold cyan]CANONICAL PROFILES[/bold cyan]"))


def render_timeline(case: Case):
    """Render a short case timeline."""
    if not case.timeline:
        return

    table = Table(show_header=True, box=None, padding=(0, 1))
    table.add_column("TIME", style="bold green", width=20)
    table.add_column("EVENT", style="bold white", width=28)
    table.add_column("VERIFY", style="bold cyan", width=10)
    table.add_column("SOURCE", style="dim", width=20)

    for event in case.timeline[:8]:
        table.add_row(
            event.timestamp[:19],
            event.title[:28],
            event.verification.upper(),
            event.source[:20],
        )

    console.print(Panel(table, border_style="green", title="[bold green]TIMELINE VIEW[/bold green]"))


def render_entity_list(entities):
    """Render advanced entity table."""
    if not entities:
        return

    table = Table(show_header=True, box=None, padding=(0, 1))
    table.add_column("TYPE", style="bold cyan", width=12)
    table.add_column("VALUE", style="bold white", width=35)
    table.add_column("CONFIDENCE", width=15)
    table.add_column("STATUS", style="bold green", width=10)

    for e in entities:
        conf = f"[{e.confidence.level}]{e.confidence.level.upper()} ({e.confidence.score:.2f})[/{e.confidence.level}]"
        table.add_row(e.type.value.upper(), e.value[:35], conf, "VERIFIED")

    console.print(Panel(table, border_style="cyan", title="[bold cyan]RESOLVED ENTITIES[/bold cyan]"))


def render_case_list(cases: list[dict]):
    """Render advanced case list."""
    if not cases:
        console.print("[dim]No cases found[/dim]")
        return

    table = Table(show_header=True, box=None, padding=(0, 1))
    table.add_column("CASE ID", style="bold green")
    table.add_column("TARGET", style="bold white")
    table.add_column("STATUS", width=12)
    table.add_column("FINDINGS", width=10)
    table.add_column("RISK", width=10)
    table.add_column("CREATED", width=12)

    for c in cases:
        status_style = "green" if c["status"] == "complete" else "yellow"
        table.add_row(
            c["case_id"],
            c["name"][:25],
            f"[{status_style}]{c['status'].upper()}[/{status_style}]",
            str(c["findings_count"]),
            "LOW",
            c["created_at"][:10],
        )

    console.print(Panel(table, border_style="cyan", title="[bold cyan]CASE DATABASE[/bold cyan]"))


def render_terminal_summary(case: Case, pdf_path=None, md_path=None, json_path=None):
    """Print the hacker-style end-of-run summary panel.

    This function is the terminal summary entry point.
    It reads the final case object and prints a structured operator console view.
    """
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

    breach_signals = [s for s in exposure.get("signals", []) if "breach" in s.lower() or "data_breach" in s.lower()]
    breach_status = "PRESENT" if breach_signals else "NONE"

    person_profiles = []
    business_traces = []
    social_mentions = []
    if primary:
        for url in primary.profile_urls:
            if "linkedin" in url.lower():
                person_profiles.append("LinkedIn")
            elif "github" in url.lower():
                person_profiles.append("GitHub")
            elif "instagram" in url.lower():
                social_mentions.append("Instagram")
            elif "twitter" in url.lower() or "x.com" in url.lower():
                social_mentions.append("Twitter/X")
            else:
                person_profiles.append(url)
        for acc in primary.linked_accounts:
            platform = acc.split(":")[0] if ":" in acc else acc
            if platform not in person_profiles:
                person_profiles.append(platform)
        for website in primary.websites:
            if any(k in website.lower() for k in ("store", "shop", "portfolio", "contact")):
                business_traces.append(website)
            elif website not in business_traces:
                business_traces.append(website)
        if primary.companies:
            business_traces.extend(primary.companies[:2])

    person_profiles = list(dict.fromkeys(person_profiles))[:5]
    business_traces = list(dict.fromkeys(business_traces))[:3]
    social_mentions = list(dict.fromkeys(social_mentions))[:3]

    next_steps = []
    if case.recommended_pivots:
        next_steps = case.recommended_pivots[:3]
    if not next_steps:
        if risk_level in ("HIGH", "CRITICAL"):
            next_steps = [
                "Review all public profiles for privacy exposure",
                "Check for credential leaks across breach databases",
                "Audit domain and certificate registrations",
            ]
        else:
            next_steps = [
                "Cross-reference findings with additional public sources",
                "Search for resolved entities on other platforms",
                "Review gaps to identify missing public data",
            ]

    lines = []
    lines.append(f"  PRIMARY:    {primary_name[:30]}       MODE: {case.case_mode}")
    lines.append(f"  ANCHOR:     {anchor_text[:50]}")
    lines.append(f"  EXPOSURE:   {risk_level} ({risk_score:.2f})   BREACH: {breach_status}")
    lines.append("")
    lines.append("  TOP SIGNALS")
    lines.append(f"    \u2022 Public profiles:  {', '.join(person_profiles[:3]) if person_profiles else 'None detected'}")
    lines.append(f"    \u2022 Business traces:  {', '.join(business_traces[:2]) if business_traces else 'None detected'}")
    lines.append(f"    \u2022 Social mentions:  {', '.join(social_mentions[:2]) if social_mentions else 'None detected'}")
    lines.append(f"    \u2022 Breach presence:  {'Yes (passwords not shown)' if breach_status == 'PRESENT' else 'Not detected'}")
    lines.append("")
    lines.append("  OUTPUTS")
    lines.append(f"    \u2022 PDF:    {pdf_path or 'N/A'}")
    lines.append(f"    \u2022 MD:     {md_path or 'N/A'}")
    lines.append(f"    \u2022 JSON:   {json_path or 'N/A'}")
    lines.append("")
    lines.append("  NEXT STEPS (AUTO-GENERATED)")
    for i, step in enumerate(next_steps[:3], 1):
        lines.append(f"    {i}. {step}")

    console.print()
    console.print(Panel(
        "\n".join(lines),
        border_style="green",
        title="[bold green]TRACE SUMMARY[/bold green]",
        subtitle=f"[dim]{case.case_id} | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}[/dim]",
    ))


def run_investigation(case: Case):
    """Execute the investigation with advanced UI."""
    render_header(case)

    activity_log = []
    quiet_mode = getattr(case, "ui_mode", "quiet") != "expert"
    major_tools = {
        "verification", "correlator", "identity_collapse", "ai_pivot",
        "pivot_engine", "graph_builder", "secret_hunter", "tech_fingerprint",
        "subdomain_takeover",
    }

    def on_event(msg):
        activity_log.append(msg)
        if msg.startswith("NOTE:"):
            console.print(f"  [bold cyan]note[/bold cyan] [dim]->[/dim] {msg[5:].strip()}")

    def on_phase(phase, detail):
        render_phase_transition(phase, detail)

    def on_tool(name, status, detail):
        if quiet_mode and name not in major_tools and status not in {"error", "blocked"}:
            return
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

    render_finding_summary(len(case.findings), len(case.entities))
    render_case_summary(case)
    render_investigation_notes(case)
    render_canonical_profiles(case)
    render_timeline(case)

    if case.entities:
        render_entity_list(case.entities)

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

    from src.config import CASES_DIR
    pdf_path = CASES_DIR / case.case_id / "reports" / "report.pdf"
    pdf_path.parent.mkdir(exist_ok=True)
    try:
        save_pdf_report(case, str(pdf_path))
    except Exception:
        pdf_path = None

    save_case(case)

    stix_path = None
    try:
        from src.reporting.stix_export import export_stix_json
        stix_path = CASES_DIR / case.case_id / "reports" / "stix.json"
        stix_path.parent.mkdir(exist_ok=True)
        export_stix_json(case, str(stix_path))
    except Exception:
        stix_path = None

    report_lines = [
        f"[bold green]══════════════════════════════════════════════════════════════════════════════[/bold green]",
        f"[bold green]  REPORTS GENERATED[/bold green]",
        f"[bold green]══════════════════════════════════════════════════════════════════════════════[/bold green]",
        f"",
        f"  [bold cyan]PDF Report:[/bold cyan]      {pdf_path}" if pdf_path else f"  [red]PDF generation failed[/red]",
        f"  [bold cyan]Markdown:[/bold cyan]        {md_path}",
        f"  [bold cyan]JSON Evidence:[/bold cyan]   {json_path}",
        f"  [bold cyan]STIX Bundle:[/bold cyan]     {stix_path}" if stix_path else f"  [dim]STIX export skipped[/dim]",
        f"  [bold cyan]Investigation Graph:[/bold cyan] {CASES_DIR / case.case_id / 'reports' / 'investigation_graph.html'}",
        f"  [bold cyan]Run Log:[/bold cyan]         {log_path}",
        f"  [bold cyan]Audit Trail:[/bold cyan]     {audit_path}",
        f"",
        f"[bold green]══════════════════════════════════════════════════════════════════════════════[/bold green]",
    ]

    console.print(Panel(
        "\n".join(report_lines),
        border_style="green",
        title="[bold green]MISSION COMPLETE[/bold green]",
        subtitle="[dim]All intelligence reports generated successfully[/dim]",
    ))

    if hasattr(engine, '_identity_profile') and engine._identity_profile:
        profile = engine._identity_profile
        console.print()
        console.print(Rule(style="cyan"))
        console.print("[bold cyan]  DIGITAL TWIN PROFILE[/bold cyan]")
        console.print(Rule(style="cyan"))

        profile_table = Table(show_header=False, box=None, padding=(0, 2))
        profile_table.add_column(style="bold green", width=18)
        profile_table.add_column(style="bold white", width=40)

        profile_table.add_row("PRIMARY TARGET", profile.primary_clue)
        profile_table.add_row("IDENTITY TYPE", profile.identity_type.upper())
        profile_table.add_row("RISK LEVEL", f"[{profile.exposure_level}]{profile.exposure_level.upper()}[/{profile.exposure_level}]")
        profile_table.add_row("RISK SCORE", f"{profile.risk_score:.2f}")
        profile_table.add_row("CONFIDENCE", f"{profile.confidence:.2f}")
        if profile.real_name:
            profile_table.add_row("REAL NAME", profile.real_name)
        if profile.emails:
            profile_table.add_row("EMAILS", ", ".join(profile.emails[:3]))
        if profile.phones:
            profile_table.add_row("PHONES", ", ".join(profile.phones[:3]))
        if profile.usernames:
            profile_table.add_row("USERNAMES", f"{len(profile.usernames)} found")
        if profile.social_profiles:
            profile_table.add_row("SOCIAL PROFILES", f"{len(profile.social_profiles)} platforms")
        if profile.domains:
            profile_table.add_row("DOMAINS", ", ".join(profile.domains[:3]))
        if profile.companies:
            profile_table.add_row("COMPANIES", ", ".join(profile.companies[:3]))
        if profile.locations:
            profile_table.add_row("LOCATIONS", ", ".join(profile.locations[:3]))
        if profile.breaches:
            profile_table.add_row("BREACHES", f"{len(profile.breaches)} found")
        profile_table.add_row("TOTAL FINDINGS", str(len(profile.raw_findings)))

        console.print(Panel(profile_table, border_style="cyan", title="[bold cyan]TARGET DOSSIER[/bold cyan]"))

    if case.canonical_profiles:
        top_profile = case.canonical_profiles[0]
        console.print(
            f"[bold green]Built {case.case_mode} profile:[/bold green] \"{top_profile.display_name}\" "
            f"([bold cyan]{getattr(engine, '_identity_profile', None).exposure_level.upper() if getattr(engine, '_identity_profile', None) else 'UNKNOWN'}[/bold cyan] exposure). "
            f"PDF: [dim]{pdf_path}[/dim]"
        )

    render_terminal_summary(case, pdf_path=pdf_path, md_path=md_path, json_path=json_path)


def extract_clues_from_text(text: str) -> list[str]:
    """Extract investigation clues from natural language input."""
    clues = []
    stripped_text = text.strip()

    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, text)
    clues.extend(emails)

    url_pattern = r'https?://[^\s<>\[\]"\'\)]+'
    urls = re.findall(url_pattern, text)
    clues.extend(urls)

    domain_pattern = r'\b([a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,})\b'
    domains = re.findall(domain_pattern, text)
    for d in domains:
        full_domain = d[0]
        if full_domain not in clues:
            clues.append(full_domain)

    phone_pattern = r'\+?\d[\d\s\-()]{7,}\d'
    phones = re.findall(phone_pattern, text)
    for p in phones:
        cleaned = p.strip()
        if len(cleaned) >= 10 and cleaned not in clues:
            clues.append(cleaned)

    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ips = re.findall(ip_pattern, text)
    for ip in ips:
        if ip not in clues:
            clues.append(ip)

    if not clues:
        name_candidate = re.sub(r'[^A-Za-z\s]', ' ', stripped_text)
        name_candidate = re.sub(r'\s+', ' ', name_candidate).strip()
        name_parts = [part for part in name_candidate.split() if part]
        if 2 <= len(name_parts) <= 4 and all(len(part) >= 2 for part in name_parts):
            return [name_candidate]

    cleaned_text = re.sub(email_pattern, '', text)
    cleaned_text = re.sub(url_pattern, '', cleaned_text)
    cleaned_text = re.sub(domain_pattern, '', cleaned_text)
    cleaned_text = re.sub(phone_pattern, '', cleaned_text)
    cleaned_text = re.sub(ip_pattern, '', cleaned_text)
    cleaned_text = re.sub(r'[^\w\s]', ' ', cleaned_text)

    command_words = {
        'the', 'a', 'an', 'is', 'are', 'was', 'were', 'have', 'has', 'had',
        'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may',
        'might', 'can', 'shall', 'to', 'of', 'in', 'for', 'on', 'with',
        'at', 'by', 'from', 'as', 'into', 'through', 'during', 'before',
        'after', 'above', 'below', 'between', 'under', 'again', 'further',
        'then', 'once', 'and', 'but', 'or', 'nor', 'not', 'so', 'yet',
        'both', 'either', 'neither', 'each', 'every', 'all', 'any', 'few',
        'more', 'most', 'other', 'some', 'such', 'no', 'only', 'own',
        'same', 'than', 'too', 'very', 'just', 'because', 'about', 'also',
        'here', 'there', 'when', 'where', 'which', 'what', 'who', 'whom',
        'this', 'that', 'these', 'those', 'being', 'been',
        'run', 'start', 'investigate', 'go', 'help', 'exit', 'quit',
        'list', 'status', 'report', 'cases', 'case', 'clear', 'email',
        'address', 'name', 'phone', 'number', 'domain', 'website', 'url',
        'link', 'profile', 'account', 'user', 'username', 'info', 'information',
        'have', 'has', 'found', 'know', 'looking', 'search', 'find',
        'investigation', 'case', 'trace', 'copilot', 'osint',
    }

    cleaned_text = re.sub(r'\b(' + '|'.join(command_words) + r')\b', ' ', cleaned_text)
    words = cleaned_text.split()
    username_like = [w for w in words if 3 <= len(w) <= 30 and w.isalnum()]
    if username_like and not clues:
        clues.extend(username_like[:3])

    seen = set()
    unique_clues = []
    for c in clues:
        c_lower = c.lower().strip()
        if c_lower not in seen and len(c_lower) >= 3:
            seen.add(c_lower)
            unique_clues.append(c)

    return unique_clues


def main():
    """Main interactive chat loop."""
    render_banner()
    render_system_info()
    render_header()

    current_case = None
    case_clues = []

    while True:
        try:
            if current_case:
                prompt = f"\n[bold green]trace[bold green] [dim]({current_case.case_id})[/dim] > "
            else:
                prompt = "\n[bold green]trace[bold green] > "

            user_input = console.input(prompt).strip()

            if not user_input:
                continue

            cmd = user_input.lower()

            if cmd in ("exit", "quit", "q"):
                console.print("\n[dim]Closing TRACE. Stay safe.[/dim]\n")
                break

            if cmd == "help":
                help_text = """
[bold cyan]COMMANDS:[/bold cyan]
  [green]help[/green]     - Show this help
  [green]status[/green]   - Show current case status
  [green]self[/green]     - Self-OSINT on your own footprint
  [green]add <clue>[/green] - Add a clue to the current case
  [green]rerun[/green]    - Re-run investigation with all clues
  [green]mode quiet[/green] / [green]mode expert[/green] - Toggle output detail
  [green]list[/green]     - List all past cases
  [green]report[/green]   - Show the final report
  [green]profile[/green]  - Show canonical profiles
  [green]timeline[/green] - Show investigation timeline
  [green]notes[/green]    - Show investigation notes
  [green]story[/green]    - Show story card
  [green]run[/green]      - Start investigation
  [green]cases[/green]    - Switch to a past case
  [green]clear[/green]    - Clear screen
  [green]exit[/green]     - Exit TRACE

[bold cyan]INPUT TYPES:[/bold cyan]
  [green]email[/green]       - target@gmail.com
  [green]username[/green]    - johndoe123
  [green]domain[/green]      - example.com
  [green]url[/green]         - https://site.com
  [green]phone[/green]       - +919876543210
  [green]ip[/green]          - 8.8.8.8
  [green]person[/green]      - John Smith

[bold cyan]EXAMPLE:[/bold cyan]
  [dim]trace > john@example.com[/dim]
  [dim]trace > run[/dim]
"""
                console.print(Panel(help_text, border_style="cyan", title="[bold cyan]TRACE COMMAND REFERENCE[/bold cyan]"))
                continue

            if cmd == "clear":
                console.clear()
                render_banner()
                render_header(current_case)
                continue

            if cmd == "list" or cmd == "cases":
                cases = list_cases()
                render_case_list(cases)
                continue

            if cmd == "status":
                if current_case:
                    status_table = Table(show_header=False, box=None, padding=(0, 2))
                    status_table.add_column(style="bold green", width=18)
                    status_table.add_column(style="bold white", width=40)

                    status_table.add_row("CASE ID", current_case.case_id)
                    status_table.add_row("TARGET", current_case.name)
                    status_table.add_row("STATUS", current_case.status.upper())
                    status_table.add_row("UI MODE", current_case.ui_mode.upper())
                    status_table.add_row("CASE MODE", current_case.case_mode.upper())
                    status_table.add_row("PHASE", current_case.phase.upper())
                    status_table.add_row("CLUES", ", ".join(current_case.clues))
                    status_table.add_row("FINDINGS", str(len(current_case.findings)))
                    status_table.add_row("ENTITIES", str(len(current_case.entities)))

                    console.print(Panel(status_table, border_style="green", title="[bold green]CASE STATUS[/bold green]"))
                else:
                    console.print("[dim]No active case. Type clues to start one.[/dim]")
                continue

            if cmd.startswith("mode "):
                requested = cmd.split(" ", 1)[1].strip()
                if requested in {"quiet", "expert"}:
                    if not current_case:
                        current_case = Case(name="New Case", clues=[])
                    current_case.ui_mode = requested
                    save_case(current_case)
                    console.print(f"[green]+[/green] UI mode set to [bold]{requested}[/bold]")
                    render_header(current_case)
                else:
                    console.print("[yellow]Use 'mode quiet' or 'mode expert'.[/yellow]")
                continue

            if cmd == "report":
                if current_case and current_case.status == "complete":
                    md_report = generate_markdown_report(current_case)
                    console.print(Panel(md_report, border_style="green", title="[bold green]INVESTIGATION REPORT[/bold green]"))
                elif current_case:
                    console.print("[yellow]Case not yet complete.[/yellow]")
                else:
                    console.print("[dim]No active case.[/dim]")
                continue

            if cmd.startswith("cases ") or cmd.startswith("case "):
                parts = cmd.split()
                if len(parts) >= 2:
                    case_id = parts[1]
                    loaded = load_case(case_id)
                    if loaded:
                        current_case = loaded
                        case_clues = list(loaded.clues)
                        console.print(f"\n[green]+[/green] Switched to case: {current_case.case_id}")
                        render_header(current_case)
                    else:
                        console.print(f"[red]![/red] Case not found: {case_id}")
                continue

            if cmd == "profile" or cmd == "profiles":
                if current_case and current_case.canonical_profiles:
                    for i, p in enumerate(current_case.canonical_profiles):
                        role = " [bold green](PRIMARY)[/bold green]" if p.is_primary else ""
                        rel = f" ({p.relationship_to_primary})" if p.relationship_to_primary else ""
                        loc = f" | {p.location}" if p.location else ""
                        urls = ", ".join(p.profile_urls[:3]) if p.profile_urls else "none"
                        console.print(
                            f"  [bold cyan]{p.display_name}[/bold cyan]{role}{rel}{loc}\n"
                            f"    @{p.main_handle} | {urls}\n"
                            f"    Verified: {p.verification_label} | {len(p.findings)} findings"
                        )
                        if i < len(current_case.canonical_profiles) - 1:
                            console.print()
                elif current_case:
                    console.print("[dim]No canonical profiles built yet.[/dim]")
                else:
                    console.print("[dim]No active case.[/dim]")
                continue

            if cmd == "timeline":
                if current_case and current_case.timeline:
                    console.print("[bold cyan]INVESTIGATION TIMELINE[/bold cyan]")
                    for event in current_case.timeline:
                        console.print(f"  [dim]{event.timestamp}[/dim] [bold cyan]{event.event_type}[/bold cyan]")
                        console.print(f"    {event.description}")
                        if event.findings:
                            for f in event.findings[:3]:
                                console.print(f"      -> {f.get('title', 'N/A')}")
                        console.print()
                elif current_case:
                    console.print("[dim]No timeline events yet.[/dim]")
                else:
                    console.print("[dim]No active case.[/dim]")
                continue

            if cmd == "notes":
                if current_case and current_case.investigation_notes:
                    console.print("[bold cyan]INVESTIGATION NOTES[/bold cyan]")
                    for note in current_case.investigation_notes:
                        console.print(f"  [dim]{note.timestamp}[/dim] {note.content}")
                elif current_case:
                    console.print("[dim]No notes yet.[/dim]")
                else:
                    console.print("[dim]No active case.[/dim]")
                continue

            if cmd == "story":
                if current_case and current_case.story_card:
                    sc = current_case.story_card
                    lines = []
                    lines.append(f"  [bold cyan]WHO IS THIS?[/bold cyan] {sc.who_is_this}")
                    lines.append(f"  [bold cyan]MAIN IDS:[/bold cyan] {', '.join(sc.main_identifiers[:5])}")
                    lines.append(f"  [bold cyan]TOP TRACES:[/bold cyan] {', '.join(sc.top_traces[:5])}")
                    lines.append(f"  [bold cyan]RISK:[/bold cyan] {sc.risk_summary}")
                    lines.append(f"  [bold cyan]VERDICT:[/bold cyan] {sc.verdict}")
                    console.print(Panel("\n".join(lines), border_style="cyan", title="[bold cyan]STORY CARD[/bold cyan]"))
                elif current_case:
                    console.print("[dim]No story card yet.[/dim]")
                else:
                    console.print("[dim]No active case.[/dim]")
                continue

            if cmd == "self":
                console.print("[bold cyan]SELF-OSINT MODE[/bold cyan]")
                console.print("[dim]Perform OSINT on your own digital footprint.[/dim]")
                console.print()
                self_email = console.input("[bold green]Your email:[/bold green] ").strip()
                self_github = console.input("[bold green]GitHub handle (optional):[/bold green] ").strip()
                self_linkedin = console.input("[bold green]LinkedIn URL (optional):[/bold green] ").strip()
                console.print()
                case_clues = []
                if self_email:
                    case_clues.append(self_email)
                if self_github:
                    if self_github.startswith("http"):
                        case_clues.append(self_github)
                    else:
                        case_clues.append(f"github.com/{self_github}")
                if self_linkedin:
                    case_clues.append(self_linkedin)
                if not case_clues:
                    console.print("[yellow]No clues provided. Aborting.[/yellow]")
                    continue
                parsed_clues = parse_clues(case_clues)
                current_case = Case(
                    name=f"Self-OSINT: {self_email or self_github or self_linkedin}",
                    clues=case_clues,
                    parsed_clues=parsed_clues,
                    case_mode="person",
                )
                save_case(current_case)
                console.print(f"\n[green]+[/green] Self-OSINT case created: [bold]{current_case.case_id}[/bold]")
                console.print(f"[bold cyan]Clues:[/bold cyan] {', '.join(case_clues)}")
                console.print()
                run_investigation(current_case)
                current_case.status = "complete"
                save_case(current_case)
                continue

            if cmd.startswith("add "):
                parts = user_input.split(None, 1)
                if len(parts) < 2:
                    console.print("[yellow]Usage: add <clue> — add a clue to the current case[/yellow]")
                    continue
                if not current_case:
                    console.print("[yellow]No active case. Type clues first.[/yellow]")
                    continue
                new_clues = extract_clues_from_text(parts[1])
                if not new_clues:
                    console.print("[yellow]No clues detected in input.[/yellow]")
                    continue
                for clue in new_clues:
                    if clue.lower() not in [c.lower() for c in current_case.clues]:
                        current_case.clues.append(clue)
                        case_clues.append(clue)
                parsed_clues = parse_clues(current_case.clues)
                current_case.parsed_clues = parsed_clues
                current_case.case_mode = detect_case_mode(parsed_clues)
                current_case.status = "active"
                save_case(current_case)
                console.print(f"[green]+[/green] Added {len(new_clues)} clue(s). Total: {len(current_case.clues)}")
                continue

            if cmd == "rerun":
                if not current_case:
                    console.print("[yellow]No active case to rerun.[/yellow]")
                    continue
                if not current_case.clues:
                    console.print("[yellow]Case has no clues to investigate.[/yellow]")
                    continue
                current_case.status = "active"
                current_case.findings = []
                current_case.entities = []
                current_case.canonical_profiles = []
                current_case.timeline = []
                current_case.investigation_notes = []
                current_case.recommended_pivots = []
                current_case.story_card = None
                current_case.plain_language_summary = ""
                save_case(current_case)
                console.print(f"[green]+[/green] Re-running investigation with {len(current_case.clues)} clue(s)...")
                run_investigation(current_case)
                current_case.status = "complete"
                save_case(current_case)
                continue

            if cmd == "run" or cmd == "go":
                if not current_case or not case_clues:
                    console.print("[yellow]Add some clues first (email, username, domain, etc.).[/yellow]")
                    continue
                run_investigation(current_case)
                current_case.status = "complete"
                save_case(current_case)
                continue

            clues = extract_clues_from_text(user_input)

            if clues:
                for clue in clues:
                    if clue.lower() not in [c.lower() for c in case_clues]:
                        case_clues.append(clue)

                render_clues_detected(clues)
                parsed_clues = parse_clues(case_clues)

                if not current_case:
                    name = user_input[:50]
                    current_case = Case(name=name, clues=case_clues, parsed_clues=parsed_clues, case_mode=detect_case_mode(parsed_clues))
                    save_case(current_case)
                    console.print(f"\n[green]+[/green] New case created: [bold]{current_case.case_id}[/bold]")
                else:
                    current_case.clues = case_clues
                    current_case.parsed_clues = parsed_clues
                    current_case.case_mode = detect_case_mode(parsed_clues)
                    save_case(current_case)

                console.print(f"\n[bold cyan]> Ready to investigate {len(case_clues)} clue(s) in {current_case.case_mode} mode[/bold cyan]")
                console.print("[dim]Type 'run' to start, or add more clues.[/dim]")
            else:
                if current_case and current_case.clues:
                    if "run" in cmd or "start" in cmd or "investigate" in cmd or "go" in cmd:
                        run_investigation(current_case)
                        current_case = load_case(current_case.case_id)
                    else:
                        console.print("[dim]No clues detected. Try typing an email, username, domain, or URL.[/dim]")
                        console.print("[dim]Type 'help' for examples.[/dim]")
                else:
                    console.print("[dim]No clues detected. Try typing an email, username, domain, or URL.[/dim]")
                    console.print("[dim]Type 'help' for examples.[/dim]")

        except KeyboardInterrupt:
            console.print("\n[dim]Use 'exit' to quit.[/dim]")
        except EOFError:
            console.print("\n[dim]Closing TRACE.[/dim]")
            break


if __name__ == "__main__":
    main()
