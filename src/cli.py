"""TRACE OSINT Copilot - Interactive Chat CLI"""

import re
import sys
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.spinner import Spinner
from rich.columns import Columns

from src.config import PROJECT_ROOT, PolicyMode
from src.models import Case, EntityType
from src.case_store import save_case, load_case, list_cases, save_report, get_case_reports
from src.workflow import WorkflowEngine
from src.reporting.markdown_report import generate_markdown_report
from src.reporting.json_report import generate_json_report
from src.reporting.pdf_report import save_pdf_report
from src.theme import TRACE_THEME, phase_label
from src.sources.normalize import detect_entity_type

console = Console(theme=TRACE_THEME)

BANNER = r"""
[bold green]
 _____ ____  ____      ___           _
|_   _|  _ \|  _ \    / _ \ _ __ ___| |_
  | | | |_) | |_) |  / /_)/ '__/ _ \ __|
  | | |  _ <|  __/  / ___/| | |  __/ |_
  |_| |_| \_\_|    /_/    |_|  \___|\__|
[/bold green]
[dim]  Terminal-native OSINT Copilot  v1.0[/dim]
[dim]  Type your clues or ask for help. Type 'exit' to quit.[/dim]
"""

HELP_TEXT = """
[bold cyan]How to use TRACE:[/bold cyan]

Just type the information you have. TRACE will detect what it is and start investigating.

[dim]Examples:[/dim]
  [green]> john@example.com[/green]
  [green]> johndoe123[/green]
  [green]> example.com[/green]
  [green]> https://example.com/profile/john[/green]
  [green]> I have an email: john@example.com and a username johndoe[/green]
  [green]> investigate target@email.com[/green]

[dim]Commands:[/dim]
  [cyan]help[/cyan]     - Show this help
  [cyan]status[/cyan]   - Show current case status
  [cyan]list[/cyan]     - List all past cases
  [cyan]report[/cyan]   - Show the final report
  [cyan]cases[/cyan]    - Switch to a past case
  [cyan]clear[/cyan]    - Clear screen
  [cyan]exit[/cyan]     - Exit TRACE
"""


def extract_clues_from_text(text: str) -> list[str]:
    """Extract investigation clues from natural language input."""
    clues = []

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
        if full_domain not in [c for c in clues]:
            clues.append(full_domain)

    phone_pattern = r'\+?\d[\d\s\-()]{7,}\d'
    phones = re.findall(phone_pattern, text)
    for p in phones:
        cleaned = p.strip()
        if len(cleaned) >= 10 and cleaned not in clues:
            clues.append(cleaned)

    cleaned_text = re.sub(email_pattern, '', text)
    cleaned_text = re.sub(url_pattern, '', cleaned_text)
    cleaned_text = re.sub(domain_pattern, '', cleaned_text)
    cleaned_text = re.sub(phone_pattern, '', cleaned_text)
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


def render_chat_header(case=None):
    """Render the chat session header."""
    header_parts = []
    header_parts.append("[bold green]TRACE//OSINT[/bold green]")
    if case:
        header_parts.append(f"[dim]Case: {case.case_id}[/dim]")
        header_parts.append(f"[dim]Policy: {case.policy_mode}[/dim]")
    else:
        header_parts.append("[dim]Policy: READ_ONLY[/dim]")
        header_parts.append("[dim]No active case[/dim]")

    console.print(Panel(
        " | ".join(header_parts),
        border_style="green",
        title="[bold green]analyst@trace:~$[/bold green]",
        subtitle="[dim]public-source read-only[/dim]",
    ))


def render_clues_detected(clues: list[str]):
    """Show detected clues to the user."""
    table = Table(show_header=True, box=None, padding=(0, 2))
    table.add_column("#", style="dim", width=3)
    table.add_column("Detected", style="bold cyan")
    table.add_column("Type", style="bold green")

    for i, clue in enumerate(clues, 1):
        entity_type = detect_entity_type(clue)
        table.add_row(str(i), clue, entity_type)

    console.print(Panel(table, border_style="cyan", title="[bold cyan]Clues Detected[/bold cyan]"))


def render_tool_activity(tool_name: str, status: str, detail: str = ""):
    """Render a tool activity line."""
    icons = {"ok": "[green]+[/green]", "running": "[cyan]>[/cyan]", "error": "[red]![/red]", "blocked": "[red]X[/red]"}
    icon = icons.get(status, "[dim]-[/dim]")
    text = f" {icon} {tool_name}"
    if detail:
        text += f" [dim]-- {detail}[/dim]"
    console.print(text)


def run_investigation(case: Case):
    """Execute the investigation with live progress."""
    render_chat_header(case)

    activity_log = []

    def on_event(msg):
        activity_log.append(msg)

    def on_phase(phase, detail):
        console.print(f"\n[bold cyan]> Phase: {phase_label(phase)}[/bold cyan] [dim]{detail}[/dim]")

    def on_tool(name, status, detail):
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
    except Exception as e:
        pdf_path = None

    save_case(case)

    report_lines = [
        f"[bold green]Investigation Complete[/bold green]\n",
        f"[dim]Reports:[/dim]",
        f"  [green]+[/green] [bold]PDF:[/bold]     {pdf_path}" if pdf_path else f"  [red]![/red] PDF generation failed",
        f"  [green]+[/green] [bold]Markdown:[/bold] {md_path}",
        f"  [green]+[/green] [bold]JSON:[/bold]     {json_path}",
        f"  [green]+[/green] [bold]Run Log:[/bold]  {log_path}",
        f"  [green]+[/green] [bold]Audit:[/bold]    {audit_path}",
    ]

    console.print(Panel(
        "\n".join(report_lines),
        border_style="green",
        title="[bold green]Done[/bold green]",
    ))


def render_finding_summary(finding_count: int, entity_count: int):
    """Render a findings summary panel."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold green")
    table.add_column(style="bold white")
    table.add_row("Findings Collected", str(finding_count))
    table.add_row("Entities Resolved", str(entity_count))
    console.print(Panel(table, border_style="cyan", title="[bold cyan]Summary[/bold cyan]"))


def render_entity_list(entities):
    """Render a table of resolved entities."""
    if not entities:
        return

    table = Table(show_header=True, box=None, padding=(0, 1))
    table.add_column("Type", style="bold cyan")
    table.add_column("Value", style="bold white")
    table.add_column("Confidence")

    for e in entities:
        conf = f"[{e.confidence.level}]{e.confidence.level} ({e.confidence.score:.2f})[/{e.confidence.level}]"
        table.add_row(e.type.value, e.value, conf)

    console.print(Panel(table, border_style="green", title="[bold green]Resolved Entities[/bold green]"))


def render_case_list(cases: list[dict]):
    """Render a table of past cases."""
    if not cases:
        console.print("[dim]No cases found[/dim]")
        return

    table = Table(show_header=True, box=None, padding=(0, 1))
    table.add_column("Case ID", style="bold green")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Findings")

    for c in cases:
        status_style = "green" if c["status"] == "complete" else "yellow"
        table.add_row(
            c["case_id"],
            c["name"][:30],
            f"[{status_style}]{c['status']}[/{status_style}]",
            str(c["findings_count"]),
        )

    console.print(Panel(table, border_style="cyan", title="[bold cyan]Past Cases[/bold cyan]"))


def main():
    """Main interactive chat loop."""
    console.print(BANNER)
    render_chat_header()

    current_case = None
    case_clues = []

    while True:
        try:
            if current_case:
                prompt = f"[green]trace[/green] [dim]({current_case.case_id})[/dim] > "
            else:
                prompt = "[green]trace[/green] > "

            user_input = console.input(prompt).strip()

            if not user_input:
                continue

            cmd = user_input.lower()

            if cmd in ("exit", "quit", "q"):
                console.print("[dim]Closing TRACE. Stay safe.[/dim]")
                break

            if cmd == "help":
                console.print(HELP_TEXT)
                continue

            if cmd == "clear":
                console.clear()
                console.print(BANNER)
                render_chat_header(current_case)
                continue

            if cmd == "list" or cmd == "cases":
                cases = list_cases()
                render_case_list(cases)
                continue

            if cmd == "status":
                if current_case:
                    console.print(f"\n[bold]Case:[/bold] {current_case.case_id}")
                    console.print(f"[bold]Name:[/bold] {current_case.name}")
                    console.print(f"[bold]Status:[/bold] {current_case.status}")
                    console.print(f"[bold]Phase:[/bold] {current_case.phase}")
                    console.print(f"[bold]Clues:[/bold] {', '.join(current_case.clues)}")
                    console.print(f"[bold]Findings:[/bold] {len(current_case.findings)}")
                    console.print(f"[bold]Entities:[/bold] {len(current_case.entities)}")
                else:
                    console.print("[dim]No active case. Type clues to start one.[/dim]")
                continue

            if cmd == "report":
                if current_case and current_case.status == "complete":
                    md_report = generate_markdown_report(current_case)
                    console.print(Panel(md_report, border_style="green", title="Markdown Report"))
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
                        console.print(f"[green]+[/green] Switched to case: {current_case.case_id}")
                        render_chat_header(current_case)
                    else:
                        console.print(f"[red]![/red] Case not found: {case_id}")
                continue

            clues = extract_clues_from_text(user_input)

            if clues:
                for clue in clues:
                    if clue.lower() not in [c.lower() for c in case_clues]:
                        case_clues.append(clue)

                render_clues_detected(clues)

                if not current_case:
                    name = user_input[:50]
                    current_case = Case(name=name, clues=case_clues)
                    save_case(current_case)
                    console.print(f"\n[green]+[/green] New case created: [bold]{current_case.case_id}[/bold]")

                console.print(f"\n[bold cyan]> Ready to investigate {len(case_clues)} clue(s)[/bold cyan]")
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
