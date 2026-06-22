"""TRACE OSINT Copilot - Typer CLI Application.

Professional command-line interface for terminal-native OSINT investigations.
All operations are READ_ONLY and use public sources only.
"""

import sys
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from src.config import PROJECT_ROOT, CASES_DIR
from src.models import Case
from src.theme import TRACE_THEME

app = typer.Typer(
    name="trace",
    help="TRACE OSINT Copilot — Terminal-native, multi-agent OSINT investigation tool.",
    add_completion=False,
    rich_markup_mode="rich",
)
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


def _render_banner():
    """Display the TRACE banner."""
    console.print(BANNER)
    console.print("[dim]  Type 'trace --help' for commands.[/dim]\n")


@app.command()
def case(
    clues: list[str] = typer.Argument(..., help="Clues to investigate (emails, usernames, domains, URLs, phones, IPs)"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Case name"),
    mode: Optional[str] = typer.Option(None, "--mode", "-m", help="Force case mode: person or asset"),
):
    """Run a full multi-clue investigation.

    Combines all clue types into a single investigation dossier.
    Example: trace case target@email.com github.com/target
    """
    from src.sources.clue_parser import parse_clues, detect_case_mode
    from src.cli.commands.run import run_investigation
    from src.case_store import save_case

    _render_banner()

    parsed = parse_clues(clues)
    case_mode = mode or detect_case_mode(parsed)
    case_name = name or clues[0]

    investigation_case = Case(
        name=case_name,
        clues=clues,
        parsed_clues=parsed,
        case_mode=case_mode,
    )
    save_case(investigation_case)

    console.print(f"[bold green]+[/bold green] Case created: [bold]{investigation_case.case_id}[/bold]")
    console.print(f"[bold cyan]Clues:[/bold cyan] {', '.join(clues)}")
    console.print(f"[bold cyan]Mode:[/bold cyan] {case_mode}")
    console.print()

    run_investigation(investigation_case)


@app.command()
def id(
    email: Optional[str] = typer.Option(None, "--email", "-e", help="Email address to investigate"),
    phone: Optional[str] = typer.Option(None, "--phone", "-p", help="Phone number to investigate"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Case name"),
):
    """ID-only investigation mode.

    Investigate a single email or phone with a focused pipeline.
    Example: trace id --email target@gmail.com
    Example: trace id --phone +919876543210
    """
    from src.sources.clue_parser import parse_clues, detect_case_mode
    from src.cli.commands.run import run_investigation
    from src.case_store import save_case

    _render_banner()

    if not email and not phone:
        console.print("[red]Error: Provide --email or --phone.[/red]")
        raise typer.Exit(1)

    clues = []
    if email:
        clues.append(email)
    if phone:
        clues.append(phone)

    parsed = parse_clues(clues)
    case_mode = detect_case_mode(parsed)
    case_name = name or (email or phone)

    investigation_case = Case(
        name=case_name,
        clues=clues,
        parsed_clues=parsed,
        case_mode=case_mode,
    )
    save_case(investigation_case)

    console.print(f"[bold green]+[/bold green] ID case created: [bold]{investigation_case.case_id}[/bold]")
    console.print(f"[bold cyan]Target:[/bold cyan] {email or phone}")
    console.print()

    run_investigation(investigation_case)


@app.command()
def add(
    case_id: Optional[str] = typer.Option(None, "--case", "-c", help="Case ID to add clues to"),
    clue: str = typer.Argument(..., help="Clue to add"),
):
    """Add a clue to an existing case.

    Example: trace add --case CASE-XXXX new_email@gmail.com
    """
    from src.case_store import load_case, save_case
    from src.sources.clue_parser import parse_clues, detect_case_mode

    if not case_id:
        console.print("[yellow]Usage: trace add --case CASE-XXXX <clue>[/yellow]")
        raise typer.Exit(1)

    investigation_case = load_case(case_id)
    if not investigation_case:
        console.print(f"[red]Case not found: {case_id}[/red]")
        raise typer.Exit(1)

    if clue not in investigation_case.clues:
        investigation_case.clues.append(clue)
        investigation_case.parsed_clues = parse_clues(investigation_case.clues)
        investigation_case.case_mode = detect_case_mode(investigation_case.parsed_clues)
        investigation_case.status = "active"
        save_case(investigation_case)
        console.print(f"[green]+[/green] Added clue: {clue}. Total: {len(investigation_case.clues)}")
    else:
        console.print(f"[dim]Clue already in case: {clue}[/dim]")


@app.command()
def rerun(
    case_id: str = typer.Argument(..., help="Case ID to re-run"),
):
    """Re-run investigation on an existing case with all clues.

    Example: trace rerun CASE-XXXX
    """
    from src.case_store import load_case, save_case
    from src.cli.commands.run import run_investigation

    investigation_case = load_case(case_id)
    if not investigation_case:
        console.print(f"[red]Case not found: {case_id}[/red]")
        raise typer.Exit(1)

    investigation_case.status = "active"
    investigation_case.findings = []
    investigation_case.entities = []
    investigation_case.canonical_profiles = []
    investigation_case.timeline = []
    investigation_case.investigation_notes = []
    investigation_case.recommended_pivots = []
    investigation_case.story_card = None
    investigation_case.plain_language_summary = ""
    save_case(investigation_case)

    console.print(f"[green]+[/green] Re-running investigation with {len(investigation_case.clues)} clue(s)...")
    run_investigation(investigation_case)


@app.command()
def self(
    email: str = typer.Option(..., "--email", "-e", help="Your email address"),
    github: Optional[str] = typer.Option(None, "--github", "-g", help="Your GitHub handle"),
    linkedin: Optional[str] = typer.Option(None, "--linkedin", "-l", help="Your LinkedIn URL"),
):
    """Self-OSINT on your own digital footprint.

    Example: trace self --email me@gmail.com --github myhandle
    """
    from src.sources.clue_parser import parse_clues, detect_case_mode
    from src.cli.commands.run import run_investigation
    from src.case_store import save_case

    _render_banner()

    clues = [email]
    if github:
        if github.startswith("http"):
            clues.append(github)
        else:
            clues.append(f"github.com/{github}")
    if linkedin:
        clues.append(linkedin)

    parsed = parse_clues(clues)

    investigation_case = Case(
        name=f"Self-OSINT: {email}",
        clues=clues,
        parsed_clues=parsed,
        case_mode="person",
    )
    save_case(investigation_case)

    console.print(f"[bold green]+[/bold green] Self-OSINT case created: [bold]{investigation_case.case_id}[/bold]")
    console.print()

    run_investigation(investigation_case)


@app.command()
def list_cases():
    """List all past investigation cases."""
    from src.case_store import list_cases

    _render_banner()
    cases = list_cases()
    if not cases:
        console.print("[dim]No cases found.[/dim]")
        return

    from rich.table import Table
    table = Table(title="Past Cases", border_style="cyan")
    table.add_column("Case ID", style="bold")
    table.add_column("Name")
    table.add_column("Clues")
    table.add_column("Status")
    table.add_column("Created")

    for c in cases:
        table.add_row(
            c["case_id"],
            c["name"][:30],
            ", ".join(c.get("clues", [])[:2]),
            c["status"],
            c["created_at"][:10] if c.get("created_at") else "",
        )
    console.print(table)


@app.command()
def status(
    case_id: str = typer.Argument(..., help="Case ID to inspect"),
):
    """Show case status and metadata."""
    from src.case_store import load_case

    investigation_case = load_case(case_id)
    if not investigation_case:
        console.print(f"[red]Case not found: {case_id}[/red]")
        raise typer.Exit(1)

    from rich.table import Table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold green", width=18)
    table.add_column(style="bold white", width=40)

    table.add_row("CASE ID", investigation_case.case_id)
    table.add_row("TARGET", investigation_case.name)
    table.add_row("STATUS", investigation_case.status.upper())
    table.add_row("CASE MODE", investigation_case.case_mode.upper())
    table.add_row("CLUES", ", ".join(investigation_case.clues))
    table.add_row("FINDINGS", str(len(investigation_case.findings)))
    table.add_row("ENTITIES", str(len(investigation_case.entities)))

    console.print(Panel(table, border_style="green", title="[bold green]CASE STATUS[/bold green]"))


@app.command()
def interactive():
    """Start interactive chat mode (the original TRACE experience).

    Type clues, run investigations, switch between cases.
    Example: trace interactive
    """
    import re
    from src.config import CASES_DIR
    from src.models import Case
    from src.case_store import save_case, load_case, list_cases
    from src.workflow import WorkflowEngine
    from src.reporting.markdown_report import generate_markdown_report
    from src.reporting.json_report import generate_json_report
    from src.reporting.pdf_report import save_pdf_report
    from src.reporting.stix_export import export_stix_json
    from src.theme import TRACE_THEME
    from src.sources.clue_parser import detect_case_mode, parse_clues
    from src.ui_helpers import (
        render_finding_summary, render_tool_activity,
    )
    from src.cli.commands.run import run_investigation

    def render_clues_detected(clues):
        from rich.table import Table
        table = Table(show_header=True, box=None, padding=(0, 2))
        table.add_column("#", style="dim")
        table.add_column("Detected", style="bold")
        table.add_column("Type", style="cyan")
        for i, clue in enumerate(clues, 1):
            from src.sources.normalize import detect_entity_type
            table.add_row(str(i), clue, detect_entity_type(clue))
        console.print(table)

    _render_banner()
    console.print("[dim]  Interactive mode. Type clues to start, 'help' for commands.[/dim]\n")

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
  [green]list[/green]     - List all past cases
  [green]report[/green]   - Show the final report
  [green]profile[/green]  - Show canonical profiles
  [green]timeline[/green] - Show investigation timeline
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
                _render_banner()
                continue

            if cmd == "list" or cmd == "cases":
                cases = list_cases()
                if not cases:
                    console.print("[dim]No cases found.[/dim]")
                    continue
                from rich.table import Table
                table = Table(title="Past Cases", border_style="cyan")
                table.add_column("Case ID", style="bold")
                table.add_column("Name")
                table.add_column("Clues")
                table.add_column("Status")
                for c in cases:
                    table.add_row(c.case_id, c.name[:30], ", ".join(c.clues[:2]), c.status)
                console.print(table)
                continue

            if cmd == "status":
                if current_case:
                    from rich.table import Table
                    status_table = Table(show_header=False, box=None, padding=(0, 2))
                    status_table.add_column(style="bold green", width=18)
                    status_table.add_column(style="bold white", width=40)
                    status_table.add_row("CASE ID", current_case.case_id)
                    status_table.add_row("TARGET", current_case.name)
                    status_table.add_row("STATUS", current_case.status.upper())
                    status_table.add_row("CLUES", ", ".join(current_case.clues))
                    status_table.add_row("FINDINGS", str(len(current_case.findings)))
                    status_table.add_row("ENTITIES", str(len(current_case.entities)))
                    console.print(Panel(status_table, border_style="green", title="[bold green]CASE STATUS[/bold green]"))
                else:
                    console.print("[dim]No active case. Type clues to start one.[/dim]")
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

            if cmd == "profile":
                if current_case and current_case.canonical_profiles:
                    for i, p in enumerate(current_case.canonical_profiles):
                        role = " [bold green](PRIMARY)[/bold green]" if p.is_primary else ""
                        loc = f" | {p.location}" if p.location else ""
                        console.print(f"  [bold cyan]{p.display_name}[/bold cyan]{role}{loc}\n    @{p.main_handle} | {', '.join(p.profile_urls[:3]) if p.profile_urls else 'none'}")
                elif current_case:
                    console.print("[dim]No canonical profiles yet.[/dim]")
                else:
                    console.print("[dim]No active case.[/dim]")
                continue

            if cmd == "timeline":
                if current_case and current_case.timeline:
                    for event in current_case.timeline:
                        console.print(f"  [dim]{event.timestamp}[/dim] [bold]{event.title}[/bold]\n    {event.description}")
                elif current_case:
                    console.print("[dim]No timeline yet.[/dim]")
                else:
                    console.print("[dim]No active case.[/dim]")
                continue

            if cmd == "story":
                if current_case and current_case.story_card:
                    sc = current_case.story_card
                    console.print(Panel(
                        f"  [bold cyan]WHO:[/bold cyan] {sc.who_is_this}\n  [bold cyan]IDS:[/bold cyan] {sc.main_ids}\n  [bold cyan]RISK:[/bold cyan] {sc.risk_summary}\n  [bold cyan]VERDICT:[/bold cyan] {sc.verdict}",
                        border_style="cyan", title="[bold cyan]STORY CARD[/bold cyan]"
                    ))
                elif current_case:
                    console.print("[dim]No story card yet.[/dim]")
                else:
                    console.print("[dim]No active case.[/dim]")
                continue

            if cmd.startswith("cases ") or cmd.startswith("case "):
                parts = cmd.split()
                if len(parts) >= 2:
                    loaded = load_case(parts[1])
                    if loaded:
                        current_case = loaded
                        case_clues = list(loaded.clues)
                        console.print(f"\n[green]+[/green] Switched to case: {current_case.case_id}")
                    else:
                        console.print(f"[red]Case not found: {parts[1]}[/red]")
                continue

            if cmd == "run" or cmd == "go":
                if not current_case or not case_clues:
                    console.print("[yellow]Add some clues first.[/yellow]")
                    continue
                run_investigation(current_case)
                current_case.status = "complete"
                save_case(current_case)
                continue

            # Default: treat input as clues
            def extract_clues(text):
                clues = []
                for pattern in [
                    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                    r'https?://[^\s<>\[\]"\'\)]+',
                    r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                    r'\+?\d[\d\s\-()]{7,}\d',
                ]:
                    clues.extend(re.findall(pattern, text))
                if not clues:
                    stripped = text.strip()
                    if re.match(r'^[a-zA-Z0-9_\-]{3,39}$', stripped):
                        return [stripped]
                    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$', stripped):
                        return [stripped]
                    name_candidate = re.sub(r'[^A-Za-z\s]', ' ', text).strip()
                    parts = [p for p in name_candidate.split() if p]
                    if 2 <= len(parts) <= 4 and all(len(p) >= 2 for p in parts):
                        return [name_candidate]
                return clues

            clues = extract_clues(user_input)
            if clues:
                for clue in clues:
                    if clue.lower() not in [c.lower() for c in case_clues]:
                        case_clues.append(clue)
                render_clues_detected(clues)
                parsed_clues = parse_clues(case_clues)
                if not current_case:
                    current_case = Case(name=user_input[:50], clues=case_clues, parsed_clues=parsed_clues, case_mode=detect_case_mode(parsed_clues))
                    save_case(current_case)
                    console.print(f"\n[green]+[/green] New case: [bold]{current_case.case_id}[/bold]")
                else:
                    current_case.clues = case_clues
                    current_case.parsed_clues = parsed_clues
                    current_case.case_mode = detect_case_mode(parsed_clues)
                    save_case(current_case)
                console.print(f"\n[bold cyan]> Ready with {len(case_clues)} clue(s). Type 'run' to start.[/bold cyan]")
            else:
                console.print("[dim]No clues detected. Try an email, username, or domain.[/dim]")

        except KeyboardInterrupt:
            console.print("\n[dim]Use 'exit' to quit.[/dim]")
        except EOFError:
            console.print("\n[dim]Closing TRACE.[/dim]")
            break


def main():
    """Entry point for the TRACE CLI."""
    import sys
    if len(sys.argv) == 1:
        interactive()
    else:
        app()


if __name__ == "__main__":
    main()
