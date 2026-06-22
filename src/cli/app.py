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
            c.case_id,
            c.name[:30],
            ", ".join(c.clues[:2]),
            c.status,
            c.created_at[:10],
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


def main():
    """Entry point for the TRACE CLI."""
    app()


if __name__ == "__main__":
    main()
