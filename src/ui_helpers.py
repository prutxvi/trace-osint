"""TRACE OSINT Copilot - Terminal UI Theme & Rendering Helpers"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns

from src.theme import TRACE_THEME, phase_label, status_icon, confidence_style


console = Console(theme=TRACE_THEME)


def render_header(case_id: str, phase: str, policy_mode: str = "READ_ONLY"):
    """Render the operator console header."""
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column(style="bold green", ratio=1)
    table.add_column(style="bold cyan", ratio=1)
    table.add_column(style="bold yellow", ratio=1)
    table.add_column(style="dim", ratio=1)

    table.add_row(
        f"TRACE//OSINT",
        f"CASE: {case_id}",
        f"POLICY: {policy_mode}",
        f"PHASE: {phase_label(phase)}",
    )

    console.print(Panel(
        table,
        border_style="green",
        title="[bold green]analyst@trace:~$[/bold green]",
        subtitle="[dim]public-source read-only[/dim]",
    ))


def render_tool_activity(tool_name: str, status: str, detail: str = ""):
    """Render a tool activity line."""
    icon = status_icon(status)
    text = f" {icon} {tool_name}"
    if detail:
        text += f" [dim]-- {detail}[/dim]"
    console.print(text)


def render_finding_summary(finding_count: int, entity_count: int):
    """Render a findings summary panel."""
    table = Table(show_header=True, box=None, padding=(0, 2))
    table.add_column("Metric", style="bold green")
    table.add_column("Value", style="bold white")

    table.add_row("Findings Collected", str(finding_count))
    table.add_row("Entities Resolved", str(entity_count))

    console.print(Panel(table, border_style="cyan", title="[bold cyan]Summary[/bold cyan]"))


def render_entity_list(entities):
    """Render a table of resolved entities."""
    if not entities:
        console.print("[dim]No entities resolved yet[/dim]")
        return

    table = Table(show_header=True, box=None, padding=(0, 1))
    table.add_column("Type", style="bold cyan")
    table.add_column("Value", style="bold white")
    table.add_column("Confidence", style="bold")
    table.add_column("Aliases")

    for e in entities:
        conf_text = f"[{confidence_style(e.confidence.level)}]{e.confidence.level} ({e.confidence.score:.2f})[/{confidence_style(e.confidence.level)}]"
        aliases = ", ".join(e.aliases[:3]) if e.aliases else "-"
        table.add_row(e.type.value, e.value, conf_text, aliases)

    console.print(Panel(table, border_style="green", title="[bold green]Resolved Entities[/bold green]"))


def render_final_report_summary(case):
    """Render the final report summary panel."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold green", ratio=1)
    table.add_column(style="bold white", ratio=2)

    table.add_row("Case ID", case.case_id)
    table.add_row("Status", f"[bold green]{case.status.upper()}[/bold green]")
    table.add_row("Phase", phase_label(case.phase))
    table.add_row("Findings", str(len(case.findings)))
    table.add_row("Entities", str(len(case.entities)))
    table.add_row("Audit Events", str(len(case.audit_log)))

    console.print(Panel(
        table,
        border_style="green",
        title="[bold green]Investigation Complete[/bold green]",
        subtitle="[dim]Reports generated in output directory[/dim]",
    ))


def render_case_list(cases: list[dict]):
    """Render a table of past cases."""
    if not cases:
        console.print("[dim]No cases found[/dim]")
        return

    table = Table(show_header=True, box=None, padding=(0, 1))
    table.add_column("Case ID", style="bold green")
    table.add_column("Name")
    table.add_column("Status", style="bold")
    table.add_column("Phase")
    table.add_column("Findings")
    table.add_column("Created")

    for c in cases:
        status_style = "green" if c["status"] == "complete" else "yellow"
        table.add_row(
            c["case_id"],
            c["name"][:30],
            f"[{status_style}]{c['status']}[/{status_style}]",
            phase_label(c["phase"]),
            str(c["findings_count"]),
            c["created_at"][:10],
        )

    console.print(Panel(table, border_style="cyan", title="[bold cyan]Past Cases[/bold cyan]"))
