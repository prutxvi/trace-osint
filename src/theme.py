"""TRACE OSINT Copilot - Terminal Theme & Rich Styling"""

from rich.theme import Theme
from rich.style import Style


TRACE_THEME = Theme(
    {
        "info": "bold green",
        "warning": "bold yellow",
        "error": "bold red",
        "success": "bold green",
        "dim": "dim white",
        "accent": "bold cyan",
        "header": "bold green on #0a0a0a",
        "phase": "bold cyan",
        "agent": "bold green",
        "source": "dim cyan",
        "confidence.high": "bold green",
        "confidence.medium": "bold yellow",
        "confidence.low": "bold red",
        "confidence.minimal": "dim white",
        "entity": "bold cyan",
        "finding": "bold white",
        "trace": "dim green",
        "panel.border": "green",
        "panel.title": "bold green",
        "progress.bar": "bold green",
        "progress.complete": "bold green",
        "progress.finished": "bold green",
        "table.header": "bold green",
        "table.row.odd": "white",
        "table.row.even": "dim white",
    }
)


PHASE_LABELS = {
    "initialized": "[dim]INIT[/dim]",
    "planning": "[bold cyan]PLANNING[/bold cyan]",
    "collecting": "[bold green]COLLECTING[/bold green]",
    "verifying": "[bold blue]VERIFYING[/bold blue]",
    "resolving": "[bold cyan]RESOLVING[/bold cyan]",
    "analyzing": "[bold yellow]ANALYZING[/bold yellow]",
    "reporting": "[bold green]REPORTING[/bold green]",
    "complete": "[bold green]COMPLETE[/bold green]",
    "error": "[bold red]ERROR[/bold red]",
}


STATUS_ICONS = {
    "ok": "[green]+[/green]",
    "running": "[cyan]>[/cyan]",
    "pending": "[dim]-[/dim]",
    "error": "[red]X[/red]",
    "blocked": "[red]X[/red]",
}


def confidence_style(level: str) -> str:
    styles = {
        "high": "bold green",
        "medium": "bold yellow",
        "low": "bold red",
        "minimal": "dim white",
    }
    return styles.get(level, "dim white")


def phase_label(phase: str) -> str:
    return PHASE_LABELS.get(phase, f"[dim]{phase.upper()}[/dim]")


def status_icon(status: str) -> str:
    return STATUS_ICONS.get(status, "[dim]?[/dim]")
