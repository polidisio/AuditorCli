from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.theme import Theme
from rich import box

from auditor.models import Finding, Priority, Severity


_theme = Theme(
    {
        "info": "cyan",
        "success": "green",
        "warning": "yellow",
        "error": "bold red",
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "header": "bold cyan",
    }
)

console = Console(theme=_theme)


_PRIORITY_COLORS = {
    Priority.HIGH: "red",
    Priority.MEDIUM: "yellow",
    Priority.LOW: "blue",
}

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def print_banner() -> None:
    console.print(
        Panel(
            "[bold cyan]AuditorCli[/] — Security Audit Tool\n"
            "[dim]Web · Network · M365/Entra ID[/]",
            box=box.DOUBLE_EDGE,
            expand=False,
        )
    )


def print_findings_table(findings: list[Finding]) -> None:
    table = Table(
        title="Findings",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("ID", style="dim", width=8)
    table.add_column("Component", width=16)
    table.add_column("Title", width=36)
    table.add_column("MITRE", width=10)
    table.add_column("Priority", width=8)
    table.add_column("Severity", width=10)

    for f in findings:
        p_color = _PRIORITY_COLORS.get(f.priority, "white")
        s_color = _SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            f.id,
            f.component,
            f.title,
            f.mitre_id or "—",
            f"[{p_color}]{f.priority.value.upper()}[/]",
            f"[{s_color}]{f.severity.value.upper()}[/]",
        )

    console.print(table)


def print_step(msg: str) -> None:
    console.print(f"[cyan]→[/] {msg}")


def print_ok(msg: str) -> None:
    console.print(f"[green]✓[/] {msg}")


def print_warn(msg: str) -> None:
    console.print(f"[yellow]![/] {msg}")


def print_err(msg: str) -> None:
    console.print(f"[bold red]✗[/] {msg}")


def print_finding(f: Finding) -> None:
    p_color = _PRIORITY_COLORS.get(f.priority, "white")
    console.print(
        f"[{p_color}][{f.priority.value.upper()}][/] [{f.mitre_id or '—'}] "
        f"[bold]{f.title}[/] — {f.component}"
    )
