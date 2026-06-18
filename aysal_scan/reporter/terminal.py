"""Rich-formatted terminal reporter."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from aysal_scan.models import Finding, ScanReport, Severity

console = Console()

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold yellow",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def _short_path(path: str, maxlen: int = 60) -> str:
    return ("…" + path[-(maxlen - 1):]) if len(path) > maxlen else path


def print_finding(f: Finding) -> None:
    color = _SEVERITY_COLORS[f.severity]
    icon = _SEVERITY_ICONS[f.severity]
    title = f"{icon} [{f.severity.value}] {f.secret_type.value}"

    lines: list[str] = []

    # Primary location
    short = _short_path(f.file_path)
    location_str = short
    if f.line_number:
        location_str += f" (line {f.line_number})"
    lines.append(f"  [bold]File    :[/bold]  {location_str}")

    if f.commit_hash:
        lines.append(f"  [bold]Commit  :[/bold]  {f.commit_hash}"
                     + (f"  ({f.commit_date})" if f.commit_date else ""))

    lines.append(f"  [bold]Secret  :[/bold]  {f.masked_value}")

    # Additional locations (dedup result)
    if f.locations:
        lines.append("")
        label = f"Also in ({len(f.locations)} more location{'s' if len(f.locations) > 1 else ''}):"
        lines.append(f"  [bold]{label}[/bold]")
        for loc in f.locations[:5]:
            loc_str = "    " + _short_path(loc.file_path)
            if loc.line_number:
                loc_str += f" (line {loc.line_number})"
            if loc.commit_hash:
                loc_str += f" @ {loc.commit_hash}"
            lines.append(loc_str)
        if len(f.locations) > 5:
            lines.append(f"    … and {len(f.locations) - 5} more")

    # Blast radius
    if f.blast_radius and f.blast_radius.check_performed:
        br = f.blast_radius
        lines.append("")
        lines.append("  [bold]Blast Radius:[/bold]")
        status = (
            "[bold red]ACTIVE[/bold red]"
            if br.is_active
            else ("[green]INACTIVE[/green]" if br.is_active is False else "[dim]UNKNOWN[/dim]")
        )
        lines.append(f"    Key status  : {status}")
        if br.account_info:
            lines.append(f"    Account     : {br.account_info}")
        for perm in br.permissions[:6]:
            lines.append(f"    Permission  : {perm}")
        for res in br.resources[:4]:
            lines.append(f"    Resource    : {res}")
        if br.check_error:
            lines.append(f"    [bold yellow]⚠ Check error :[/bold yellow] [yellow]{br.check_error}[/yellow]")
        if br.risk_summary:
            lines.append(f"    [italic]{br.risk_summary}[/italic]")

    # If blast radius was NOT performed, say so clearly
    elif f.blast_radius is None:
        lines.append("")
        lines.append("  [dim]Blast radius : not checked (use without --no-blast-radius to check)[/dim]")

    if f.blast_radius and f.blast_radius.remediation:
        lines.append("")
        lines.append(f"  [bold]Fix:[/bold] {f.blast_radius.remediation}")

    console.print(Panel("\n".join(lines), title=f"[{color}]{title}[/{color}]",
                        border_style=color, expand=False))


def print_report(report: ScanReport) -> None:
    console.rule("[bold blue]Aysal-Scan Results[/bold blue]")
    console.print()

    # Summary table
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Target", report.scan_target)
    table.add_row("Files scanned", str(report.files_scanned))
    table.add_row("Commits scanned", str(report.commits_scanned))
    table.add_row("Findings", str(len(report.findings)))
    if report.total_critical:
        table.add_row("Critical", f"[bold red]{report.total_critical}[/bold red]")
    if report.total_high:
        table.add_row("High", f"[bold yellow]{report.total_high}[/bold yellow]")
    if report.total_medium:
        table.add_row("Medium", f"[yellow]{report.total_medium}[/yellow]")
    if report.total_low:
        table.add_row("Low", f"[cyan]{report.total_low}[/cyan]")
    if report.total_info:
        table.add_row("Info", f"[dim]{report.total_info}[/dim]")
    console.print(table)
    console.print()

    if not report.findings:
        console.print("[bold green]✓ No secrets found.[/bold green]")
        return

    for finding in report.findings:
        print_finding(finding)
        console.print()

    verdict_color = "green" if report.passed else "red"
    verdict_text = "✓ PASSED" if report.passed else "✗ FAILED — secrets detected"
    console.rule(f"[bold {verdict_color}]{verdict_text}[/bold {verdict_color}]")