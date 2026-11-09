"""Rich-formatted terminal reporter.

SECURITY NOTE: every string that originates outside this tool (file paths,
provider API responses, JWT claims, error messages, the scan target) is passed
through rich.markup.escape() before being placed into a Rich markup string.
Without this, a hostile repository could crash the scan (MarkupError), inject
clickable links, or spoof verdict lines in the report.
"""
from __future__ import annotations

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

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

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _short_path(path: str, maxlen: int = 60) -> str:
    return ("…" + path[-(maxlen - 1):]) if len(path) > maxlen else path


def print_finding(f: Finding, verbose: bool = False) -> None:
    color = _SEVERITY_COLORS[f.severity]
    icon = _SEVERITY_ICONS[f.severity]
    title = f"{icon} {escape('[' + f.severity.value + ']')} {escape(f.secret_type.value)}"

    lines: list[str] = []

    # Primary location
    location_str = escape(_short_path(f.file_path))
    if f.line_number:
        location_str += f" (line {f.line_number})"
    lines.append(f"  [bold]File    :[/bold]  {location_str}")

    if f.commit_hash:
        lines.append(
            f"  [bold]Commit  :[/bold]  {escape(f.commit_hash)}"
            + (f"  ({escape(f.commit_date)})" if f.commit_date else "")
        )

    lines.append(f"  [bold]Secret  :[/bold]  {escape(f.masked_value)}")
    if f.risk_score is not None:
        tag_text = f"  [dim]{escape(', '.join(f.tags))}[/dim]" if f.tags else ""
        lines.append(f"  [bold]Risk    :[/bold]  {f.risk_score}/100{tag_text}")
        if verbose:
            for factor in f.risk_factors:
                lines.append(f"            [dim]· {escape(factor)}[/dim]")

    # Additional locations (dedup result)
    if f.locations:
        lines.append("")
        label = f"Also in ({len(f.locations)} more location{'s' if len(f.locations) > 1 else ''}):"
        lines.append(f"  [bold]{escape(label)}[/bold]")
        for loc in f.locations[:5]:
            loc_str = "    " + escape(_short_path(loc.file_path))
            if loc.line_number:
                loc_str += f" (line {loc.line_number})"
            if loc.commit_hash:
                loc_str += f" @ {escape(loc.commit_hash)}"
            lines.append(loc_str)
        if len(f.locations) > 5:
            lines.append(f"    … and {len(f.locations) - 5} more")

    br = f.blast_radius

    if br is not None and br.check_performed:
        lines.append("")
        lines.append("  [bold]Blast Radius:[/bold]")
        status = (
            "[bold red]ACTIVE[/bold red]"
            if br.is_active
            else ("[green]INACTIVE[/green]" if br.is_active is False else "[dim]UNKNOWN[/dim]")
        )
        lines.append(f"    Key status  : {status}")
        if br.account_info:
            lines.append(f"    Account     : {escape(br.account_info)}")
        for perm in br.permissions[:6]:
            lines.append(f"    Permission  : {escape(perm)}")
        for res in br.resources[:4]:
            lines.append(f"    Resource    : {escape(res)}")
        if br.check_error:
            lines.append(
                f"    [bold yellow]⚠ Check error :[/bold yellow] [yellow]{escape(br.check_error)}[/yellow]"
            )
        if verbose:
            lines.append(f"    [dim]check_performed : {br.check_performed}[/dim]")
            lines.append(f"    [dim]is_active       : {br.is_active}[/dim]")
        if br.risk_summary:
            lines.append(f"    [italic]{escape(br.risk_summary)}[/italic]")

    elif br is not None:
        # A checker ran but could not verify (e.g. AWS key ID without its secret,
        # PyPI token, private key). Show WHY instead of hiding the explanation.
        lines.append("")
        lines.append("  [bold]Blast Radius:[/bold] [dim]not verified automatically[/dim]")
        if br.risk_summary:
            lines.append(f"    [italic]{escape(br.risk_summary)}[/italic]")

    else:
        lines.append("")
        lines.append(
            "  [dim]Blast radius : not checked (use without --no-blast-radius to check)[/dim]"
        )

    if br is not None and br.remediation:
        lines.append("")
        lines.append("  [bold]Fix:[/bold]")
        for rem_line in br.remediation.splitlines():
            lines.append(f"    {escape(rem_line)}")

    console.print(
        Panel(
            "\n".join(lines),
            title=f"[{color}]{title}[/{color}]",
            border_style=color,
            expand=False,
        )
    )


def print_report(report: ScanReport, verbose: bool = False) -> None:
    console.rule("[bold blue]Aysal-Scan Results[/bold blue]")
    console.print()

    total_all = (
        report.total_critical + report.total_high + report.total_medium
        + report.total_low + report.total_info
    )
    hidden = max(0, total_all - len(report.findings))

    # Summary table
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Target", escape(report.scan_target))
    table.add_row("Files scanned", str(report.files_scanned))
    if report.files_skipped:
        table.add_row("Files skipped", str(report.files_skipped))
    table.add_row("Commits scanned", str(report.commits_scanned))
    table.add_row("Findings", str(len(report.findings)))
    if hidden:
        table.add_row("Hidden by --min-severity", str(hidden))
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
    for warning in report.warnings:
        console.print(f"[bold yellow]⚠ {escape(warning)}[/bold yellow]")
    if report.warnings:
        console.print()

    if not report.findings:
        if total_all == 0:
            console.print("[bold green]✓ No secrets found.[/bold green]")
        else:
            console.print(
                f"[bold yellow]No findings at or above the selected severity — "
                f"{hidden} lower-severity finding(s) hidden.[/bold yellow]"
            )
            if not report.passed:
                console.print(
                    "[bold red]Note: CRITICAL/HIGH findings exist but are hidden by "
                    "--min-severity. The exit code still reflects them.[/bold red]"
                )
    else:
        ordered = sorted(
            report.findings,
            key=lambda x: (_SEVERITY_RANK[x.severity], -(x.risk_score or 0), x.file_path, x.line_number or 0),
        )
        for finding in ordered:
            print_finding(finding, verbose=verbose)
            console.print()

    verdict_color = "green" if report.passed else "red"
    verdict_text = "✓ PASSED" if report.passed else "✗ FAILED — secrets detected"
    console.rule(f"[bold {verdict_color}]{verdict_text}[/bold {verdict_color}]")
