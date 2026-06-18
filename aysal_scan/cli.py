import sys
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from aysal_scan import __version__
from aysal_scan.models import Finding, ScanReport, Severity
from aysal_scan.scanner.file_scanner import scan_directory, scan_file
from aysal_scan.scanner.git_utils import scan_staged, scan_commits
from aysal_scan.scanner.deduplicator import deduplicate
from aysal_scan.blast_radius import run_blast_radius_concurrent
from aysal_scan.reporter.terminal import print_report
from aysal_scan.reporter.json_report import write_json_report
from aysal_scan.reporter.html_report import generate_html_report
from aysal_scan.reporter.sarif_report import generate_sarif_report

app = typer.Typer(
    name="aysal-scan",
    help="🔐 Scan git repos for leaked secrets and estimate their blast radius.",
    add_completion=False,
)

console = Console()

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _count_by_severity(findings: list[Finding], sev: Severity) -> int:
    return sum(1 for f in findings if f.severity == sev)


def _filter_by_min_severity(findings: list[Finding], min_severity: str) -> list[Finding]:
    try:
        min_sev = Severity(min_severity.upper())
    except ValueError:
        return findings
    cutoff = SEVERITY_ORDER.index(min_sev)
    return [f for f in findings if SEVERITY_ORDER.index(f.severity) <= cutoff]


def _resolve_target(path: str, full_history: bool = False) -> tuple[Path, bool]:
    """
    If path looks like a GitHub/GitLab URL, clone it to a temp directory.
    Respects full_history flag — skips --depth limit when full history is needed.
    Returns (local_path, is_temp).
    """
    # Only treat as a remote URL if it has a network scheme or git@ prefix.
    # DO NOT use path.endswith(".git") alone — bare local repos are named *.git
    # and would be mistakenly cloned as remote URLs.
    is_git_url = path.startswith((
        "https://github.com", "http://github.com",
        "git@github.com",
        "https://gitlab.com", "git@gitlab.com",
        "https://bitbucket.org", "git@bitbucket.org",
    ))

    if is_git_url:
        tmp = tempfile.mkdtemp(prefix="aysal-scan-")
        console.print(f"[cyan]Cloning[/cyan] {path} …")
        # Only use --depth when not scanning full history
        depth_args = [] if full_history else ["--depth=100"]
        result = subprocess.run(
            ["git", "clone"] + depth_args + [path, tmp],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            shutil.rmtree(tmp, ignore_errors=True)
            console.print(f"[red]Clone failed:[/red] {result.stderr.strip()}")
            raise typer.Exit(1)
        console.print(f"[green]Cloned to[/green] {tmp}\n")
        return Path(tmp), True
    return Path(path).resolve(), False


def _run_scan(
    target: Path,
    mode: str,
    commits: Optional[int],
    no_blast_radius: bool,
    fmt: str,
    output: Optional[str],
    output_json: Optional[str],
    output_sarif: Optional[str],
    min_severity: str,
    no_fail: bool,
) -> None:
    findings: list[Finding] = []
    raw_values: dict[str, str] = {}
    files_scanned = 0
    commits_scanned = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:

        if mode == "staged":
            task = progress.add_task("[cyan]Scanning staged changes…", total=None)
            findings, raw_values, files_scanned = scan_staged(target)
            progress.update(task, description=f"[cyan]Staged scan complete — {files_scanned} file(s) checked")

        elif mode == "full_history":
            task = progress.add_task("[cyan]Scanning full git history…", total=None)
            findings, raw_values, files_scanned, commits_scanned = scan_commits(
                target, n_commits=None
            )
            progress.update(task, description=f"[cyan]History scan complete — {commits_scanned} commit(s), {files_scanned} file change(s)")

        elif mode == "commits" and commits:
            task = progress.add_task(f"[cyan]Scanning last {commits} commit(s)…", total=None)
            findings, raw_values, files_scanned, commits_scanned = scan_commits(
                target, n_commits=commits
            )
            progress.update(task, description=f"[cyan]Done — {commits_scanned} commit(s), {files_scanned} file change(s)")

        elif target.is_file():
            task = progress.add_task(f"[cyan]Scanning {target.name}…", total=None)
            findings, raw_values = scan_file(target)
            files_scanned = 1
            progress.update(task, description=f"[cyan]Done — 1 file scanned")

        else:
            task = progress.add_task(f"[cyan]Scanning {target.name}…", total=None)
            findings, raw_values, files_scanned = scan_directory(target)
            progress.update(task, description=f"[cyan]Scan complete — {files_scanned} file(s) checked")

        findings = deduplicate(findings)

        if not no_blast_radius and findings:
            task2 = progress.add_task(
                f"[yellow]Checking blast radius for {len(findings)} finding(s)…",
                total=None,
            )
            findings = run_blast_radius_concurrent(findings, raw_values)
            progress.update(task2, description=f"[yellow]Blast radius checks complete")

    # Compute totals BEFORE filtering so the report shows the true picture
    total_critical = _count_by_severity(findings, Severity.CRITICAL)
    total_high = _count_by_severity(findings, Severity.HIGH)
    total_medium = _count_by_severity(findings, Severity.MEDIUM)
    total_low = _count_by_severity(findings, Severity.LOW)
    total_info = _count_by_severity(findings, Severity.INFO)
    passed = (total_critical == 0 and total_high == 0)

    # Filter AFTER computing totals — displayed findings respect --min-severity
    findings = _filter_by_min_severity(findings, min_severity)

    # Annotate scan_target with the active filter so output is self-documenting
    scan_target = str(target)
    if min_severity.upper() != "INFO":
        scan_target += f" [min-severity: {min_severity.upper()}]"

    report = ScanReport(
        tool_version=__version__,
        scan_target=scan_target,
        scan_time=datetime.now(timezone.utc).isoformat(),
        files_scanned=files_scanned,
        commits_scanned=commits_scanned,
        findings=findings,
        total_critical=total_critical,
        total_high=total_high,
        total_medium=total_medium,
        total_low=total_low,
        total_info=total_info,
        passed=passed,
    )

    # Primary output format
    if fmt == "json":
        out_path = Path(output) if output else None
        json_str = write_json_report(report, out_path)
        if not out_path:
            print(json_str)
    elif fmt == "html":
        out_path = Path(output) if output else Path("aysal-scan-report.html")
        generate_html_report(report, out_path)
        console.print(f"\n[green]HTML report saved to:[/green] {out_path}")
    elif fmt == "sarif":
        out_path = Path(output) if output else Path("aysal-scan-results.sarif")
        generate_sarif_report(report, out_path)
        console.print(f"\n[green]SARIF report saved to:[/green] {out_path}")
    else:
        print_report(report)

    # Additional output formats (can be combined with any primary format)
    if output_json and fmt != "json":
        write_json_report(report, Path(output_json))
        console.print(f"[green]JSON report saved to:[/green] {output_json}")

    if output_sarif and fmt != "sarif":
        generate_sarif_report(report, Path(output_sarif))
        console.print(f"[green]SARIF report saved to:[/green] {output_sarif}")

    if not no_fail and not report.passed:
        sys.exit(1)


@app.command()
def scan(
    path: str = typer.Argument(".", help="Path, file, or GitHub/GitLab URL to scan"),
    staged: bool = typer.Option(False, "--staged", help="Scan only staged git changes"),
    commits: Optional[int] = typer.Option(None, "--commits", help="Scan last N commits"),
    full_history: bool = typer.Option(False, "--full-history", help="Scan full git history"),
    no_blast_radius: bool = typer.Option(False, "--no-blast-radius", help="Skip blast radius checks"),
    format: str = typer.Option("terminal", "--report", help="Report format: terminal | json | html | sarif"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Also save a JSON report to this path"),
    output_sarif: Optional[str] = typer.Option(None, "--output-sarif", help="Also save a SARIF report to this path"),
    min_severity: str = typer.Option("HIGH", "--min-severity", help="Minimum severity to report: CRITICAL|HIGH|MEDIUM|LOW|INFO  [default: HIGH]"),
    no_fail: bool = typer.Option(False, "--no-fail", help="Always exit 0 even if secrets found"),
) -> None:
    """Scan a path, file, or GitHub/GitLab URL for leaked secrets."""
    target, is_temp = _resolve_target(path, full_history=full_history)
    mode = (
        "staged" if staged
        else "full_history" if full_history
        else "commits" if commits
        else "directory"
    )
    try:
        _run_scan(target, mode, commits, no_blast_radius, format, output, output_json, output_sarif, min_severity, no_fail)
    finally:
        if is_temp:
            shutil.rmtree(target, ignore_errors=True)


@app.command()
def ui() -> None:
    """Interactive menu-driven interface — no flags needed."""
    try:
        import questionary
    except ImportError:
        console.print("[red]Run: pip install aysal-scan[ui][/red]")
        raise typer.Exit(1)

    console.print()
    console.rule("[bold cyan]🔐 Aysal-Scan Interactive Mode[/bold cyan]")
    console.print()

    scan_mode = questionary.select(
        "What do you want to scan?",
        choices=[
            "Current directory (.)",
            "A specific path",
            "Staged git changes only",
            "Last N commits",
            "Full git history",
        ],
    ).ask()

    if scan_mode is None:
        raise typer.Exit(0)

    target = Path(".").resolve()
    raw_scan_path = None          # set to a string when the user enters a URL
    commits_n = None
    is_full_history = scan_mode == "Full git history"

    if scan_mode == "A specific path":
        path_input = questionary.text("Enter the path or GitHub URL to scan:").ask()
        if not path_input:
            raise typer.Exit(0)
        path_input = path_input.strip()
        # URLs must NOT be wrapped in Path() — Windows mangles https:// → https:\
        if path_input.startswith(("https://", "http://", "git@")):
            raw_scan_path = path_input          # keep as plain string
            target = Path(".")                  # placeholder, overridden below
        else:
            raw_scan_path = None
            target = Path(path_input).resolve()

    elif scan_mode == "Last N commits":
        n_input = questionary.text("How many commits to scan?", default="10").ask()
        try:
            commits_n = int(n_input or "10")
        except ValueError:
            commits_n = 10

    mode_map = {
        "Current directory (.)": "directory",
        "A specific path": "directory",
        "Staged git changes only": "staged",
        "Last N commits": "commits",
        "Full git history": "full_history",
    }
    mode = mode_map[scan_mode]

    blast = questionary.confirm(
        "Run blast radius checks? (Calls provider APIs to verify keys)",
        default=True,
    ).ask()
    no_blast_radius = not blast if blast is not None else True

    fmt_choice = questionary.select(
        "Output format?",
        choices=[
            "Terminal (coloured output)",
            "HTML report (open in browser)",
            "JSON (for scripts/CI)",
        ],
    ).ask()
    if fmt_choice is None:
        raise typer.Exit(0)

    format_map = {
        "Terminal (coloured output)": "terminal",
        "HTML report (open in browser)": "html",
        "JSON (for scripts/CI)": "json",
    }
    fmt = format_map[fmt_choice]

    output_path = None
    if fmt == "html":
        output_path = questionary.text(
            "Save HTML report as:", default="aysal-scan-report.html"
        ).ask()
    elif fmt == "json":
        if questionary.confirm("Save to file? (No = print to terminal)", default=False).ask():
            output_path = questionary.text(
                "Save JSON as:", default="aysal-scan-report.json"
            ).ask()

    min_sev_choice = questionary.select(
        "Minimum severity to show?",
        choices=[
            "CRITICAL only", "HIGH and above", "MEDIUM and above",
            "LOW and above", "Everything (INFO)",
        ],
        default="HIGH and above",  # sane default — INFO floods output
    ).ask()
    sev_map = {
        "CRITICAL only": "CRITICAL",
        "HIGH and above": "HIGH",
        "MEDIUM and above": "MEDIUM",
        "LOW and above": "LOW",
        "Everything (INFO)": "INFO",
    }
    min_severity = sev_map.get(min_sev_choice or "HIGH and above", "HIGH")

    console.print()
    console.print(f"  [bold cyan]Target   :[/bold cyan]  {raw_scan_path if raw_scan_path else target}")
    console.print(f"  [bold cyan]Mode     :[/bold cyan]  {scan_mode}")
    console.print(f"  [bold cyan]Blast    :[/bold cyan]  {'yes' if not no_blast_radius else 'no'}")
    console.print(f"  [bold cyan]Format   :[/bold cyan]  {fmt}")
    console.print(f"  [bold cyan]Severity :[/bold cyan]  {min_severity} and above")
    console.print()

    # No confirmation prompt — user already made all choices above.
    # Jump straight into the scan.
    while True:
        target, is_temp = _resolve_target(raw_scan_path if raw_scan_path else str(target), full_history=is_full_history)
        try:
            _run_scan(target, mode, commits_n, no_blast_radius, fmt, output_path, None, None, min_severity, no_fail=True)
        finally:
            if is_temp:
                shutil.rmtree(target, ignore_errors=True)

        # After scan completes, offer rescan or exit
        console.print()
        action = questionary.select(
            "What would you like to do next?",
            choices=[
                "Rescan same target",
                "Start a new scan",
                "Exit",
            ],
        ).ask()

        if action is None or action == "Exit":
            console.print("[dim]Goodbye.[/dim]")
            break
        elif action == "Start a new scan":
            # Restart the interactive UI from scratch
            ui()
            break
        # "Rescan same target" — loop continues with same settings


@app.callback(invoke_without_command=True)
def _version_callback(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", is_eager=True, help="Show version"),
) -> None:
    if version:
        console.print(f"[bold green]Aysal-Scan v{__version__}[/bold green]")
        raise typer.Exit()


if __name__ == "__main__":
    app()