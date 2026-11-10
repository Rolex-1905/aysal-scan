"""Aysal-Scan command line interface.

Exit codes
----------
0  scan completed; nothing at or above ``--fail-on`` (default HIGH) was found
1  scan completed and found secrets at or above ``--fail-on``
2  the scan could NOT be performed (bad path, not a git repo, invalid option, clone failure...)

A scan that cannot run never reports "clean": it exits 2.

Output streams
--------------
Reports go to stdout. Progress and status messages go to stderr, so
``aysal-scan scan . --report json > out.json`` always produces valid JSON.
"""
from __future__ import annotations

import json as _json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from aysal_scan import __version__
from aysal_scan.blast_radius import NETWORK_SECRET_TYPES, run_blast_radius_concurrent
from aysal_scan.config import ConfigError, compile_rules, find_config, load_config
from aysal_scan.models import Finding, ScanReport, Severity
from aysal_scan.reporter.html_report import generate_html_report
from aysal_scan.reporter.json_report import write_json_report
from aysal_scan.reporter.markdown_report import write_markdown_report
from aysal_scan.reporter.sarif_report import FINGERPRINT_KEY, generate_sarif_report
from aysal_scan.reporter.terminal import print_report
from aysal_scan.scanner.deduplicator import deduplicate
from aysal_scan.scanner.file_scanner import (
    DEFAULT_MAX_FILE_SIZE,
    ScanStats,
    configure_ignore,
    scan_directory_ex,
    scan_file,
)
from aysal_scan.scanner.git_utils import GitScanError, scan_commits_ex, scan_staged
from aysal_scan.scanner.patterns import register_custom_patterns
from aysal_scan.scoring import apply_scores

EXIT_FINDINGS = 1
EXIT_ERROR = 2
VALID_FORMATS = ("terminal", "json", "html", "sarif", "markdown")

app = typer.Typer(
    name="aysal-scan",
    help="Find leaked secrets in git repositories and measure what each one can access.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
status = Console(stderr=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fail(message: str) -> "typer.Exit":
    status.print(f"[bold red]Error:[/bold red] {escape(message)}")
    raise typer.Exit(EXIT_ERROR)


def _parse_severity(value: str, option: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        _fail(f"{option}: {exc}")


def _parse_fail_on(value: str) -> Optional[Severity]:
    if value.strip().upper() == "NONE":
        return None
    return _parse_severity(value, "--fail-on")


def _filter_by_min_severity(findings: list[Finding], min_severity: str) -> list[Finding]:
    cutoff = Severity.parse(min_severity)
    return [f for f in findings if f.severity.at_least(cutoff)]


def _load_sarif_fingerprints(sarif_path: Optional[str]) -> set[str]:
    """Read fingerprints from a previous SARIF file for baseline comparison."""
    if not sarif_path:
        return set()
    try:
        data = _json.loads(Path(sarif_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _fail(f"--sarif-baseline: cannot read {sarif_path}: {exc}")
    fps: set[str] = set()
    for run in data.get("runs", []):
        for result in run.get("results", []):
            fp = result.get("fingerprints", {}).get(FINGERPRINT_KEY)
            if fp:
                fps.add(fp)
    return fps


def _is_git_url(path: str) -> bool:
    return path.startswith(("https://", "http://", "ssh://", "git://", "git@"))


def _redact_url(url: str) -> str:
    return re.sub(r"(://)[^/@\s]+@", r"\1***@", url)


def _rmtree(path: Path) -> None:
    """Delete a directory tree, including read-only files (git objects on Windows)."""
    def onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass
    shutil.rmtree(path, onerror=onerror)


def _resolve_target(path: str, full_history: bool = False) -> tuple[Path, bool]:
    """Return ``(local_path, is_temporary_clone)``. Remote URLs are cloned; local paths must exist."""
    if _is_git_url(path):
        shown = escape(_redact_url(path))
        tmp = tempfile.mkdtemp(prefix="aysal-scan-")
        status.print(f"[cyan]Cloning[/cyan] {shown}")
        depth_args = [] if full_history else ["--depth=100"]
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}  # never hang waiting for a password
        try:
            result = subprocess.run(
                ["git", "-c", "protocol.ext.allow=never", "clone", *depth_args, "--", path, tmp],
                capture_output=True, text=True, env=env, timeout=600,
            )
        except subprocess.TimeoutExpired:
            _rmtree(Path(tmp))
            _fail("git clone timed out after 10 minutes")
        except FileNotFoundError:
            _rmtree(Path(tmp))
            _fail("The 'git' executable was not found on PATH")
        if result.returncode != 0:
            _rmtree(Path(tmp))
            _fail(f"Clone failed: {_redact_url(result.stderr.strip())}")
        status.print(f"[green]Cloned[/green] to {escape(tmp)}")
        return Path(tmp), True

    local = Path(path).resolve()
    if not local.exists():
        _fail(f"Path does not exist: {path}")
    return local, False


@dataclass
class ScanOptions:
    mode: str = "directory"            # directory | staged | commits | full_history
    commits: Optional[int] = None
    no_blast_radius: bool = False
    fmt: str = "terminal"
    output: Optional[str] = None
    output_json: Optional[str] = None
    output_sarif: Optional[str] = None
    output_markdown: Optional[str] = None
    min_severity: str = "HIGH"
    fail_on: str = "HIGH"
    no_fail: bool = False
    allow_list: str = ""
    sarif_baseline: Optional[str] = None
    verbose: bool = False
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    max_history_seconds: Optional[float] = None


# ---------------------------------------------------------------------------
# The scan pipeline
# ---------------------------------------------------------------------------

def _run_scan(target: Path, opts: ScanOptions) -> None:
    findings: list[Finding] = []
    raw_values: dict[str, str] = {}
    files_scanned = 0
    files_skipped = 0
    commits_scanned = 0
    warnings: list[str] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=20),
        TimeElapsedColumn(),
        console=status,
        transient=True,
    ) as progress:
        task = progress.add_task("", total=None)

        if opts.mode == "staged":
            progress.update(task, description="[cyan]Scanning staged changes")
            findings, raw_values, files_scanned = scan_staged(target)

        elif opts.mode in ("commits", "full_history"):
            progress.update(task, description="[cyan]Scanning git history (this can take a while)")
            history = scan_commits_ex(
                target,
                n_commits=opts.commits if opts.mode == "commits" else None,
                all_refs=opts.mode == "full_history",
                max_seconds=opts.max_history_seconds,
            )
            findings, raw_values = history.findings, history.raw_values
            files_scanned, commits_scanned = history.files_changed, history.commits_scanned
            warnings.extend(history.warnings)
            if history.partial_history and opts.mode == "commits":
                warnings.append(
                    f"Only the last {commits_scanned} commit(s) were scanned; older history was "
                    "not checked. Use --full-history to scan everything."
                )

        elif target.is_file():
            progress.update(task, description="[cyan]Scanning file")
            findings, raw_values = scan_file(target, opts.max_file_size)
            files_scanned = 1

        else:
            progress.update(task, description="[cyan]Scanning files")
            findings, raw_values, stats = scan_directory_ex(target, opts.max_file_size)
            files_scanned, files_skipped = stats.files_scanned, stats.files_skipped
            warnings.extend(stats.warnings())

        findings = deduplicate(findings)

        suppressed = {x.strip() for x in opts.allow_list.split(",") if x.strip()}
        if suppressed:
            findings = [f for f in findings if f.id not in suppressed]

        if not opts.no_blast_radius and findings:
            network = sum(1 for f in findings if f.secret_type in NETWORK_SECRET_TYPES)
            if network:
                status.print(
                    f"[dim]Verifying {network} credential(s) with their providers "
                    "(read-only API calls using the found credentials; the call may appear in the "
                    "owner's audit log). Use --no-blast-radius to skip.[/dim]"
                )
            progress.update(task, description="[cyan]Checking blast radius", total=len(findings), completed=0)
            findings = run_blast_radius_concurrent(
                findings, raw_values,
                on_progress=lambda done, total: progress.update(task, completed=done, total=total),
            )

        findings = apply_scores(findings)

    findings.sort(key=lambda f: (f.severity.rank, -(f.risk_score or 0), f.file_path, f.line_number or 0))

    # Totals and pass/fail reflect EVERYTHING found; --min-severity only limits what is displayed.
    totals = {sev: sum(1 for f in findings if f.severity == sev) for sev in Severity}
    fail_on = _parse_fail_on(opts.fail_on)
    passed = True if fail_on is None else not any(f.severity.at_least(fail_on) for f in findings)

    shown = _filter_by_min_severity(findings, opts.min_severity)
    report = ScanReport(
        tool_version=__version__,
        scan_target=str(target),
        scan_root=str(target if target.is_dir() else target.parent),
        scan_time=datetime.now(timezone.utc).isoformat(),
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        commits_scanned=commits_scanned,
        findings=shown,
        total_critical=totals[Severity.CRITICAL],
        total_high=totals[Severity.HIGH],
        total_medium=totals[Severity.MEDIUM],
        total_low=totals[Severity.LOW],
        total_info=totals[Severity.INFO],
        passed=passed,
        warnings=warnings,
    )

    _write_outputs(report, opts)

    if not passed and not opts.no_fail:
        raise typer.Exit(EXIT_FINDINGS)


def _write_outputs(report: ScanReport, opts: ScanOptions) -> None:
    fmt, out = opts.fmt, opts.output
    baseline = _load_sarif_fingerprints(opts.sarif_baseline)

    if fmt == "json":
        text = write_json_report(report, Path(out) if out else None)
        if out:
            status.print(f"[green]JSON report saved:[/green] {escape(out)}")
        else:
            print(text)
    elif fmt == "html":
        path = Path(out or "aysal-scan-report.html")
        generate_html_report(report, path)
        status.print(f"[green]HTML report saved:[/green] {escape(str(path))}")
    elif fmt == "sarif":
        if out:
            generate_sarif_report(report, Path(out), baseline)
            status.print(f"[green]SARIF report saved:[/green] {escape(out)}")
        else:
            from aysal_scan.reporter.sarif_report import build_sarif
            print(_json.dumps(build_sarif(report, baseline), indent=2))
    elif fmt == "markdown":
        if out:
            write_markdown_report(report, Path(out))
            status.print(f"[green]Markdown report saved:[/green] {escape(out)}")
        else:
            from aysal_scan.reporter.markdown_report import render_markdown
            print(render_markdown(report))
    else:
        print_report(report, verbose=opts.verbose)

    # Additional files alongside the primary output
    if opts.output_json and fmt != "json":
        write_json_report(report, Path(opts.output_json))
        status.print(f"[green]JSON report saved:[/green] {escape(opts.output_json)}")
    if opts.output_sarif and fmt != "sarif":
        generate_sarif_report(report, Path(opts.output_sarif), baseline)
        status.print(f"[green]SARIF report saved:[/green] {escape(opts.output_sarif)}")
    if opts.output_markdown and fmt != "markdown":
        write_markdown_report(report, Path(opts.output_markdown))
        status.print(f"[green]Markdown report saved:[/green] {escape(opts.output_markdown)}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _from_cli_or_config(ctx: typer.Context, name: str, value, cfg: dict, cfg_key: Optional[str] = None):
    """CLI flag > config file > built-in default."""
    source = ctx.get_parameter_source(name)
    explicitly_set = source is not None and source.name != "DEFAULT"
    key = cfg_key or name
    if not explicitly_set and key in cfg:
        return cfg[key]
    return value


@app.command()
def scan(
    ctx: typer.Context,
    path: str = typer.Argument(".", help="Path, file, or git URL (https://, ssh://, git@) to scan"),
    staged: bool = typer.Option(False, "--staged", help="Scan only the lines being added in staged changes"),
    commits: Optional[int] = typer.Option(None, "--commits", help="Scan the last N commits of the current branch"),
    full_history: bool = typer.Option(False, "--full-history", help="Scan every commit on every branch/tag"),
    no_blast_radius: bool = typer.Option(
        False, "--no-blast-radius", envvar="AYSAL_SCAN_NO_VERIFY",
        help="Do not verify credentials with their providers (offline mode)",
    ),
    format: str = typer.Option("terminal", "--report", help="Report format: terminal | json | html | sarif | markdown"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write the report to this file"),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Also save a JSON report to this path"),
    output_sarif: Optional[str] = typer.Option(None, "--output-sarif", help="Also save a SARIF report to this path"),
    output_markdown: Optional[str] = typer.Option(None, "--output-markdown", help="Also save a Markdown report to this path"),
    min_severity: str = typer.Option("HIGH", "--min-severity", help="Lowest severity to DISPLAY: CRITICAL|HIGH|MEDIUM|LOW|INFO"),
    fail_on: str = typer.Option("HIGH", "--fail-on", help="Exit 1 if any finding is at/above this severity (or NONE)"),
    no_fail: bool = typer.Option(False, "--no-fail", help="Always exit 0 when the scan itself succeeds"),
    allow_list: str = typer.Option("", "--allow-list", help="Comma-separated finding IDs to suppress"),
    sarif_baseline: Optional[str] = typer.Option(None, "--sarif-baseline", help="Previous SARIF file: known findings become 'unchanged'"),
    verbose: bool = typer.Option(False, "--verbose", "-V", help="Show scoring factors and raw check details"),
    config: Optional[str] = typer.Option(None, "--config", help="Path to aysal-scan.toml (default: ./aysal-scan.toml)"),
    ignore_file: Optional[str] = typer.Option(None, "--ignore-file", help="Use this ignore file instead of the repo's AysalScanignore"),
    no_ignore_file: bool = typer.Option(False, "--no-ignore-file", help="Ignore any AysalScanignore in the scanned tree (use for UNTRUSTED repos)"),
    max_file_size: float = typer.Option(5.0, "--max-file-size", help="Skip files larger than this many MB"),
    max_time: Optional[float] = typer.Option(None, "--max-time", help="Stop a history scan after this many seconds"),
) -> None:
    """Scan a path, file, or git URL for leaked secrets."""
    # ---- configuration -------------------------------------------------
    cfg: dict = {}
    cfg_path = Path(config) if config else find_config()
    try:
        if cfg_path:
            cfg = load_config(cfg_path)
        register_custom_patterns(compile_rules(cfg.get("rules", [])))
    except ConfigError as exc:
        _fail(str(exc))

    min_severity = _from_cli_or_config(ctx, "min_severity", min_severity, cfg)
    fail_on = _from_cli_or_config(ctx, "fail_on", fail_on, cfg)
    no_blast_radius = _from_cli_or_config(ctx, "no_blast_radius", no_blast_radius, cfg)
    max_file_size = _from_cli_or_config(ctx, "max_file_size", max_file_size, cfg, "max_file_size_mb")
    cfg_allow = ",".join(str(x) for x in cfg.get("allow_list", []))
    allow_list = ",".join(x for x in (allow_list, cfg_allow) if x)

    # ---- validation (fail loudly, never silently fall back) -------------
    if format not in VALID_FORMATS:
        _fail(f"--report: invalid value {format!r}. Choose one of: {', '.join(VALID_FORMATS)}")
    _parse_severity(min_severity, "--min-severity")
    _parse_fail_on(fail_on)
    if sum([staged, full_history, commits is not None]) > 1:
        _fail("Choose only one of --staged, --commits and --full-history")
    if commits is not None and commits < 1:
        _fail("--commits must be 1 or greater")
    if staged and _is_git_url(path):
        _fail("--staged needs a local repository, not a URL")
    if max_file_size <= 0:
        _fail("--max-file-size must be greater than 0")
    if ignore_file and not Path(ignore_file).is_file():
        _fail(f"--ignore-file: file not found: {ignore_file}")

    configure_ignore(Path(ignore_file) if ignore_file else None, no_ignore_file)

    mode = (
        "staged" if staged
        else "full_history" if full_history
        else "commits" if commits is not None
        else "directory"
    )
    opts = ScanOptions(
        mode=mode, commits=commits, no_blast_radius=no_blast_radius, fmt=format, output=output,
        output_json=output_json, output_sarif=output_sarif, output_markdown=output_markdown,
        min_severity=min_severity, fail_on=fail_on, no_fail=no_fail, allow_list=allow_list,
        sarif_baseline=sarif_baseline, verbose=verbose,
        max_file_size=int(max_file_size * 1024 * 1024), max_history_seconds=max_time,
    )

    target, is_temp = _resolve_target(path, full_history=full_history)
    try:
        _run_scan(target, opts)
    except GitScanError as exc:
        _fail(str(exc))
    finally:
        if is_temp:
            _rmtree(target)


@app.command()
def ui() -> None:
    """Interactive menu-driven interface — no flags needed."""
    try:
        import questionary
    except ImportError:
        status.print("[red]Run: pip install aysal-scan\\[ui][/red]")
        raise typer.Exit(EXIT_ERROR)

    console.print()
    console.rule("[bold cyan] Aysal-Scan Interactive Mode[/bold cyan]")
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
    raw_scan_path = None
    commits_n = None
    is_full_history = scan_mode == "Full git history"

    if scan_mode == "A specific path":
        path_input = questionary.text("Enter the path or git URL to scan:").ask()
        if not path_input:
            raise typer.Exit(0)
        path_input = path_input.strip()
        if _is_git_url(path_input):
            raw_scan_path = path_input
        else:
            target = Path(path_input).resolve()

    elif scan_mode == "Last N commits":
        n_input = questionary.text("How many commits to scan?", default="10").ask()
        try:
            commits_n = max(1, int(n_input or "10"))
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
        "Verify found credentials with their providers? (read-only API calls using the credentials)",
        default=True,
    ).ask()
    no_blast_radius = not blast if blast is not None else True

    fmt_choice = questionary.select(
        "Output format?",
        choices=[
            "Terminal (coloured output)",
            "HTML report (open in browser)",
            "Markdown (for PRs / job summaries)",
            "JSON (for scripts/CI)",
        ],
    ).ask()
    if fmt_choice is None:
        raise typer.Exit(0)

    format_map = {
        "Terminal (coloured output)": "terminal",
        "HTML report (open in browser)": "html",
        "Markdown (for PRs / job summaries)": "markdown",
        "JSON (for scripts/CI)": "json",
    }
    fmt = format_map[fmt_choice]

    output_path = None
    if fmt == "html":
        output_path = questionary.text("Save HTML report as:", default="aysal-scan-report.html").ask()
    elif fmt in ("json", "markdown"):
        ext = "json" if fmt == "json" else "md"
        if questionary.confirm("Save to file? (No = print to terminal)", default=False).ask():
            output_path = questionary.text("Save as:", default=f"aysal-scan-report.{ext}").ask()

    min_sev_choice = questionary.select(
        "Minimum severity to show?",
        choices=[
            "CRITICAL only", "HIGH and above", "MEDIUM and above",
            "LOW and above", "Everything (INFO)",
        ],
        default="HIGH and above",
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
    console.print(f"  [bold cyan]Target   :[/bold cyan]  {escape(str(raw_scan_path if raw_scan_path else target))}")
    console.print(f"  [bold cyan]Mode     :[/bold cyan]  {escape(scan_mode)}")
    console.print(f"  [bold cyan]Verify   :[/bold cyan]  {'yes' if not no_blast_radius else 'no'}")
    console.print(f"  [bold cyan]Format   :[/bold cyan]  {fmt}")
    console.print(f"  [bold cyan]Severity :[/bold cyan]  {min_severity} and above")
    console.print()

    opts = ScanOptions(
        mode=mode, commits=commits_n, no_blast_radius=no_blast_radius, fmt=fmt,
        output=output_path, min_severity=min_severity, no_fail=True,
    )
    configure_ignore(None, False)
    register_custom_patterns([])

    # Resolve (clone if remote) ONCE, before the loop, so "Rescan" reuses the same clone.
    try:
        target, is_temp = _resolve_target(raw_scan_path if raw_scan_path else str(target), full_history=is_full_history)
    except typer.Exit:
        raise
    try:
        while True:
            try:
                _run_scan(target, opts)
            except GitScanError as exc:
                status.print(f"[bold red]Error:[/bold red] {escape(str(exc))}")

            console.print()
            action = questionary.select(
                "What would you like to do next?",
                choices=["Rescan same target", "Start a new scan", "Exit"],
            ).ask()

            if action is None or action == "Exit":
                console.print("[dim]Goodbye.[/dim]")
                break
            elif action == "Start a new scan":
                ui()
                break
    finally:
        if is_temp:
            _rmtree(target)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold green]Aysal-Scan v{__version__}[/bold green]")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False, "--version", "-v", callback=_version_callback, is_eager=True, help="Show version"
    ),
) -> None:
    """Find leaked secrets in git repositories and measure what each one can access."""


if __name__ == "__main__":
    app()
