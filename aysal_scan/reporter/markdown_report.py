"""Markdown report — ideal for GitHub Actions job summaries and PR comments."""
from __future__ import annotations

from pathlib import Path

from aysal_scan.models import ScanReport, Severity

_ICON = {
    Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵", Severity.INFO: "⚪",
}


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _status(f) -> str:
    br = f.blast_radius
    if br is None or not br.check_performed:
        return "not verified"
    return {True: "**ACTIVE**", False: "revoked", None: "unknown"}[br.is_active]


def render_markdown(report: ScanReport) -> str:
    verdict = "✅ **PASSED**" if report.passed else "❌ **FAILED** — secrets detected"
    lines = [
        "## Aysal-Scan results",
        "",
        verdict,
        "",
        f"- Target: `{_cell(report.scan_target)}`",
        f"- Files scanned: {report.files_scanned} · Commits scanned: {report.commits_scanned}",
        f"- Critical: {report.total_critical} · High: {report.total_high} · "
        f"Medium: {report.total_medium} · Low: {report.total_low} · Info: {report.total_info}",
        "",
    ]
    if report.warnings:
        lines += ["> ⚠️ " + _cell(w) for w in report.warnings] + [""]

    if not report.findings:
        lines.append("No findings at the selected severity.")
        return "\n".join(lines) + "\n"

    lines += [
        "| Severity | Type | Location | Risk | Status | Finding ID |",
        "|---|---|---|---|---|---|",
    ]
    ordered = sorted(
        report.findings,
        key=lambda x: (x.severity.rank, -(x.risk_score or 0), x.file_path, x.line_number or 0),
    )
    for f in ordered:
        loc = f"`{_cell(f.file_path)}`" + (f":{f.line_number}" if f.line_number else "")
        risk = f"{f.risk_score}/100" if f.risk_score is not None else "-"
        lines.append(
            f"| {_ICON[f.severity]} {f.severity.value} | {_cell(f.secret_type.value)} | {loc} | "
            f"{risk} | {_status(f)} | `{f.id[:12]}…` |"
        )
    lines += ["", "<details><summary>Remediation</summary>", ""]
    seen = set()
    for f in ordered:
        if f.secret_type in seen or not (f.blast_radius and f.blast_radius.remediation):
            continue
        seen.add(f.secret_type)
        lines.append(f"**{_cell(f.secret_type.value)}**")
        lines.append("")
        lines.append(_cell(f.blast_radius.remediation).replace(" 2. ", "<br>2. "))
        lines.append("")
    lines.append("</details>")
    return "\n".join(lines) + "\n"


def write_markdown_report(report: ScanReport, output_path: Path) -> str:
    text = render_markdown(report)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")
    return text
