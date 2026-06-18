"""HTML report generator for GitHub Actions artifacts and local viewing."""
from __future__ import annotations
import html as _html

from pathlib import Path
from aysal_scan.models import ScanReport, Severity

_SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#d97706",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#6b7280",
}


def _finding_html(f) -> str:
    color = _SEVERITY_COLORS[f.severity]
    br = f.blast_radius

    def e(val) -> str:
        """HTML-escape a value safely."""
        return _html.escape(str(val)) if val is not None else ""

    # Extra locations block
    extra_locs_html = ""
    if f.locations:
        items = ""
        for loc in f.locations[:10]:
            loc_str = e(loc.file_path)
            if loc.line_number:
                loc_str += f" (line {loc.line_number})"
            if loc.commit_hash:
                loc_str += f" @ {e(loc.commit_hash)}"
            items += f"<li>{loc_str}</li>"
        if len(f.locations) > 10:
            items += f"<li><em>… and {len(f.locations) - 10} more</em></li>"
        extra_locs_html = f"""
        <div class="also-in">
          <strong>Also found in ({len(f.locations)} more location{"s" if len(f.locations) > 1 else ""}):</strong>
          <ul>{items}</ul>
        </div>"""

    # Blast radius block
    br_html = ""
    if br and br.check_performed:
        if br.is_active is True:
            status = '<span style="color:#dc2626;font-weight:bold">ACTIVE</span>'
        elif br.is_active is False:
            status = '<span style="color:#16a34a;font-weight:bold">INACTIVE</span>'
        else:
            status = '<span style="color:#6b7280">UNKNOWN</span>'

        perms = "".join(f"<li>{e(p)}</li>" for p in br.permissions)
        resources = "".join(f"<li>{e(r)}</li>" for r in br.resources)
        err = f'<p class="error">Check error: {e(br.check_error)}</p>' if br.check_error else ""
        br_html = f"""
        <div class="blast-radius">
          <h4>Blast Radius</h4>
          <p>Status: {status}</p>
          {"<p>Account: " + e(br.account_info) + "</p>" if br.account_info else ""}
          {"<ul>" + perms + "</ul>" if perms else ""}
          {"<ul>" + resources + "</ul>" if resources else ""}
          {"<p><em>" + e(br.risk_summary) + "</em></p>" if br.risk_summary else ""}
          {err}
        </div>"""

    remediation_html = ""
    if br and br.remediation:
        remediation_html = f'<div class="remediation"><strong>Fix:</strong> {e(br.remediation)}</div>'

    commit_html = ""
    if f.commit_hash:
        commit_html = (
            f'<p><strong>Commit:</strong> {e(f.commit_hash)}'
            + (f' ({e(f.commit_date)})' if f.commit_date else '')
            + '</p>'
        )

    line_str = f' (line {f.line_number})' if f.line_number else ''
    return f"""
    <div class="finding" style="border-left:4px solid {color}">
      <div class="finding-header" style="color:{color}">
        [{e(f.severity.value)}] {e(f.secret_type.value)}
      </div>
      <p><strong>File:</strong> {e(f.file_path)}{line_str}</p>
      {commit_html}
      <p><strong>Secret:</strong> <code>{e(f.masked_value)}</code></p>
      {extra_locs_html}
      {br_html}
      {remediation_html}
    </div>"""


def generate_html_report(report: ScanReport, output_path: Path) -> None:
    verdict_class = "passed" if report.passed else "failed"
    verdict_text = "✓ PASSED" if report.passed else "✗ FAILED — secrets detected"

    findings_html = "\n".join(_finding_html(f) for f in report.findings)
    if not findings_html:
        findings_html = '<p class="no-findings">✓ No secrets found.</p>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Aysal-Scan Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          max-width: 960px; margin: 0 auto; padding: 2rem; background: #f9fafb; color: #111; }}
  h1 {{ color: #1e293b; }}
  .summary {{ background: #fff; border-radius: 8px; padding: 1rem 1.5rem;
              box-shadow: 0 1px 3px rgba(0,0,0,.1); margin-bottom: 1.5rem; }}
  .summary table {{ border-collapse: collapse; width: 100%; }}
  .summary td {{ padding: 0.35rem 0.75rem; }}
  .summary td:first-child {{ color: #6b7280; font-weight: 500; width: 160px; }}
  .finding {{ background: #fff; border-radius: 8px; padding: 1rem 1.5rem;
              margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
  .finding-header {{ font-size: 1.1rem; font-weight: 700; margin-bottom: .75rem; }}
  .blast-radius {{ background: #fef2f2; border-radius: 6px; padding: .75rem 1rem; margin: .75rem 0; }}
  .blast-radius h4 {{ margin: 0 0 .5rem; }}
  .blast-radius ul {{ margin: .25rem 0; padding-left: 1.25rem; }}
  .also-in {{ background: #fffbeb; border-radius: 6px; padding: .75rem 1rem; margin: .75rem 0; }}
  .also-in ul {{ margin: .25rem 0; padding-left: 1.25rem; }}
  .remediation {{ background: #f0fdf4; border-radius: 6px; padding: .75rem 1rem; margin: .75rem 0; }}
  .error {{ color: #dc2626; font-size: .875rem; }}
  code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-family: monospace; }}
  .verdict {{ text-align: center; padding: 1rem; border-radius: 8px; font-size: 1.25rem;
              font-weight: 700; margin-top: 1.5rem; }}
  .passed {{ background: #dcfce7; color: #16a34a; }}
  .failed {{ background: #fee2e2; color: #dc2626; }}
  .no-findings {{ color: #16a34a; font-size: 1.1rem; }}
</style>
</head>
<body>
<h1>🔐 Aysal-Scan Report</h1>
<div class="summary">
  <table>
    <tr><td>Tool version</td><td>{report.tool_version}</td></tr>
    <tr><td>Scan target</td><td>{report.scan_target}</td></tr>
    <tr><td>Scan time</td><td>{report.scan_time}</td></tr>
    <tr><td>Files scanned</td><td>{report.files_scanned}</td></tr>
    <tr><td>Commits scanned</td><td>{report.commits_scanned}</td></tr>
    <tr><td>Critical</td><td><strong style="color:#dc2626">{report.total_critical}</strong></td></tr>
    <tr><td>High</td><td><strong style="color:#d97706">{report.total_high}</strong></td></tr>
    <tr><td>Medium</td><td>{report.total_medium}</td></tr>
    <tr><td>Low</td><td>{report.total_low}</td></tr>
    <tr><td>Info</td><td>{report.total_info}</td></tr>
  </table>
</div>

{findings_html}

<div class="verdict {verdict_class}">{verdict_text}</div>
</body>
</html>"""

    output_path.write_text(html, encoding="utf-8")