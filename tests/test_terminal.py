"""Terminal reporter tests — focus on untrusted-input safety and honest output."""
from __future__ import annotations

import pytest
from rich.console import Console

from aysal_scan.models import (
    BlastRadiusResult,
    Finding,
    ScanReport,
    SecretType,
    Severity,
)
from aysal_scan.reporter import terminal


@pytest.fixture
def wide_console(monkeypatch):
    c = Console(width=300)
    monkeypatch.setattr(terminal, "console", c)
    return c


def _finding(severity=Severity.HIGH, path="a.py", line=1, blast=None, stype=SecretType.JWT):
    return Finding(
        id=f"id-{path}-{line}",
        secret_type=stype,
        severity=severity,
        file_path=path,
        line_number=line,
        masked_value="eyJh****WXYZ",
        blast_radius=blast,
    )


def _report(findings, passed=True, **totals):
    base = dict(
        total_critical=0, total_high=0, total_medium=0, total_low=0, total_info=0
    )
    base.update(totals)
    return ScanReport(
        tool_version="test",
        scan_target="/tmp/target [min-severity: HIGH]",
        scan_time="2026-01-01T00:00:00+00:00",
        files_scanned=1,
        commits_scanned=0,
        findings=findings,
        passed=passed,
        **base,
    )


def _render(console, report):
    with console.capture() as cap:
        terminal.print_report(report)
    return cap.get()


def test_closing_tag_in_untrusted_text_does_not_crash(wide_console):
    br = BlastRadiusResult(
        is_active=True, check_performed=True,
        account_info="iss=[/x] sub=u1", risk_summary="Issuer: [/x].",
    )
    out = _render(wide_console, _report([_finding(blast=br)], total_high=1, passed=False))
    assert "[/x]" in out


def test_link_markup_is_shown_literally_not_rendered(wide_console):
    payload = "[link=https://evil.example.invalid]Click here[/link]"
    br = BlastRadiusResult(is_active=True, check_performed=True, account_info=payload)
    out = _render(wide_console, _report([_finding(blast=br)], total_high=1, passed=False))
    assert payload in out
    assert "\x1b]8;" not in out  # no OSC-8 hyperlink escape


def test_bracketed_file_path_is_shown_literally(wide_console):
    out = _render(
        wide_console,
        _report([_finding(path="pages/[bold]x/[id].tsx")], total_high=1, passed=False),
    )
    assert "pages/[bold]x/[id].tsx" in out


def test_scan_target_suffix_is_visible(wide_console):
    out = _render(wide_console, _report([]))
    assert "[min-severity: HIGH]" in out


def test_unverified_finding_shows_reason(wide_console):
    br = BlastRadiusResult(
        is_active=None, check_performed=False,
        risk_summary="PyPI token detected. Treat as active and revoke immediately.",
    )
    out = _render(wide_console, _report([_finding(blast=br)], total_high=1, passed=False))
    assert "not verified automatically" in out
    assert "Treat as active and revoke immediately" in out


def test_hidden_high_finding_is_not_reported_as_clean(wide_console):
    out = _render(wide_console, _report([], total_high=1, passed=False))
    assert "No secrets found" not in out
    assert "hidden" in out
    assert "FAILED" in out


def test_truly_clean_scan_says_no_secrets(wide_console):
    out = _render(wide_console, _report([]))
    assert "No secrets found" in out
    assert "PASSED" in out


def test_findings_sorted_by_severity(wide_console):
    findings = [
        _finding(severity=Severity.LOW, path="low.py"),
        _finding(severity=Severity.CRITICAL, path="crit.py"),
        _finding(severity=Severity.HIGH, path="high.py"),
    ]
    out = _render(
        wide_console,
        _report(findings, total_critical=1, total_high=1, total_low=1, passed=False),
    )
    assert out.index("crit.py") < out.index("high.py") < out.index("low.py")
