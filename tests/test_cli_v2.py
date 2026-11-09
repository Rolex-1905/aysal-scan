"""CLI behaviour tests for the v2 contract (exit codes, fail-closed, output purity)."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from aysal_scan.cli import app
from aysal_scan.scanner.file_scanner import configure_ignore
from aysal_scan.scanner.patterns import register_custom_patterns

runner = CliRunner()
KEY = "sk_live_" + "a1B2c3D4" * 3
DBURL = "DATABASE_URL=postgres://app:S3cretPw9xyz@db.prod.acme-corp.net:5432/app"


@pytest.fixture(autouse=True)
def _reset_global_state():
    configure_ignore(None, False)
    register_custom_patterns([])
    yield
    configure_ignore(None, False)
    register_custom_patterns([])


def w(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.email", "t@t.t")
    git(r, "config", "user.name", "t")
    return r


def scan(*args):
    return runner.invoke(app, ["scan", *args])


# --------------------------------------------------------------------------
# Fail closed: a scan that cannot run is exit 2, never "clean"
# --------------------------------------------------------------------------

def test_missing_path_exits_2(tmp_path):
    r = scan(str(tmp_path / "nope"), "--no-blast-radius")
    assert r.exit_code == 2 and "does not exist" in r.output


def test_history_scan_of_non_git_directory_exits_2(tmp_path):
    w(tmp_path, "a.env", f"S={KEY}\n")
    for flag in ("--full-history", "--staged"):
        r = scan(str(tmp_path), flag, "--no-blast-radius")
        assert r.exit_code == 2 and "Not a git repository" in r.output, flag
    assert scan(str(tmp_path), "--commits", "3", "--no-blast-radius").exit_code == 2


@pytest.mark.parametrize("args", [
    ["--report", "jsonn"], ["--min-severity", "HIGHH"], ["--fail-on", "BAD"],
    ["--staged", "--full-history"], ["--commits", "0"], ["--max-file-size", "0"],
    ["--ignore-file", "/no/such/file"],
])
def test_invalid_options_exit_2(tmp_path, args):
    assert scan(str(tmp_path), "--no-blast-radius", *args).exit_code == 2


def test_bare_command_shows_help():
    r = runner.invoke(app, [])
    assert "Usage" in r.output


# --------------------------------------------------------------------------
# Exit-code semantics
# --------------------------------------------------------------------------

def test_clean_scan_exits_0(tmp_path):
    w(tmp_path, "a.py", "print('hi')\n")
    r = scan(str(tmp_path), "--no-blast-radius")
    assert r.exit_code == 0 and "No secrets found" in r.output


def test_finding_exits_1(tmp_path):
    w(tmp_path, "a.env", f"S={KEY}\n")
    assert scan(str(tmp_path), "--no-blast-radius").exit_code == 1


def test_no_fail_exits_0(tmp_path):
    w(tmp_path, "a.env", f"S={KEY}\n")
    assert scan(str(tmp_path), "--no-blast-radius", "--no-fail").exit_code == 0


def test_fail_on_threshold(tmp_path):
    w(tmp_path, "a.yml", DBURL + "\n")                    # HIGH
    assert scan(str(tmp_path), "--no-blast-radius").exit_code == 1
    assert scan(str(tmp_path), "--no-blast-radius", "--fail-on", "CRITICAL").exit_code == 0
    assert scan(str(tmp_path), "--no-blast-radius", "--fail-on", "NONE").exit_code == 0


def test_hidden_findings_are_not_reported_as_clean_but_still_fail(tmp_path):
    w(tmp_path, "a.yml", DBURL + "\n")                    # HIGH
    r = scan(str(tmp_path), "--no-blast-radius", "--min-severity", "CRITICAL")
    assert r.exit_code == 1
    assert "No secrets found" not in r.output and "hidden" in r.output


# --------------------------------------------------------------------------
# Output purity
# --------------------------------------------------------------------------

def test_json_stdout_is_pure_json_even_with_status_messages(tmp_path):
    w(tmp_path, "a.env", f"S={KEY}\n")
    p = subprocess.run(
        [sys.executable, "-m", "aysal_scan.cli", "scan", str(tmp_path),
         "--no-blast-radius", "--report", "json", "--no-fail"],
        capture_output=True, text=True,
    )
    data = json.loads(p.stdout)
    assert data["schema_version"] == "2" and data["findings"]


def test_json_report_contains_risk_score_and_factors(tmp_path):
    w(tmp_path, "a.env", f"S={KEY}\n")
    r = scan(str(tmp_path), "--no-blast-radius", "--report", "json", "--no-fail", "-o", str(tmp_path / "o" / "r.json"))
    f = json.loads((tmp_path / "o" / "r.json").read_text())["findings"][0]
    assert 0 < f["risk_score"] <= 100 and f["risk_factors"] and f["rule_id"] == "stripe-live-secret-key"


def test_markdown_report(tmp_path):
    w(tmp_path, "a.env", f"S={KEY}\n")
    r = scan(str(tmp_path), "--no-blast-radius", "--report", "markdown", "--no-fail")
    assert "## Aysal-Scan results" in r.output and "Stripe Secret Key" in r.output and "|" in r.output


def test_html_report_escapes_every_untrusted_field(tmp_path):
    """Built directly (not via a folder name) because Windows forbids < and > in paths."""
    from aysal_scan.models import ScanReport
    from aysal_scan.reporter.html_report import generate_html_report

    report = ScanReport(
        tool_version="<b>v</b>",
        scan_target="/x/<img src=x onerror=alert(1)>",
        scan_time="<script>alert(1)</script>",
        files_scanned=1, commits_scanned=0, findings=[],
        total_critical=0, total_high=0, total_medium=0, total_low=0, total_info=0,
        passed=True, warnings=["<i>warn</i>"],
    )
    out = tmp_path / "r.html"
    generate_html_report(report, out)
    html = out.read_text(encoding="utf-8")
    assert "<img src=x onerror" not in html and "&lt;img src=x onerror" in html
    assert "<script>alert(1)</script>" not in html
    assert "<b>v</b>" not in html and "<i>warn</i>" not in html


# --------------------------------------------------------------------------
# SARIF
# --------------------------------------------------------------------------

def _sarif(tmp_path, *extra, target=None):
    out = tmp_path / "out.sarif"
    scan(str(target or tmp_path / "proj"), "--no-blast-radius", "--no-fail", "--report", "sarif", "-o", str(out), *extra)
    return json.loads(out.read_text())


def test_sarif_uses_repo_relative_paths_and_leaks_no_local_path(tmp_path):
    w(tmp_path / "proj", "src/a.env", f"S={KEY}\n")
    sarif = _sarif(tmp_path)
    run = sarif["runs"][0]
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/a.env"
    assert str(tmp_path) not in json.dumps(sarif)
    assert "artifacts" not in run


def test_sarif_rules_are_static_per_detector_and_have_security_severity(tmp_path):
    w(tmp_path / "proj", "a.env", f"S={KEY}\n")
    rule = _sarif(tmp_path)["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "stripe-live-secret-key"
    assert float(rule["properties"]["security-severity"]) >= 9
    assert "ACTIVE" not in rule["fullDescription"]["text"]   # no account-specific text


def test_sarif_has_partial_fingerprints_and_baseline(tmp_path):
    w(tmp_path / "proj", "a.env", f"S={KEY}\n")
    first = _sarif(tmp_path)
    fp = first["runs"][0]["results"][0]["partialFingerprints"]["aysalScanFingerprint/v1"]
    assert fp
    (tmp_path / "base.sarif").write_text(json.dumps(first))
    second = _sarif(tmp_path, "--sarif-baseline", str(tmp_path / "base.sarif"))
    assert second["runs"][0]["results"][0]["baselineState"] == "unchanged"


def test_unreadable_sarif_baseline_exits_2(tmp_path):
    w(tmp_path, "a.py", "x=1\n")
    assert scan(str(tmp_path), "--no-blast-radius", "--sarif-baseline", str(tmp_path / "missing.sarif")).exit_code == 2


# --------------------------------------------------------------------------
# Ignore handling flags
# --------------------------------------------------------------------------

def test_no_ignore_file_defeats_a_hostile_repo_ignore(tmp_path):
    w(tmp_path, "AysalScanignore", "*\n")
    w(tmp_path, "a.env", f"S={KEY}\n")
    assert scan(str(tmp_path), "--no-blast-radius").exit_code == 0           # hidden by repo
    assert scan(str(tmp_path), "--no-blast-radius", "--no-ignore-file").exit_code == 1


def test_explicit_ignore_file(tmp_path):
    w(tmp_path / "proj", "a.env", f"S={KEY}\n")
    mine = w(tmp_path, "mine.ignore", "a.env\n")
    assert scan(str(tmp_path / "proj"), "--no-blast-radius", "--ignore-file", str(mine)).exit_code == 0


def test_max_file_size_option_reports_skipped_files(tmp_path):
    w(tmp_path, "big.env", f"S={KEY}\n" + "x" * 300_000)
    r = scan(str(tmp_path), "--no-blast-radius", "--max-file-size", "0.1")
    assert r.exit_code == 0 and "larger than the size limit" in r.output


# --------------------------------------------------------------------------
# Allow-list, config file, custom rules
# --------------------------------------------------------------------------

def test_allow_list_suppresses_finding(tmp_path):
    w(tmp_path, "a.env", f"S={KEY}\n")
    out = tmp_path / "r.json"
    scan(str(tmp_path), "--no-blast-radius", "--no-fail", "--report", "json", "-o", str(out))
    fid = json.loads(out.read_text())["findings"][0]["id"]
    assert scan(str(tmp_path), "--no-blast-radius", "--allow-list", fid).exit_code == 0


def test_config_file_sets_defaults_and_custom_rules(tmp_path):
    proj = tmp_path / "proj"
    w(proj, "a.env", "ACME_TOKEN=acme_" + "a1b2" * 8 + "\n")
    cfg = w(tmp_path, "aysal-scan.toml", '''
min_severity = "LOW"
[[rules]]
id = "acme-token"
regex = 'acme_[a-z0-9]{32}'
severity = "CRITICAL"
keywords = ["acme"]
''')
    out = tmp_path / "r.json"
    r = scan(str(proj), "--no-blast-radius", "--no-fail", "--report", "json", "-o", str(out), "--config", str(cfg))
    findings = json.loads(out.read_text())["findings"]
    assert [(f["rule_id"], f["severity"]) for f in findings] == [("acme-token", "CRITICAL")]


@pytest.mark.parametrize("toml", [
    'regex = "x"', 'min_severity = "NOPE"', '[[rules]]\nid = "a"\nregex = "("',
    '[[rules]]\nid = "a"', '[[rules]]\nid = "a"\nregex = "x"\nseverity = "WAT"',
    'unknown_key = 1',
])
def test_bad_config_exits_2(tmp_path, toml):
    cfg = w(tmp_path, "aysal-scan.toml", toml)
    assert scan(str(tmp_path), "--no-blast-radius", "--config", str(cfg)).exit_code == 2


def test_cli_flag_beats_config(tmp_path):
    w(tmp_path / "proj", "a.yml", DBURL + "\n")
    cfg = w(tmp_path, "c.toml", 'fail_on = "NONE"\n')
    assert scan(str(tmp_path / "proj"), "--no-blast-radius", "--config", str(cfg)).exit_code == 0
    assert scan(str(tmp_path / "proj"), "--no-blast-radius", "--config", str(cfg), "--fail-on", "HIGH").exit_code == 1


# --------------------------------------------------------------------------
# Git modes
# --------------------------------------------------------------------------

def test_commits_flag_warns_when_history_is_partial(repo):
    for i in range(3):
        w(repo, f"f{i}.txt", f"{i}\n")
        git(repo, "add", "."); git(repo, "commit", "-qm", f"c{i}")
    r = scan(str(repo), "--commits", "1", "--no-blast-radius")
    assert "older history was not checked" in r.output.replace("\n", " ")


def test_full_history_finds_secret_on_unmerged_branch_via_cli(repo):
    w(repo, "a.txt", "hi\n"); git(repo, "add", "."); git(repo, "commit", "-qm", "base")
    git(repo, "checkout", "-qb", "feature")
    w(repo, "leak.env", f"S={KEY}\n"); git(repo, "add", "."); git(repo, "commit", "-qm", "leak")
    git(repo, "checkout", "-q", "main")
    assert scan(str(repo), "--full-history", "--no-blast-radius").exit_code == 1
    assert scan(str(repo), "--commits", "5", "--no-blast-radius").exit_code == 0


def test_staged_scan_from_subdirectory_via_cli(repo):
    w(repo, "sub/x.env", f"S={KEY}\n"); git(repo, "add", ".")
    assert scan(str(repo / "sub"), "--staged", "--no-blast-radius").exit_code == 1


# --------------------------------------------------------------------------
# Verification pipeline through the CLI
# --------------------------------------------------------------------------

def _resp(status):
    r = MagicMock(); r.status_code = status; r.json.return_value = {}; r.headers = {}; r.text = ""
    return r


def test_revoked_key_is_downgraded_and_does_not_fail_the_build(tmp_path):
    w(tmp_path, "a.env", "T=ghp_" + "a1B2" * 9 + "\n")
    with patch("httpx.get", return_value=_resp(401)):
        r = scan(str(tmp_path))                       # blast radius ON
    assert r.exit_code == 0


def test_verification_notice_is_printed_for_network_checks(tmp_path):
    w(tmp_path, "a.env", "T=ghp_" + "a1B2" * 9 + "\n")
    with patch("httpx.get", return_value=_resp(401)):
        r = scan(str(tmp_path))
    assert "Verifying 1 credential" in r.output


def test_env_var_disables_verification(tmp_path, monkeypatch):
    w(tmp_path, "a.env", "T=ghp_" + "a1B2" * 9 + "\n")
    monkeypatch.setenv("AYSAL_SCAN_NO_VERIFY", "1")
    with patch("httpx.get", side_effect=AssertionError("network must not be used")):
        assert scan(str(tmp_path)).exit_code == 1


def test_verbose_shows_scoring_factors(tmp_path):
    w(tmp_path, "a.env", f"S={KEY}\n")
    r = scan(str(tmp_path), "--no-blast-radius", "--verbose")
    assert "credential class" in r.output
