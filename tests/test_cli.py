"""
CLI integration tests — use typer's CliRunner so no subprocess needed.
All blast radius calls are disabled via --no-blast-radius.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aysal_scan.cli import app

_STRIPE_LIVE = "sk" + "_live_" + "a" * 24

runner = CliRunner()


def _write(tmp: Path, name: str, content: str) -> None:
    (tmp / name).write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Basic scan
# ---------------------------------------------------------------------------
class TestScanCommand:
    def test_clean_directory_exits_zero(self, tmp_path):
        _write(tmp_path, "hello.py", "print('hello')\n")
        result = runner.invoke(app, ["scan", str(tmp_path), "--no-blast-radius"])
        assert result.exit_code == 0

    def test_secret_causes_exit_one(self, tmp_path):
        _write(tmp_path, "creds.env", f"STRIPE_KEY={_STRIPE_LIVE}\n")
        result = runner.invoke(app, ["scan", str(tmp_path), "--no-blast-radius"])
        assert result.exit_code == 1

    def test_no_fail_flag_overrides_exit_code(self, tmp_path):
        _write(tmp_path, "creds.env", f"STRIPE_KEY={_STRIPE_LIVE}\n")
        result = runner.invoke(app, ["scan", str(tmp_path), "--no-blast-radius", "--no-fail"])
        assert result.exit_code == 0

    def test_aws_key_detected(self, tmp_path):
        _write(tmp_path, "aws.env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
        result = runner.invoke(app, ["scan", str(tmp_path), "--no-blast-radius", "--no-fail"])
        assert "AWS" in result.output

    def test_private_key_detected(self, tmp_path):
        _write(tmp_path, "key.pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIB...\n")
        result = runner.invoke(app, ["scan", str(tmp_path), "--no-blast-radius", "--no-fail"])
        assert "Private Key" in result.output


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------
class TestJsonOutput:
    def test_valid_json_on_clean_dir(self, tmp_path):
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--no-blast-radius", "--report", "json", "--no-fail"]
        )
        data = json.loads(result.stdout)
        assert "findings" in data
        assert data["findings"] == []
        assert data["passed"] is True

    def test_finding_in_json_output(self, tmp_path):
        _write(tmp_path, "creds.env", f"STRIPE_KEY={_STRIPE_LIVE}\n")
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--no-blast-radius", "--report", "json", "--no-fail"]
        )
        data = json.loads(result.stdout)
        assert len(data["findings"]) >= 1
        assert data["passed"] is False

    def test_json_structure(self, tmp_path):
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--no-blast-radius", "--report", "json", "--no-fail"]
        )
        data = json.loads(result.stdout)
        required_keys = {
            "tool_version", "scan_target", "scan_time", "files_scanned",
            "commits_scanned", "findings", "total_critical", "total_high",
            "total_medium", "total_low", "total_info", "passed",
        }
        assert required_keys.issubset(data.keys())


# ---------------------------------------------------------------------------
# Severity filtering
# ---------------------------------------------------------------------------
class TestSeverityFilter:
    def test_medium_filtered_when_min_high(self, tmp_path):
        # JWT is MEDIUM severity
        _write(
            tmp_path, "token.txt",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0dXNlciJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n",
        )
        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--no-blast-radius", "--report", "json",
             "--no-fail", "--min-severity", "HIGH"],
        )
        data = json.loads(result.stdout)
        medium_findings = [f for f in data["findings"] if f["severity"] == "MEDIUM"]
        assert medium_findings == []

    def test_critical_always_shown(self, tmp_path):
        _write(tmp_path, "creds.env", f"STRIPE_KEY={_STRIPE_LIVE}\n")
        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--no-blast-radius", "--report", "json",
             "--no-fail", "--min-severity", "CRITICAL"],
        )
        data = json.loads(result.stdout)
        # Stripe live key is CRITICAL
        assert any(f["severity"] == "CRITICAL" for f in data["findings"])


# ---------------------------------------------------------------------------
# HTML output
# ---------------------------------------------------------------------------
class TestHtmlOutput:
    def test_html_file_created(self, tmp_path):
        out_file = tmp_path / "report.html"
        runner.invoke(
            app,
            ["scan", str(tmp_path), "--no-blast-radius", "--report", "html",
             "--output", str(out_file), "--no-fail"],
        )
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "Aysal-Scan" in content
        assert "<!DOCTYPE html>" in content

    def test_html_contains_finding(self, tmp_path):
        _write(tmp_path, "creds.env", f"STRIPE_KEY={_STRIPE_LIVE}\n")
        out_file = tmp_path / "report.html"
        runner.invoke(
            app,
            ["scan", str(tmp_path), "--no-blast-radius", "--report", "html",
             "--output", str(out_file), "--no-fail"],
        )
        content = out_file.read_text(encoding="utf-8")
        assert "Stripe" in content


# ---------------------------------------------------------------------------
# Ignore patterns
# ---------------------------------------------------------------------------
class TestIgnorePatterns:
    def test_AysalScanignore_respected(self, tmp_path):
        _write(tmp_path, "creds.env", f"STRIPE_KEY={_STRIPE_LIVE}\n")
        _write(tmp_path, "AysalScanignore", "creds.env\n")
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--no-blast-radius", "--report", "json", "--no-fail"]
        )
        data = json.loads(result.stdout)
        assert data["findings"] == []


# ---------------------------------------------------------------------------
# Version flag
# ---------------------------------------------------------------------------
def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "Aysal-Scan" in result.output
