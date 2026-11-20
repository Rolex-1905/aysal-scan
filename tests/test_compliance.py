"""CWE / OWASP mapping."""
from __future__ import annotations

import json

from typer.testing import CliRunner

from aysal_scan.cli import app
from aysal_scan.compliance import apply_compliance, classify, owasp_label
from aysal_scan.models import Finding, SecretType, Severity


def _f(stype):
    return Finding(id="x" * 8, secret_type=stype, severity=Severity.HIGH, file_path="a", masked_value="m")


def test_every_secret_type_has_a_mapping():
    for t in SecretType:
        cwe, owasp = classify(t)
        assert cwe.startswith("CWE-") and owasp.endswith(":2021")


def test_specific_mappings():
    assert classify(SecretType.GITHUB_TOKEN)[0] == "CWE-798"
    assert classify(SecretType.PRIVATE_KEY) == ("CWE-321", "A02:2021")
    assert classify(SecretType.DATABASE_URL)[0] == "CWE-259"
    assert classify(SecretType.JWT)[0] == "CWE-522"
    assert owasp_label("A02:2021") == "A02:2021 Cryptographic Failures"


def test_apply_compliance_sets_fields():
    fs = apply_compliance([_f(SecretType.PRIVATE_KEY), _f(SecretType.OPENAI_KEY)])
    assert fs[0].cwe == ["CWE-321"] and fs[0].owasp == "A02:2021"
    assert fs[1].cwe == ["CWE-798"]


def test_json_and_sarif_reports_carry_cwe(tmp_path):
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "a.env").write_text("S=sk_live_" + "a1B2c3D4" * 3 + "\n")
    runner = CliRunner()
    j, s = tmp_path / "r.json", tmp_path / "r.sarif"
    runner.invoke(app, ["scan", str(tmp_path / "proj"), "--no-blast-radius", "--no-fail",
                        "--report", "json", "-o", str(j), "--output-sarif", str(s)])
    finding = json.loads(j.read_text())["findings"][0]
    assert finding["cwe"] == ["CWE-798"] and finding["owasp"] == "A07:2021"
    rule = json.loads(s.read_text())["runs"][0]["tool"]["driver"]["rules"][0]
    assert "external/cwe/cwe-798" in rule["properties"]["tags"]
    assert "A07:2021" in rule["properties"]["owasp"]
