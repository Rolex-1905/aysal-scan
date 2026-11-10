"""SARIF 2.1.0 reporter (GitHub code scanning compatible)."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from aysal_scan import __version__
from aysal_scan.models import Finding, ScanReport, Severity
from aysal_scan.remediation import remediation_for

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub groups alerts by this CVSS-like 0-10 score (>=9 critical, >=7 high, >=4 medium, else low).
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}

_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
FINGERPRINT_KEY = "aysal-scan/v1"


def _rule_id(f: Finding) -> str:
    return f.rule_id or f.secret_type.value.upper().replace(" ", "_")


def to_uri(file_path: str, root: Optional[str]) -> str:
    """Repo-relative, forward-slash path. Absolute paths under ``root`` are made relative to it."""
    p = Path(file_path)
    if p.is_absolute():
        for base in filter(None, (root, os.environ.get("GITHUB_WORKSPACE"))):
            try:
                return p.relative_to(Path(base).resolve()).as_posix()
            except ValueError:
                continue
        return p.as_posix().lstrip("/")
    return p.as_posix()


def build_sarif(
    report: ScanReport,
    baseline_fingerprints: Optional[set[str]] = None,
) -> dict:
    baseline_fingerprints = baseline_fingerprints or set()
    root = report.scan_root

    rules: dict[str, dict] = {}
    for f in report.findings:
        rid = _rule_id(f)
        existing = rules.get(rid)
        # One rule per detector; GitHub shows the most severe result severity.
        if existing is None or f.severity.rank < existing["_rank"]:
            rules[rid] = {
                "_rank": f.severity.rank,
                "id": rid,
                "name": f.secret_type.value,
                "shortDescription": {"text": f"Hardcoded {f.secret_type.value}"},
                "fullDescription": {
                    "text": (
                        f"A {f.secret_type.value} appears to be committed to the repository. "
                        "Leaked credentials can be used by anyone who can read the code or its history."
                    )
                },
                "help": {
                    "text": remediation_for(f.secret_type),
                    "markdown": "**How to fix**\n\n" + remediation_for(f.secret_type).replace("\n", "\n\n"),
                },
                "helpUri": "https://github.com/Rolex-1905/aysal-scan#readme",
                "defaultConfiguration": {"level": _LEVEL[f.severity]},
                "properties": {
                    "tags": ["security", "secret", "credentials"],
                    "security-severity": _SECURITY_SEVERITY[f.severity],
                },
            }
    for rule in rules.values():
        rule.pop("_rank", None)

    results = []
    for f in report.findings:
        message = f"{f.secret_type.value} detected ({f.masked_value})."
        if f.blast_radius and f.blast_radius.risk_summary:
            message += " " + f.blast_radius.risk_summary
        result = {
            "ruleId": _rule_id(f),
            "level": _LEVEL[f.severity],
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": to_uri(f.file_path, root), "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.line_number or 1},
                }
            }],
            "partialFingerprints": {"aysalScanFingerprint/v1": f.id},
            "fingerprints": {FINGERPRINT_KEY: f.id},
            "baselineState": "unchanged" if f.id in baseline_fingerprints else "new",
            "properties": {
                "severity": f.severity.value,
                "tags": f.tags,
                **({"riskScore": f.risk_score} if f.risk_score is not None else {}),
                **({"credentialActive": f.blast_radius.is_active}
                   if f.blast_radius and f.blast_radius.check_performed else {}),
            },
        }
        if f.locations:
            result["relatedLocations"] = [
                {
                    "id": i,
                    "physicalLocation": {
                        "artifactLocation": {"uri": to_uri(loc.file_path, root), "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": loc.line_number or 1},
                    },
                    "message": {"text": f"Also found here{f' (commit {loc.commit_hash})' if loc.commit_hash else ''}"},
                }
                for i, loc in enumerate(f.locations[:20], start=1)
            ]
        results.append(result)

    run: dict = {
        "tool": {
            "driver": {
                "name": "Aysal-Scan",
                "version": __version__,
                "informationUri": "https://github.com/Rolex-1905/aysal-scan",
                "rules": list(rules.values()),
            }
        },
        "results": results,
        "invocations": [{
            "executionSuccessful": True,
            "toolExecutionNotifications": [
                {"level": "warning", "message": {"text": w}} for w in report.warnings
            ],
        }],
    }
    return {"$schema": _SCHEMA, "version": "2.1.0", "runs": [run]}


def generate_sarif_report(
    report: ScanReport,
    output_path: Path,
    baseline_fingerprints: Optional[set[str]] = None,
) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(build_sarif(report, baseline_fingerprints), indent=2), encoding="utf-8"
    )
