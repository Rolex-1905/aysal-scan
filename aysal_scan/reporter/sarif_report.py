"""SARIF 2.1.0 reporter — GitHub Security tab integration."""
from __future__ import annotations

import json
from pathlib import Path

from aysal_scan.models import ScanReport, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "none",
}


def generate_sarif_report(
    report: ScanReport,
    output_path: Path,
    baseline_fingerprints: set[str] | None = None,
) -> None:
    rules = {}
    results = []

    for finding in report.findings:
        rule_id = finding.secret_type.value.replace(" ", "_").upper()

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.secret_type.value.replace(" ", ""),
                "shortDescription": {
                    "text": f"Leaked {finding.secret_type.value} detected"
                },
                "fullDescription": {
                    "text": (
                        finding.blast_radius.risk_summary
                        if finding.blast_radius and finding.blast_radius.risk_summary
                        else f"A {finding.secret_type.value} was found in the repository."
                    )
                },
                "helpUri": "https://github.com/Rolex-1905/aysal-scan",
                "properties": {
                    "tags": ["security", "secret-detection"],
                    "severity": finding.severity.value.lower(),
                },
            }

        remediation_text = (
            finding.blast_radius.remediation
            if finding.blast_radius and finding.blast_radius.remediation
            else "Revoke this credential immediately and remove it from git history using git filter-repo."
        )

        result = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL[finding.severity],
            "message": {
                "text": (
                    f"{finding.secret_type.value} found: {finding.masked_value}. "
                    f"{remediation_text}"
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path.lstrip("/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line_number or 1,
                        },
                    }
                }
            ],
            "fingerprints": {
                "aysal-scan/v1": finding.id
            },
            "baselineState": (
                "unchanged"
                if baseline_fingerprints and finding.id in baseline_fingerprints
                else "new"
            ),
        }

        # Add extra locations if the secret appears in multiple files
        if finding.locations:
            result["relatedLocations"] = [
                {
                    "id": idx + 1,
                    "message": {"text": f"Also found here"},
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": loc.file_path.lstrip("/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": loc.line_number or 1,
                        },
                    },
                }
                for idx, loc in enumerate(finding.locations[:10])
            ]

        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Aysal-Scan",
                        "version": report.tool_version,
                        "informationUri": "https://github.com/Rolex-1905/aysal-scan",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "artifacts": [
                    {"location": {"uri": report.scan_target, "uriBaseId": "%SRCROOT%"}}
                ],
            }
        ],
    }

    output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")