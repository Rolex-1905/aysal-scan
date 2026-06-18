#!/bin/sh
set -e

PATH_TO_SCAN="${INPUT_PATH:-.}"
MIN_SEVERITY="${INPUT_MIN_SEVERITY:-HIGH}"
NO_BLAST="${INPUT_NO_BLAST_RADIUS:-false}"
FAIL_ON="${INPUT_FAIL_ON_FINDINGS:-true}"
REPORT_HTML="${GITHUB_WORKSPACE:-/github/workspace}/aysal-scan-report.html"
REPORT_JSON="${GITHUB_WORKSPACE:-/github/workspace}/aysal-scan-report.json"
REPORT_SARIF="${GITHUB_WORKSPACE:-/github/workspace}/aysal-scan-results.sarif"

# Build flags — single scan, all three formats at once
FLAGS="--min-severity ${MIN_SEVERITY}"
FLAGS="${FLAGS} --report html --output ${REPORT_HTML}"
FLAGS="${FLAGS} --output-json ${REPORT_JSON}"
FLAGS="${FLAGS} --output-sarif ${REPORT_SARIF}"

if [ "${NO_BLAST}" = "true" ]; then
  FLAGS="${FLAGS} --no-blast-radius"
fi
if [ "${FAIL_ON}" != "true" ]; then
  FLAGS="${FLAGS} --no-fail"
fi

# Single scan — produces HTML + JSON + SARIF in one pass
aysal-scan scan "${PATH_TO_SCAN}" ${FLAGS} || SCAN_EXIT=$?

# Parse finding count from JSON
FINDINGS_COUNT=0
if [ -f "${REPORT_JSON}" ]; then
  FINDINGS_COUNT=$(python3 -c "
import json, sys
try:
    with open('${REPORT_JSON}') as f:
        d = json.load(f)
    print(len(d.get('findings', [])))
except Exception:
    print(0)
")
fi

# Set GitHub Actions outputs
if [ -n "${GITHUB_OUTPUT}" ]; then
  echo "findings-count=${FINDINGS_COUNT}" >> "${GITHUB_OUTPUT}"
  echo "report-path=${REPORT_HTML}" >> "${GITHUB_OUTPUT}"
  echo "sarif-path=${REPORT_SARIF}" >> "${GITHUB_OUTPUT}"
fi

# Write step summary
if [ -n "${GITHUB_STEP_SUMMARY}" ]; then
  echo "## 🔐 Aysal-Scan Results" >> "${GITHUB_STEP_SUMMARY}"
  echo "- Findings: **${FINDINGS_COUNT}**" >> "${GITHUB_STEP_SUMMARY}"
  echo "- Min severity: **${MIN_SEVERITY}**" >> "${GITHUB_STEP_SUMMARY}"
  echo "- Blast radius: **$([ "${NO_BLAST}" = "true" ] && echo "skipped" || echo "checked")**" >> "${GITHUB_STEP_SUMMARY}"
  echo "- HTML report: \`${REPORT_HTML}\`" >> "${GITHUB_STEP_SUMMARY}"
  echo "- SARIF report: \`${REPORT_SARIF}\`" >> "${GITHUB_STEP_SUMMARY}"
fi

exit "${SCAN_EXIT:-0}"