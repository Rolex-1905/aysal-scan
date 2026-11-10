#!/usr/bin/env bash
# GitHub Action entrypoint. Reads inputs, runs ONE scan, writes HTML + JSON + SARIF + Markdown.
#
# Why bash and not /bin/sh: GitHub names inputs like "min-severity" as the environment variable
# INPUT_MIN-SEVERITY (hyphen kept). dash (/bin/sh on Debian) silently DROPS variables whose names
# are not valid identifiers, so a #!/bin/sh script never sees them and every input falls back to
# its default. bash keeps them; /proc/self/environ is used as a second line of defence.
set -euo pipefail

input() {
  local name="$1" default="$2" upper value
  upper=$(printf '%s' "$name" | tr 'a-z' 'A-Z')
  value=$(printenv "INPUT_${upper}" 2>/dev/null || true)
  if [ -z "$value" ]; then
    value=$(printenv "INPUT_${upper//-/_}" 2>/dev/null || true)
  fi
  if [ -z "$value" ] && [ -r /proc/self/environ ]; then
    value=$(tr '\0' '\n' < /proc/self/environ | sed -n "s/^INPUT_${upper}=//p" | head -n1 || true)
  fi
  if [ -n "$value" ]; then printf '%s' "$value"; else printf '%s' "$default"; fi
}

WORKSPACE="${GITHUB_WORKSPACE:-/github/workspace}"
PATH_TO_SCAN=$(input path .)
MIN_SEVERITY=$(input min-severity HIGH)
NO_BLAST=$(input no-blast-radius false)
FAIL_ON_FINDINGS=$(input fail-on-findings true)
FAIL_ON=$(input fail-on HIGH)
HISTORY=$(input history none)          # none | full | <number of commits>
CONFIG=$(input config "")

REPORT_HTML="${WORKSPACE}/aysal-scan-report.html"
REPORT_JSON="${WORKSPACE}/aysal-scan-report.json"
REPORT_SARIF="${WORKSPACE}/aysal-scan-results.sarif"
REPORT_MD="${WORKSPACE}/aysal-scan-report.md"

git config --global --add safe.directory "${WORKSPACE}" 2>/dev/null || true

args=(scan "${PATH_TO_SCAN}" --min-severity "${MIN_SEVERITY}"
      --report html --output "${REPORT_HTML}"
      --output-json "${REPORT_JSON}" --output-sarif "${REPORT_SARIF}"
      --output-markdown "${REPORT_MD}")

case "${HISTORY}" in
  none|"")   ;;
  full)      args+=(--full-history) ;;
  *[!0-9]*)  echo "Invalid 'history' input: ${HISTORY} (use none, full, or a number)" >&2; exit 2 ;;
  *)         args+=(--commits "${HISTORY}") ;;
esac

[ -n "${CONFIG}" ] && args+=(--config "${CONFIG}")
[ "${NO_BLAST}" = "true" ] && args+=(--no-blast-radius)

if [ "${FAIL_ON_FINDINGS}" = "true" ]; then
  args+=(--fail-on "${FAIL_ON}")
else
  args+=(--no-fail)      # findings never fail the job; scan ERRORS (exit 2) still do
fi

SCAN_EXIT=0
aysal-scan "${args[@]}" || SCAN_EXIT=$?

FINDINGS_COUNT=0
if [ -f "${REPORT_JSON}" ]; then
  FINDINGS_COUNT=$(python3 -c "
import json
try:
    print(len(json.load(open('${REPORT_JSON}')).get('findings', [])))
except Exception:
    print(0)
")
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "findings-count=${FINDINGS_COUNT}"
    echo "report-path=${REPORT_HTML}"
    echo "sarif-path=${REPORT_SARIF}"
  } >> "${GITHUB_OUTPUT}"
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "${REPORT_MD}" ]; then
  cat "${REPORT_MD}" >> "${GITHUB_STEP_SUMMARY}"
fi

exit "${SCAN_EXIT}"
