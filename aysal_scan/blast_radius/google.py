"""Google API key checker.

Google APIs report a bad key in several shapes: the legacy ``errors[0].reason == "keyInvalid"``
(HTTP 403), the modern ``API_KEY_INVALID`` detail / "API key not valid" message (HTTP 400), and
Maps' HTTP-200 body ``{"status": "REQUEST_DENIED", "error_message": "The provided API key is
invalid."}``. All are recognised so a revoked or fake key is never reported as active.
"""
from __future__ import annotations

import json

import httpx

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult

_PROBES = [
    ("Maps Geocoding", "https://maps.googleapis.com/maps/api/geocode/json?address=test&key={}"),
    ("YouTube Data", "https://www.googleapis.com/youtube/v3/videos?part=id&id=test&key={}"),
]

_INVALID_HINTS = (
    "keyinvalid", "keyexpired", "api_key_invalid", "api key not valid", "key not valid",
    "provided api key is invalid", "api key expired", "invalid api key",
)


class GoogleChecker(BaseChecker):
    PROVIDER = "Google"

    def _verdict(self, resp) -> str:
        """'valid' (works) | 'restricted' (key recognised, call refused) | 'invalid' | 'unknown'."""
        status = self.status_of(resp)
        body = self.json_or_empty(resp)
        blob = json.dumps(body).lower()
        if any(hint in blob for hint in _INVALID_HINTS):
            return "invalid"
        if status == 200:
            api_status = str(body.get("status", "OK")).upper()
            if api_status in ("OK", "ZERO_RESULTS"):
                return "valid"
            return "restricted" if api_status == "REQUEST_DENIED" else "unknown"
        if status in (400, 403):
            return "restricted"
        return "unknown"

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            enabled: list[str] = []
            verdicts: list[str] = []
            for api_name, template in _PROBES:
                try:
                    resp = httpx.get(template.format(secret_value), timeout=self.TIMEOUT)
                except Exception:
                    verdicts.append("unknown")
                    continue
                verdict = self._verdict(resp)
                verdicts.append(verdict)
                if verdict == "valid":
                    enabled.append(api_name)

            if "valid" in verdicts or "restricted" in verdicts:
                apis = ", ".join(enabled) if enabled else "unknown (restricted / quota limited)"
                return BlastRadiusResult(
                    is_active=True, check_performed=True,
                    permissions=[f"Enabled API access: {apis}"],
                    risk_summary=(
                        f"ACTIVE Google API key. Accessible APIs: {apis}. "
                        "May incur charges or expose data depending on enabled services."
                    ),
                    remediation=(
                        "1. Go to console.cloud.google.com/apis/credentials\n"
                        "2. Delete or restrict this API key immediately\n"
                        "3. Check API usage logs for unauthorized calls\n"
                        "4. Remove from git history with: git filter-repo"
                    ),
                    privilege="write",
                )
            if verdicts and all(v == "invalid" for v in verdicts):
                return BlastRadiusResult(
                    is_active=False, check_performed=True,
                    risk_summary="Google API key is invalid or revoked.",
                    remediation="Remove from git history.",
                )
            return BlastRadiusResult(
                is_active=None, check_performed=True,
                risk_summary="Could not determine Google API key status. Treat as active.",
                remediation="Manually verify and revoke at console.cloud.google.com/apis/credentials.",
            )
        except Exception as exc:
            return BlastRadiusResult(
                is_active=None, check_performed=True, check_error=str(exc),
                risk_summary="Could not verify key. Treat as active.",
                remediation="Manually verify at console.cloud.google.com/apis/credentials.",
            )
