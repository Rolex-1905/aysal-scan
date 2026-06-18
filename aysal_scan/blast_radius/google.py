"""Google API Key blast radius checker."""
from __future__ import annotations

import httpx
from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult

# Low-quota APIs to probe — ordered by likelihood of being enabled
_PROBE_URLS = [
    ("Maps Geocoding", "https://maps.googleapis.com/maps/api/geocode/json?address=test&key={}"),
    ("YouTube Data", "https://www.googleapis.com/youtube/v3/videos?part=id&id=test&key={}"),
]


class GoogleChecker(BaseChecker):

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            enabled_apis: list[str] = []
            is_valid = False

            for api_name, url_template in _PROBE_URLS:
                try:
                    resp = httpx.get(
                        url_template.format(secret_value),
                        timeout=self.TIMEOUT,
                    )
                    # 200 or 400 (bad request but valid key) = key is active
                    # 403 with keyInvalid = inactive
                    if resp.status_code in (200, 400):
                        body = resp.json()
                        error_reason = (
                            body.get("error", {}).get("errors", [{}])[0].get("reason", "")
                            if "error" in body
                            else ""
                        )
                        if error_reason not in ("keyInvalid", "keyExpired"):
                            is_valid = True
                            enabled_apis.append(api_name)
                    elif resp.status_code == 403:
                        body = resp.json()
                        error_reason = (
                            body.get("error", {}).get("errors", [{}])[0].get("reason", "")
                            if "error" in body
                            else ""
                        )
                        if error_reason == "keyInvalid":
                            # Confirmed invalid — no need to probe further
                            return BlastRadiusResult(
                                is_active=False,
                                check_performed=True,
                                risk_summary="Google API key is invalid or revoked.",
                                remediation="Remove from git history.",
                            )
                        # 403 for other reasons (API not enabled, quota) — key may still be valid
                        is_valid = True
                except Exception:
                    continue

            if not is_valid:
                return BlastRadiusResult(
                    is_active=None,
                    check_performed=True,
                    risk_summary="Could not determine Google API key status. Treat as active.",
                    remediation="Manually verify and revoke at console.cloud.google.com/apis/credentials.",
                )

            apis_str = ", ".join(enabled_apis) if enabled_apis else "unknown (quota/permission limited)"
            return BlastRadiusResult(
                is_active=True,
                check_performed=True,
                permissions=[f"Enabled API access: {apis_str}"],
                risk_summary=(
                    f"ACTIVE Google API key. Accessible APIs: {apis_str}. "
                    "May incur charges or expose data depending on enabled services."
                ),
                remediation=(
                    "1. Go to console.cloud.google.com/apis/credentials\n"
                    "2. Delete or restrict this API key immediately\n"
                    "3. Check API usage logs for unauthorized calls\n"
                    "4. Remove from git history with: git filter-repo"
                ),
            )

        except Exception as exc:
            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=str(exc),
                risk_summary="Could not verify key. Treat as active.",
                remediation="Manually verify at console.cloud.google.com/apis/credentials.",
            )