from __future__ import annotations

import httpx

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class AnthropicChecker(BaseChecker):
    """Lists models with the key (read-only, no tokens consumed)."""

    PROVIDER = "Anthropic"

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            resp = httpx.get(
                "https://api.anthropic.com/v1/models",
                headers={"x-api-key": secret_value, "anthropic-version": "2023-06-01"},
                timeout=self.TIMEOUT,
            )
            early = self.classify_status(self.status_of(resp))
            if early is not None:
                return early
            models = self.json_or_empty(resp).get("data", [])
            ids = [m["id"] for m in models[:5] if isinstance(m, dict) and "id" in m]
            return BlastRadiusResult(
                is_active=True, check_performed=True,
                permissions=["API access (model listing confirmed)"], resources=ids,
                risk_summary=(
                    "ACTIVE Anthropic API key. Anyone holding it can make API calls "
                    "billed to your organization."
                ),
                privilege="write",
            )
        except Exception as e:
            return BlastRadiusResult(
                is_active=None, check_performed=True, check_error=str(e),
                risk_summary="Could not verify key. Treat as active.",
                remediation="Manually revoke at console.anthropic.com/settings/keys.",
            )
