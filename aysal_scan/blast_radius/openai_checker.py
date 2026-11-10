from __future__ import annotations

import httpx

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class OpenAIChecker(BaseChecker):
    PROVIDER = "OpenAI"

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            resp = httpx.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {secret_value}"},
                timeout=self.TIMEOUT,
            )
            early = self.classify_status(self.status_of(resp))
            if early is not None:
                return early

            models = self.json_or_empty(resp).get("data", [])
            model_ids = [m["id"] for m in models[:5] if isinstance(m, dict) and "id" in m]
            return BlastRadiusResult(
                is_active=True,
                check_performed=True,
                permissions=["API access (model listing confirmed)"],
                resources=model_ids,
                risk_summary=(
                    "ACTIVE OpenAI API key. Anyone with this key can make API calls "
                    "billed to your account."
                ),
                privilege="write",
            )
        except Exception as e:
            return BlastRadiusResult(
                is_active=None, check_performed=True, check_error=str(e),
                risk_summary="Could not verify key. Treat as active.",
                remediation="Manually revoke at platform.openai.com/api-keys.",
            )
