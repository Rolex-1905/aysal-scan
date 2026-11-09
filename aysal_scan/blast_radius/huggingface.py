from __future__ import annotations

import httpx

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class HuggingFaceChecker(BaseChecker):
    PROVIDER = "Hugging Face"

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            resp = httpx.get(
                "https://huggingface.co/api/whoami-v2",
                headers={"Authorization": f"Bearer {secret_value}"},
                timeout=self.TIMEOUT,
            )
            early = self.classify_status(self.status_of(resp))
            if early is not None:
                return early
            data = self.json_or_empty(resp)
            name = data.get("name", "unknown")
            role = ""
            auth = data.get("auth")
            if isinstance(auth, dict) and isinstance(auth.get("accessToken"), dict):
                role = str(auth["accessToken"].get("role", ""))
            privilege = {"write": "write", "read": "read", "admin": "admin"}.get(role)
            return BlastRadiusResult(
                is_active=True, check_performed=True,
                account_info=f"Hugging Face user: {name}",
                permissions=[f"Token role: {role or 'unknown / fine-grained'}"],
                risk_summary=(
                    f"ACTIVE Hugging Face token for '{name}'"
                    + (" with WRITE access: can modify or delete models and datasets." if role == "write" else ".")
                ),
                privilege=privilege,
            )
        except Exception as e:
            return BlastRadiusResult(
                is_active=None, check_performed=True, check_error=str(e),
                risk_summary="Could not verify token. Treat as active.",
                remediation="Manually revoke at huggingface.co/settings/tokens.",
            )
