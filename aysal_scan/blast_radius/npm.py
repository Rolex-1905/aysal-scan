from __future__ import annotations

import httpx

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class NpmChecker(BaseChecker):
    PROVIDER = "npm"

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            resp = httpx.get(
                "https://registry.npmjs.org/-/whoami",
                headers={"Authorization": f"Bearer {secret_value}"},
                timeout=self.TIMEOUT,
            )
            early = self.classify_status(self.status_of(resp), inactive=(401, 403))
            if early is not None:
                return early

            username = self.json_or_empty(resp).get("username", "unknown")
            return BlastRadiusResult(
                is_active=True, check_performed=True,
                account_info=f"npm user: {username}",
                permissions=["Valid token (npm does not expose whether it can publish)"],
                risk_summary=(
                    f"ACTIVE npm token for user '{username}'. If it has publish rights it can "
                    "push malicious versions of this user's packages (supply-chain risk)."
                ),
                privilege="write",
            )
        except Exception as e:
            return BlastRadiusResult(
                is_active=None, check_performed=True, check_error=str(e),
                risk_summary="Could not verify token. Treat as active.",
                remediation="Manually revoke at npmjs.com/settings/tokens.",
            )
