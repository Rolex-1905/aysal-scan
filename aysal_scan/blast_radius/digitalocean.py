from __future__ import annotations

import httpx

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class DigitalOceanChecker(BaseChecker):
    PROVIDER = "DigitalOcean"

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            resp = httpx.get(
                "https://api.digitalocean.com/v2/account",
                headers={"Authorization": f"Bearer {secret_value}"},
                timeout=self.TIMEOUT,
            )
            early = self.classify_status(self.status_of(resp))
            if early is not None:
                return early
            account = self.json_or_empty(resp).get("account", {})
            email = account.get("email", "unknown") if isinstance(account, dict) else "unknown"
            return BlastRadiusResult(
                is_active=True, check_performed=True,
                account_info=f"DigitalOcean account: {email}",
                permissions=["Valid token (read vs write scope not exposed by the API)"],
                risk_summary=(
                    f"ACTIVE DigitalOcean token for {email}. Depending on its scope it can "
                    "create, modify or destroy droplets, volumes and databases."
                ),
                privilege="write",
            )
        except Exception as e:
            return BlastRadiusResult(
                is_active=None, check_performed=True, check_error=str(e),
                risk_summary="Could not verify token. Treat as active.",
                remediation="Manually revoke at cloud.digitalocean.com/account/api/tokens.",
            )
