from __future__ import annotations

import httpx

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class GitLabChecker(BaseChecker):
    PROVIDER = "GitLab"

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            headers = {"PRIVATE-TOKEN": secret_value}
            resp = httpx.get("https://gitlab.com/api/v4/user", headers=headers, timeout=self.TIMEOUT)
            early = self.classify_status(self.status_of(resp))
            if early is not None:
                return early
            data = self.json_or_empty(resp)
            username = data.get("username", "unknown")

            scopes: list[str] = []
            try:
                me = httpx.get(
                    "https://gitlab.com/api/v4/personal_access_tokens/self",
                    headers=headers, timeout=self.TIMEOUT,
                )
                if self.status_of(me) == 200:
                    scopes = [s for s in self.json_or_empty(me).get("scopes", []) if isinstance(s, str)]
            except Exception:
                pass

            if "sudo" in scopes or "admin_mode" in scopes or data.get("is_admin"):
                privilege = "admin"
            elif any(s in scopes for s in ("api", "write_repository", "write_registry")):
                privilege = "write"
            elif scopes:
                privilege = "read"
            else:
                privilege = None
            return BlastRadiusResult(
                is_active=True, check_performed=True,
                account_info=f"GitLab user: {username}",
                permissions=scopes or ["Scopes not exposed"],
                resources=["All projects accessible by this user"],
                risk_summary=f"ACTIVE GitLab token for '{username}'. Scopes: {', '.join(scopes) or 'unknown'}.",
                privilege=privilege,
            )
        except Exception as e:
            return BlastRadiusResult(
                is_active=None, check_performed=True, check_error=str(e),
                risk_summary="Could not verify token. Treat as active.",
                remediation="Manually revoke at gitlab.com/-/user_settings/personal_access_tokens.",
            )
