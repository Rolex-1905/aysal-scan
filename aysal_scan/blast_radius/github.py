from __future__ import annotations

import re

import httpx

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult

_ADMIN_SCOPES = {"delete_repo", "site_admin", "admin:org", "admin:enterprise", "admin:org_hook",
                 "admin:repo_hook", "admin:gpg_key", "admin:public_key"}
_WRITE_SCOPES = {"repo", "workflow", "write:packages", "delete:packages", "gist", "write:org",
                 "public_repo", "notifications", "user"}
_LAST_PAGE = re.compile(r'[?&]page=(\d+)[^>]*>;\s*rel="last"')


class GitHubChecker(BaseChecker):
    PROVIDER = "GitHub"

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            headers = {
                "Authorization": f"token {secret_value}",
                "Accept": "application/vnd.github+json",
            }
            resp = httpx.get("https://api.github.com/user", headers=headers, timeout=self.TIMEOUT)
            early = self.classify_status(self.status_of(resp))
            if early is not None:
                return early

            username = self.json_or_empty(resp).get("login", "unknown")
            raw_scopes = resp.headers.get("X-OAuth-Scopes")
            scopes = (
                [s.strip() for s in raw_scopes.split(",") if s.strip()]
                if isinstance(raw_scopes, str) else []
            )
            token_kind_unknown = not isinstance(raw_scopes, str)  # fine-grained / app tokens

            repo_note = ""
            try:
                repos = httpx.get(
                    "https://api.github.com/user/repos?per_page=1",
                    headers=headers, timeout=self.TIMEOUT,
                )
                if self.status_of(repos) == 200:
                    link = repos.headers.get("link", "") if hasattr(repos.headers, "get") else ""
                    last = _LAST_PAGE.search(link) if isinstance(link, str) else None
                    repo_note = (
                        f"Can list {last.group(1)} repositories."
                        if last else "Repo access confirmed."
                    )
                else:
                    repo_note = "Repo access unconfirmed."
            except Exception:
                repo_note = "Repo access unconfirmed (network error)."

            has_delete = "delete_repo" in scopes
            if scopes:
                scope_text = ", ".join(scopes)
            elif token_kind_unknown:
                scope_text = "not exposed (fine-grained or app token — check its permissions in GitHub)"
            else:
                scope_text = "none"
            risk = f"ACTIVE token for GitHub user '{username}'. Scopes: {scope_text}. {repo_note}"
            if has_delete:
                risk += " CAN DELETE REPOSITORIES."

            if any(s in _ADMIN_SCOPES or s.startswith("admin:") for s in scopes):
                privilege = "admin"
            elif any(s in _WRITE_SCOPES or s.startswith("write:") for s in scopes):
                privilege = "write"
            elif scopes:
                privilege = "read"
            else:
                privilege = None

            return BlastRadiusResult(
                is_active=True,
                check_performed=True,
                account_info=f"GitHub user: {username}",
                permissions=scopes or (["Fine-grained / app token (scopes not exposed)"] if token_kind_unknown else []),
                resources=["All repos accessible by this token"],
                risk_summary=risk,
                privilege=privilege,
            )
        except Exception as e:
            return BlastRadiusResult(
                is_active=None, check_performed=True, check_error=str(e),
                risk_summary="Could not verify token. Treat as active.",
                remediation="Manually revoke at github.com/settings/tokens.",
            )
