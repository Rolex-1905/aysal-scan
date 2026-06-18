import httpx
from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class GitHubChecker(BaseChecker):

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            headers = {
                "Authorization": f"token {secret_value}",
                "Accept": "application/vnd.github+json",
            }
            resp = httpx.get(
                "https://api.github.com/user",
                headers=headers,
                timeout=self.TIMEOUT,
            )

            if resp.status_code == 401:
                return BlastRadiusResult(
                    is_active=False,
                    check_performed=True,
                    risk_summary="Token is invalid or already revoked.",
                    remediation="Remove from git history using git filter-repo.",
                )

            # Treat anything other than a clean 200 as unverifiable
            if resp.status_code != 200:
                return BlastRadiusResult(
                    is_active=None,
                    check_performed=True,
                    check_error=f"Unexpected HTTP {resp.status_code} from GitHub API",
                    risk_summary="Could not verify token status. Treat as active.",
                    remediation="Manually revoke at github.com/settings/tokens.",
                )

            user_data = resp.json()
            username = user_data.get("login", "unknown")

            scopes_header = resp.headers.get("X-OAuth-Scopes", "")
            scopes = [s.strip() for s in scopes_header.split(",") if s.strip()]

            # Second call: count repos (best-effort, don't fail the whole check)
            try:
                repos_resp = httpx.get(
                    "https://api.github.com/user/repos?per_page=1",
                    headers=headers,
                    timeout=self.TIMEOUT,
                )
                repo_note = (
                    "Repo access confirmed."
                    if repos_resp.status_code == 200
                    else "Repo access unconfirmed."
                )
            except Exception:
                repo_note = "Repo access unconfirmed (network error)."

            has_delete = "delete_repo" in scopes
            risk = (
                f"ACTIVE token for GitHub user '{username}'. "
                f"Scopes: {', '.join(scopes) or 'none'}. {repo_note}"
            )
            if has_delete:
                risk += " CAN DELETE REPOSITORIES."

            return BlastRadiusResult(
                is_active=True,
                check_performed=True,
                account_info=f"GitHub user: {username}",
                permissions=scopes,
                resources=["All repos accessible by this token"],
                risk_summary=risk,
                remediation=(
                    "1. Go to github.com/settings/tokens\n"
                    "2. Revoke this token immediately\n"
                    "3. Rotate any secrets it had access to\n"
                    "4. Remove from git history with: git filter-repo"
                ),
            )

        except Exception as e:
            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=str(e),
                risk_summary="Could not verify token. Treat as active.",
                remediation="Manually revoke at github.com/settings/tokens.",
            )