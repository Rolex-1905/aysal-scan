import httpx
from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class SlackChecker(BaseChecker):

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            resp = httpx.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {secret_value}"},
                timeout=self.TIMEOUT,
            )
            data = resp.json()
            if not data.get("ok"):
                error = data.get("error", "unknown")
                if error in ("invalid_auth", "token_revoked", "not_authed"):
                    return BlastRadiusResult(
                        is_active=False,
                        check_performed=True,
                        risk_summary="Slack token is invalid or revoked.",
                        remediation="Remove from git history.",
                    )
                return BlastRadiusResult(
                    is_active=None,
                    check_performed=True,
                    check_error=error,
                    risk_summary="Could not verify token status.",
                    remediation="Manually revoke at api.slack.com/apps.",
                )
            team = data.get("team", "unknown workspace")
            user = data.get("user", "unknown bot")
            bot_id = data.get("bot_id", "")
            scopes = resp.headers.get("x-oauth-scopes", "")
            risk = (
                f"ACTIVE Slack token for {'bot' if bot_id else 'user'} '{user}' "
                f"in workspace '{team}'."
            )
            if "chat:write" in scopes:
                risk += " Can send messages to channels."
            if "files:write" in scopes:
                risk += " Can upload files."
            if "admin" in scopes:
                risk += " Has admin-level access."
            return BlastRadiusResult(
                is_active=True,
                check_performed=True,
                account_info=f"Workspace: {team} | User/Bot: {user}",
                permissions=[s.strip() for s in scopes.split(",") if s.strip()][:10],
                risk_summary=risk,
                remediation=(
                    "1. Go to api.slack.com/apps → your app → OAuth & Permissions\n"
                    "2. Revoke this token immediately\n"
                    "3. Audit recent bot activity in Slack audit logs\n"
                    "4. Remove from git history with: git filter-repo"
                ),
            )
        except Exception as e:
            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=str(e),
                risk_summary="Could not verify token. Treat as active.",
                remediation="Manually revoke at api.slack.com/apps.",
            )