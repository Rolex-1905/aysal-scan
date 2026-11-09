from __future__ import annotations

import httpx

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult

_DEAD = {"invalid_auth", "token_revoked", "not_authed", "account_inactive", "token_expired"}


class SlackChecker(BaseChecker):
    PROVIDER = "Slack"

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            resp = httpx.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {secret_value}"},
                timeout=self.TIMEOUT,
            )
            status = self.status_of(resp)
            if status == 429:  # Slack signals rate limits at the HTTP level
                return self.classify_status(status)  # type: ignore[return-value]
            data = self.json_or_empty(resp)
            if not data.get("ok"):
                error = str(data.get("error", "unknown"))
                if error in _DEAD:
                    return BlastRadiusResult(
                        is_active=False, check_performed=True,
                        risk_summary="Slack token is invalid or revoked.",
                        remediation="Remove from git history.",
                    )
                if error == "ratelimited":
                    return self.classify_status(429)  # type: ignore[return-value]
                return BlastRadiusResult(
                    is_active=None, check_performed=True, check_error=error,
                    risk_summary="Could not verify token status.",
                    remediation="Manually revoke at api.slack.com/apps.",
                )
            team = data.get("team", "unknown workspace")
            user = data.get("user", "unknown bot")
            bot_id = data.get("bot_id", "")
            scopes = resp.headers.get("x-oauth-scopes", "") if hasattr(resp.headers, "get") else ""
            scopes = scopes if isinstance(scopes, str) else ""
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
            privilege = (
                "admin" if "admin" in scopes
                else "write" if any(w in scopes for w in ("chat:write", "files:write", "write"))
                else "read"
            )
            return BlastRadiusResult(
                is_active=True, check_performed=True,
                account_info=f"Workspace: {team} | User/Bot: {user}",
                permissions=[s.strip() for s in scopes.split(",") if s.strip()][:10],
                risk_summary=risk, privilege=privilege,
            )
        except Exception as e:
            return BlastRadiusResult(
                is_active=None, check_performed=True, check_error=str(e),
                risk_summary="Could not verify token. Treat as active.",
                remediation="Manually revoke at api.slack.com/apps.",
            )
