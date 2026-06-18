import httpx
from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class OpenAIChecker(BaseChecker):

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            headers = {"Authorization": f"Bearer {secret_value}"}
            resp = httpx.get(
                "https://api.openai.com/v1/models",
                headers=headers,
                timeout=self.TIMEOUT,
            )

            if resp.status_code == 401:
                return BlastRadiusResult(
                    is_active=False,
                    check_performed=True,
                    risk_summary="OpenAI key is invalid or revoked.",
                    remediation="Remove from git history. No further action needed if already revoked.",
                )

            models = resp.json().get("data", [])
            model_ids = [m["id"] for m in models[:5]]

            return BlastRadiusResult(
                is_active=True,
                check_performed=True,
                permissions=["API access to all models"],
                resources=model_ids,
                risk_summary=(
                    "ACTIVE OpenAI API key. Anyone with this key can make API calls "
                    "billed to your account, including GPT-4 and image generation."
                ),
                remediation=(
                    "1. Go to platform.openai.com/api-keys\n"
                    "2. Revoke this key immediately\n"
                    "3. Check your usage dashboard for unauthorized charges\n"
                    "4. Remove from git history with: git filter-repo"
                ),
            )

        except Exception as e:
            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=str(e),
                risk_summary="Could not verify key. Treat as active.",
                remediation="Manually revoke at platform.openai.com/api-keys.",
            )
