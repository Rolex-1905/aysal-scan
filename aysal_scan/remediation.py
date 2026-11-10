"""Provider-specific revoke/rotate guidance shown with every finding."""
from __future__ import annotations

from aysal_scan.models import SecretType

_REVOKE: dict[SecretType, str] = {
    SecretType.AWS_ACCESS_KEY: "AWS Console > IAM > Users > Security credentials > deactivate and delete the access key, then create a new one.",
    SecretType.GCP_SERVICE_ACCOUNT: "Google Cloud Console > IAM & Admin > Service Accounts > Keys > delete the key (https://console.cloud.google.com/iam-admin/serviceaccounts).",
    SecretType.AZURE_CLIENT_SECRET: "Azure Portal > Microsoft Entra ID > App registrations > Certificates & secrets > delete the secret and issue a new one.",
    SecretType.GITHUB_TOKEN: "GitHub > Settings > Developer settings > Personal access tokens (https://github.com/settings/tokens) > Delete.",
    SecretType.GITLAB_TOKEN: "GitLab > User settings > Access tokens (https://gitlab.com/-/user_settings/personal_access_tokens) > Revoke.",
    SecretType.OPENAI_KEY: "OpenAI dashboard > API keys (https://platform.openai.com/api-keys) > Revoke the key.",
    SecretType.ANTHROPIC_KEY: "Anthropic Console > API keys (https://console.anthropic.com/settings/keys) > delete the key.",
    SecretType.HUGGINGFACE_TOKEN: "Hugging Face > Settings > Access Tokens (https://huggingface.co/settings/tokens) > Invalidate and refresh.",
    SecretType.DIGITALOCEAN_TOKEN: "DigitalOcean > API > Tokens (https://cloud.digitalocean.com/account/api/tokens) > Delete.",
    SecretType.DOCKERHUB_TOKEN: "Docker Hub > Account settings > Personal access tokens > Delete.",
    SecretType.STRIPE_SECRET: "Stripe Dashboard > Developers > API keys > Roll key (https://dashboard.stripe.com/apikeys). Review recent API activity.",
    SecretType.STRIPE_RESTRICTED: "Stripe Dashboard > Developers > API keys > Roll the restricted key.",
    SecretType.STRIPE_TEST_SECRET: "Stripe Dashboard (test mode) > Developers > API keys > Roll key. Test keys cannot move real money.",
    SecretType.SENDGRID: "SendGrid > Settings > API Keys (https://app.sendgrid.com/settings/api_keys) > Delete.",
    SecretType.SLACK_BOT: "Slack API > Your Apps > OAuth & Permissions > Revoke tokens / reinstall the app.",
    SecretType.SLACK_TOKEN: "Slack API > Your Apps > OAuth & Permissions > Revoke the token.",
    SecretType.SLACK_WEBHOOK: "Slack API > Your Apps > Incoming Webhooks > remove the webhook URL.",
    SecretType.TWILIO: "Twilio Console > Account > API keys & tokens > rotate the Auth Token.",
    SecretType.NPM_TOKEN: "npm > Access Tokens (https://www.npmjs.com/settings/~/tokens) > Delete. Audit recently published versions.",
    SecretType.PYPI_TOKEN: "PyPI > Account settings > API tokens (https://pypi.org/manage/account/) > Remove the token. Audit recent releases.",
    SecretType.HEROKU: "Heroku > Account settings > Applications > Reveal/Regenerate API key, or `heroku authorizations:revoke`.",
    SecretType.GOOGLE_API: "Google Cloud Console > APIs & Services > Credentials > delete or regenerate the key, and add API/referrer restrictions.",
    SecretType.GOOGLE_OAUTH_SECRET: "Google Cloud Console > APIs & Services > Credentials > OAuth client > reset the client secret.",
    SecretType.SHOPIFY_TOKEN: "Shopify admin > Apps > the app > API credentials > rotate the access token.",
    SecretType.TELEGRAM_BOT: "Telegram @BotFather > /revoke to issue a new bot token.",
    SecretType.DATABRICKS_TOKEN: "Databricks > User settings > Developer > Access tokens > Revoke.",
    SecretType.POSTMAN_KEY: "Postman > Settings > API keys > Revoke.",
    SecretType.LINEAR_KEY: "Linear > Settings > API > revoke the personal API key.",
    SecretType.NOTION_TOKEN: "Notion > Settings > Connections > rotate or delete the integration secret.",
    SecretType.PLANETSCALE_TOKEN: "PlanetScale > Settings > Service tokens / passwords > delete and recreate.",
    SecretType.SUPABASE_TOKEN: "Supabase > Account > Access Tokens > Revoke.",
    SecretType.PRIVATE_KEY: "Generate a new key pair, remove the old public key from every server/service that trusts it (authorized_keys, cloud consoles, CI), then retire this key.",
    SecretType.AGE_SECRET_KEY: "Generate a new age identity, re-encrypt affected files to the new recipient, retire this key.",
    SecretType.DATABASE_URL: "Change the database user's password (or drop the user), then update the connection string in your secrets manager. Review connection logs.",
    SecretType.JWT: "Invalidate the token / rotate the signing secret if the token is still valid; shorten token lifetimes.",
    SecretType.STRIPE_PUBLISHABLE: "Publishable keys are designed to be public; no action is normally required.",
    SecretType.STRIPE_TEST_PUBLISHABLE: "Publishable test keys are not sensitive; no action required.",
    SecretType.HIGH_ENTROPY: "Identify what this string is. If it is a credential, revoke it at the issuing service.",
    SecretType.GENERIC: "Change this password/secret wherever it is used and move it to a secrets manager.",
    SecretType.CUSTOM: "Revoke or rotate this credential at its issuing service.",
}

COMMON_CLEANUP = (
    "Then remove it from git history (git filter-repo or BFG), force-push, and ask collaborators "
    "to re-clone. Store future secrets in a secrets manager (AWS Secrets Manager, Vault, GitHub Secrets)."
)


def remediation_for(secret_type: SecretType) -> str:
    """Numbered, provider-specific remediation text."""
    revoke = _REVOKE.get(secret_type, "Revoke or rotate this credential at the service that issued it.")
    return f"1. {revoke}\n2. {COMMON_CLEANUP}"
