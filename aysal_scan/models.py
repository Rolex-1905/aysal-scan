from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """0 = most severe. Use for sorting and comparisons."""
        return _SEVERITY_ORDER.index(self)

    def at_least(self, other: "Severity") -> bool:
        """True if self is as severe as, or more severe than, other."""
        return self.rank <= other.rank

    def lowered(self, steps: int = 1) -> "Severity":
        return _SEVERITY_ORDER[min(self.rank + steps, len(_SEVERITY_ORDER) - 1)]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(value.strip().upper())
        except ValueError as exc:
            raise ValueError(
                f"Invalid severity {value!r}. Choose one of: "
                + ", ".join(s.value for s in _SEVERITY_ORDER)
            ) from exc


_SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
]


class SecretType(str, Enum):
    AWS_ACCESS_KEY = "AWS Access Key"
    GCP_SERVICE_ACCOUNT = "GCP Service Account"
    AZURE_CLIENT_SECRET = "Azure Client Secret"
    GITHUB_TOKEN = "GitHub Token"
    OPENAI_KEY = "OpenAI API Key"
    ANTHROPIC_KEY = "Anthropic API Key"
    HUGGINGFACE_TOKEN = "Hugging Face Token"
    GITLAB_TOKEN = "GitLab Token"
    DIGITALOCEAN_TOKEN = "DigitalOcean Token"
    DOCKERHUB_TOKEN = "Docker Hub Token"
    SHOPIFY_TOKEN = "Shopify Token"
    GOOGLE_OAUTH_SECRET = "Google OAuth Client Secret"
    AGE_SECRET_KEY = "age Secret Key"
    TELEGRAM_BOT = "Telegram Bot Token"
    DATABRICKS_TOKEN = "Databricks Token"
    POSTMAN_KEY = "Postman API Key"
    LINEAR_KEY = "Linear API Key"
    NOTION_TOKEN = "Notion Token"
    PLANETSCALE_TOKEN = "PlanetScale Token"
    SUPABASE_TOKEN = "Supabase Access Token"
    STRIPE_SECRET = "Stripe Secret Key"
    STRIPE_RESTRICTED = "Stripe Restricted Key"
    STRIPE_PUBLISHABLE = "Stripe Publishable Key"
    STRIPE_TEST_SECRET = "Stripe Test Secret Key"
    STRIPE_TEST_PUBLISHABLE = "Stripe Test Publishable Key"
    TWILIO = "Twilio Account SID"
    SENDGRID = "SendGrid API Key"
    SLACK_BOT = "Slack Bot Token"
    SLACK_TOKEN = "Slack Token"
    SLACK_WEBHOOK = "Slack Webhook URL"
    GOOGLE_API = "Google API Key"
    NPM_TOKEN = "npm Token"
    JWT = "JWT Token"
    PRIVATE_KEY = "Private Key"
    DATABASE_URL = "Database URL"
    HEROKU = "Heroku API Key"
    PYPI_TOKEN = "PyPI Token"
    HIGH_ENTROPY = "High Entropy String"
    GENERIC = "Generic Secret"
    CUSTOM = "Custom Rule"


class BlastRadiusResult(BaseModel):
    is_active: Optional[bool] = None
    check_performed: bool = False
    check_error: Optional[str] = None
    permissions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    account_info: Optional[str] = None
    risk_summary: str = ""
    remediation: str = ""
    # "admin" | "write" | "read" | None (unknown). Set by checkers; drives risk score.
    privilege: Optional[str] = None
    # A checker may recommend a different severity (e.g. an expired JWT is LOW).
    suggested_severity: Optional[Severity] = None


class Location(BaseModel):
    """A single occurrence of a secret (file + line + optional commit)."""
    file_path: str
    line_number: Optional[int] = None
    commit_hash: Optional[str] = None
    commit_date: Optional[str] = None


class Finding(BaseModel):
    id: str
    secret_type: SecretType
    severity: Severity
    file_path: str
    line_number: Optional[int] = None
    commit_hash: Optional[str] = None
    commit_date: Optional[str] = None
    masked_value: str
    blast_radius: Optional[BlastRadiusResult] = None
    locations: list[Location] = Field(default_factory=list)
    # v2 additions (all optional so old JSON/consumers keep working)
    rule_id: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    risk_score: Optional[int] = None
    risk_factors: list[str] = Field(default_factory=list)
    in_head: Optional[bool] = None


class ScanReport(BaseModel):
    tool_version: str
    scan_target: str
    scan_time: str
    files_scanned: int
    commits_scanned: int
    findings: list[Finding]
    total_critical: int
    total_high: int
    total_medium: int
    total_low: int
    total_info: int
    passed: bool
    # v2 additions
    schema_version: str = "2"
    scan_root: Optional[str] = None
    files_skipped: int = 0
    warnings: list[str] = Field(default_factory=list)
