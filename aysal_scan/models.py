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


class SecretType(str, Enum):
    AWS_ACCESS_KEY = "AWS Access Key"
    GCP_SERVICE_ACCOUNT = "GCP Service Account"
    AZURE_CLIENT_SECRET = "Azure Client Secret"
    GITHUB_TOKEN = "GitHub Token"
    OPENAI_KEY = "OpenAI API Key"
    STRIPE_SECRET = "Stripe Secret Key"
    STRIPE_PUBLISHABLE = "Stripe Publishable Key"
    STRIPE_TEST_SECRET = "Stripe Test Secret Key"
    STRIPE_TEST_PUBLISHABLE = "Stripe Test Publishable Key"
    TWILIO = "Twilio Account SID"
    SENDGRID = "SendGrid API Key"
    SLACK_BOT = "Slack Bot Token"
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


class BlastRadiusResult(BaseModel):
    is_active: Optional[bool] = None
    check_performed: bool = False
    check_error: Optional[str] = None
    permissions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    account_info: Optional[str] = None
    risk_summary: str = ""
    remediation: str = ""


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