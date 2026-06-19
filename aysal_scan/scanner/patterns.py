import re
from dataclasses import dataclass, field
from aysal_scan.models import SecretType, Severity


@dataclass
class SecretPattern:
    secret_type: SecretType
    pattern: re.Pattern
    default_severity: Severity
    requires_context: bool = False
    context_keywords: list[str] = field(default_factory=list)
    value_group: int = 0  # which capture group holds the secret (0 = full match)


# Dummy values the generic password regex should skip to avoid false positives
GENERIC_DUMMY_VALUES: frozenset[str] = frozenset({
    "changeme", "password", "password123", "password1", "secret", "example",
    "test", "placeholder", "your_api_key", "your_secret", "your_password",
    "xxxxxxxx", "aaaaaaaa", "12345678", "abcdefgh", "admin", "admin123",
    "letmein", "qwerty", "qwerty123", "dummy", "replace_me", "insert_here",
    "enter_here", "my_password", "my_secret", "none", "null", "undefined",
    "todo", "fixme", "xxx", "abc123", "foobar", "enter_password",
    "enter_secret", "put_here", "goes_here", "add_here", "<secret>",
    "<password>", "<api_key>", "supersecret", "topsecret",
    "localhost", "development", "production", "staging", "local",
    "default", "username", "root", "guest", "demo", "sandbox",
    "my-database-name", "mydb", "myapp", "true", "false", "debug",
})


PATTERNS: list[SecretPattern] = [
    SecretPattern(
        secret_type=SecretType.AWS_ACCESS_KEY,
        pattern=re.compile(r'AKIA[0-9A-Z]{16}'),
        default_severity=Severity.CRITICAL,
    ),
    SecretPattern(
        secret_type=SecretType.GITHUB_TOKEN,
        pattern=re.compile(
            r'ghp_[a-zA-Z0-9]{36}'
            r'|gho_[a-zA-Z0-9]{36}'
            r'|github_pat_[a-zA-Z0-9_]{82}'
        ),
        default_severity=Severity.HIGH,
    ),
    SecretPattern(
        secret_type=SecretType.OPENAI_KEY,
        pattern=re.compile(r'sk-(?:proj-|svcacct-)?[a-zA-Z0-9_-]{48,}'),
        default_severity=Severity.HIGH,
        requires_context=False,
    ),
    SecretPattern(
        secret_type=SecretType.STRIPE_SECRET,
        pattern=re.compile(r'sk_live_[a-zA-Z0-9]{24,}'),
        default_severity=Severity.CRITICAL,
    ),
    SecretPattern(
        secret_type=SecretType.STRIPE_PUBLISHABLE,
        pattern=re.compile(r'pk_live_[a-zA-Z0-9]{24,}'),
        default_severity=Severity.LOW,
    ),
    SecretPattern(
        secret_type=SecretType.STRIPE_TEST_SECRET,
        pattern=re.compile(r'sk_test_[a-zA-Z0-9]{24,}'),
        default_severity=Severity.LOW,
    ),
    SecretPattern(
        secret_type=SecretType.STRIPE_TEST_PUBLISHABLE,
        pattern=re.compile(r'pk_test_[a-zA-Z0-9]{24,}'),
        default_severity=Severity.INFO,
    ),
    SecretPattern(
        secret_type=SecretType.SENDGRID,
        pattern=re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),
        default_severity=Severity.HIGH,
    ),
    SecretPattern(
        secret_type=SecretType.SLACK_BOT,
        pattern=re.compile(r'xoxb-[0-9]{6,14}-[0-9]{6,14}-[a-zA-Z0-9]{16,32}'),
        default_severity=Severity.HIGH,
    ),
    SecretPattern(
        secret_type=SecretType.SLACK_WEBHOOK,
        pattern=re.compile(
            r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'
        ),
        default_severity=Severity.HIGH,
    ),
    SecretPattern(
        secret_type=SecretType.GOOGLE_API,
        pattern=re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        default_severity=Severity.HIGH,
    ),
    SecretPattern(
        secret_type=SecretType.NPM_TOKEN,
        pattern=re.compile(r'npm_[A-Za-z0-9]{36}'),
        default_severity=Severity.HIGH,
    ),
    SecretPattern(
        secret_type=SecretType.PYPI_TOKEN,
        pattern=re.compile(r'pypi-[A-Za-z0-9_-]{100,}'),
        default_severity=Severity.HIGH,
    ),
    SecretPattern(
        secret_type=SecretType.JWT,
        pattern=re.compile(
            r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
        ),
        default_severity=Severity.MEDIUM,
    ),
    SecretPattern(
        secret_type=SecretType.PRIVATE_KEY,
        pattern=re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        default_severity=Severity.CRITICAL,
    ),
    SecretPattern(
        secret_type=SecretType.DATABASE_URL,
        pattern=re.compile(
            r'(postgres|postgresql|mysql|mongodb|redis|mongodb\+srv)'
            r'://[^:]+:[^@\s]+@[^\s]+'
        ),
        default_severity=Severity.HIGH,
    ),
    SecretPattern(
        secret_type=SecretType.TWILIO,
        pattern=re.compile(r'AC[a-zA-Z0-9]{32}'),
        default_severity=Severity.HIGH,
        requires_context=True,
        context_keywords=["twilio", "TWILIO", "account_sid", "AccountSid"],
    ),
    SecretPattern(
        secret_type=SecretType.HEROKU,
        pattern=re.compile(
            r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}'
            r'-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        ),
        default_severity=Severity.HIGH,
        requires_context=True,
        context_keywords=[
            "heroku", "HEROKU", "HEROKU_API_KEY", "heroku_api_key",
            "api_key", "apikey", "API_KEY",
        ],
    ),
    # Generic password / secret assignments — allowlist checked in file_scanner.py
    SecretPattern(
        secret_type=SecretType.GENERIC,
        pattern=re.compile(
            r'(?i)(?:password|passwd|secret|api_key|apikey|api_secret)'
            r'\s*[:=]\s*["\']?([A-Za-z0-9!@#$%^&*()_+\-=]{8,})["\']?'
        ),
        default_severity=Severity.MEDIUM,
        value_group=1,
    ),
    SecretPattern(
        secret_type=SecretType.GCP_SERVICE_ACCOUNT,
        pattern=re.compile(
            r'"type"\s*:\s*"service_account"'
        ),
        default_severity=Severity.CRITICAL,
        requires_context=False,
    ),
    SecretPattern(
        secret_type=SecretType.AZURE_CLIENT_SECRET,
        pattern=re.compile(
            r'(?i)(?:AZURE_CLIENT_SECRET|client.secret|clientSecret)'
            r'\s*[:=]\s*["\']?([A-Za-z0-9\-._~]{32,})["\']?'
        ),
        default_severity=Severity.HIGH,
        requires_context=False,
        value_group=1,
    ),
]