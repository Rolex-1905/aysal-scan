"""Secret detection rules.

Design notes
------------
* Every rule with a distinctive prefix is anchored with look-arounds so that it
  cannot match in the middle of an unrelated word (e.g. ``disk-...`` must not
  look like an OpenAI ``sk-`` key).
* Rules for generic assignments (``password = ...``) run extra false-positive
  filters (placeholders, code references, entropy floor) declared on the rule.
* ``register_custom_patterns`` lets users add their own rules from a config
  file without touching this module.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

from aysal_scan.models import SecretType, Severity


@dataclass
class SecretPattern:
    secret_type: SecretType
    pattern: re.Pattern
    default_severity: Severity
    requires_context: bool = False
    context_keywords: list[str] = field(default_factory=list)
    value_group: int = 0           # which capture group holds the secret (0 = full match)
    rule_id: Optional[str] = None  # stable identifier shown in reports / SARIF
    check_dummy: bool = False      # apply placeholder + code-reference filters to the value
    min_entropy: float = 0.0       # reject values below this Shannon entropy (0 = off)
    validator: Optional[Callable[[str], bool]] = None  # return False to reject a match
    adjust_severity: Optional[Callable[[str, Severity], Severity]] = None


# ---------------------------------------------------------------------------
# Placeholder / code-reference filtering
# ---------------------------------------------------------------------------

GENERIC_DUMMY_VALUES: frozenset[str] = frozenset({
    "changeme", "changeit", "password", "password123", "password1", "secret", "example",
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
    "yourpassword", "your-password", "your-api-key", "your_token", "secretkey",
    "redacted", "hidden", "masked", "notasecret", "not-a-secret",
})

_PLACEHOLDER_PREFIXES = (
    "<", "$", "{{", "%", "your", "my_", "my-", "example", "xxxx", "****",
    "dummy", "fake", "sample", "replace", "changeme", "insert", "enter",
    "todo", "env(", "ENC[", "vault:", "ref+",
)

_DOTTED_IDENTIFIER = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")
_LETTERS_ONLY = re.compile(r"^[A-Za-z_]+$")
_ENV_VAR_NAME = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
_MASK_LIKE = re.compile(r"^[xX*#.\-_•]+$")


_PLACEHOLDER_WORD = re.compile(
    r"(?i)(?:^|[-_.])(?:your|my|example|dummy|fake|sample|placeholder|replace|insert)(?:[-_.]|$)"
    r"|[-_.](?:here|goes[-_]here|placeholder|example)$"
)


def is_placeholder_value(value: str) -> bool:
    """True for obvious dummy values: 'changeme', '<password>', 'xxxxxxxx', '${DB_PASS}'..."""
    v = value.strip().strip("'\"")
    low = v.lower()
    if low in GENERIC_DUMMY_VALUES:
        return True
    if low.startswith(tuple(p.lower() for p in _PLACEHOLDER_PREFIXES)):
        return True
    if len(set(low)) < 4:
        return True
    return bool(_MASK_LIKE.match(v) or _PLACEHOLDER_WORD.search(v))


def looks_like_code_reference(value: str) -> bool:
    """True when the 'value' is really an identifier/expression, not a literal secret.

    ``settings.SECRET_KEY``, ``process.env.TOKEN``, ``get_password`` and
    ``AZURE_CLIENT_SECRET`` are references to a secret, not the secret itself.
    """
    v = value.strip().strip("'\"")
    return bool(
        _DOTTED_IDENTIFIER.match(v) or _LETTERS_ONLY.match(v) or _ENV_VAR_NAME.match(v)
    )


# ---------------------------------------------------------------------------
# Per-rule validators / severity hooks
# ---------------------------------------------------------------------------

def _openai_ok(value: str) -> bool:
    """Real OpenAI keys are random mixed-case strings. Lowercase kebab-case slugs
    (``sk-encryption-configuration-...``) have no uppercase letters and are rejected."""
    return any(ch.isupper() for ch in value[3:])


_DB_URL_PARTS = re.compile(r"^[a-z0-9+]+://([^:@\s/]*):([^@\s]+)@([^\s/'\"?#]+)", re.IGNORECASE)
_LOCAL_DB_HOSTS = (
    "localhost", "127.0.0.1", "0.0.0.0", "[::1]", "host.docker.internal",
    "db", "database", "postgres", "postgresql", "mysql", "mariadb", "mongo",
    "mongodb", "redis", "rabbitmq", "example.com", "example.org",
)


def _db_url_ok(value: str) -> bool:
    m = _DB_URL_PARTS.match(value)
    if not m:
        return False
    _user, password, _host = m.groups()
    return not is_placeholder_value(password) and not re.search(r"[<>{}]|\$\{|\$\(", password)


def _db_url_severity(value: str, default: Severity) -> Severity:
    m = _DB_URL_PARTS.match(value)
    if not m:
        return default
    host = m.group(3).lower().split("@")[-1]
    hostname = re.sub(r":\d+$", "", host)
    if (
        hostname in _LOCAL_DB_HOSTS
        or hostname.endswith((".local", ".test", ".invalid", ".example"))
    ):
        return Severity.MEDIUM  # local / dev-looking host: real credentials, lower blast radius
    return default


# ---------------------------------------------------------------------------
# Built-in rules
# ---------------------------------------------------------------------------

_B = r"(?<![A-Za-z0-9_])"      # left boundary for token-like prefixes
_E = r"(?![A-Za-z0-9_])"       # right boundary


def _p(stype, regex, sev, rule_id, **kw) -> SecretPattern:
    return SecretPattern(
        secret_type=stype, pattern=re.compile(regex), default_severity=sev, rule_id=rule_id, **kw
    )


PATTERNS: list[SecretPattern] = [
    # --- Cloud ---------------------------------------------------------
    _p(SecretType.AWS_ACCESS_KEY, r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])",
       Severity.CRITICAL, "aws-access-key-id"),
    _p(SecretType.AWS_ACCESS_KEY, r"(?<![A-Z0-9])ASIA[0-9A-Z]{16}(?![A-Z0-9])",
       Severity.HIGH, "aws-temporary-access-key-id"),
    _p(SecretType.GCP_SERVICE_ACCOUNT, r'"type"\s*:\s*"service_account"',
       Severity.CRITICAL, "gcp-service-account"),
    _p(SecretType.AZURE_CLIENT_SECRET,
       r'(?i)(?:AZURE_CLIENT_SECRET|client[._-]?secret|clientSecret)'
       r'["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-._~]{32,})["\']?',
       Severity.HIGH, "azure-client-secret", value_group=1, check_dummy=True, min_entropy=3.3),
    _p(SecretType.GOOGLE_API, _B + r"AIza[0-9A-Za-z\-_]{35}" + _E,
       Severity.HIGH, "google-api-key"),
    _p(SecretType.GOOGLE_OAUTH_SECRET, _B + r"GOCSPX-[A-Za-z0-9_-]{28}" + _E,
       Severity.HIGH, "google-oauth-client-secret"),

    # --- Source control / CI / registries -------------------------------
    _p(SecretType.GITHUB_TOKEN,
       _B + r"(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82})" + _E,
       Severity.HIGH, "github-token"),
    _p(SecretType.GITLAB_TOKEN, _B + r"glpat-[A-Za-z0-9_-]{20,}" + _E,
       Severity.HIGH, "gitlab-personal-access-token"),
    _p(SecretType.NPM_TOKEN, _B + r"npm_[A-Za-z0-9]{36}" + _E, Severity.HIGH, "npm-token"),
    _p(SecretType.PYPI_TOKEN, _B + r"pypi-[A-Za-z0-9_-]{100,}", Severity.HIGH, "pypi-token"),
    _p(SecretType.DOCKERHUB_TOKEN, _B + r"dckr_pat_[A-Za-z0-9_-]{27,}", Severity.HIGH,
       "dockerhub-pat"),

    # --- AI / ML ----------------------------------------------------------
    _p(SecretType.ANTHROPIC_KEY,
       r"(?<![A-Za-z0-9_-])sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}",
       Severity.HIGH, "anthropic-api-key"),
    _p(SecretType.OPENAI_KEY,
       r"(?<![A-Za-z0-9_-])sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])",
       Severity.HIGH, "openai-api-key", validator=_openai_ok),
    _p(SecretType.HUGGINGFACE_TOKEN, _B + r"hf_[A-Za-z0-9]{34,}" + _E, Severity.HIGH,
       "huggingface-token"),

    # --- Payments / comms / SaaS -----------------------------------------
    _p(SecretType.STRIPE_SECRET, _B + r"sk_live_[a-zA-Z0-9]{24,}", Severity.CRITICAL,
       "stripe-live-secret-key"),
    _p(SecretType.STRIPE_RESTRICTED, _B + r"rk_live_[a-zA-Z0-9]{24,}", Severity.HIGH,
       "stripe-live-restricted-key"),
    _p(SecretType.STRIPE_PUBLISHABLE, _B + r"pk_live_[a-zA-Z0-9]{24,}", Severity.LOW,
       "stripe-live-publishable-key"),
    _p(SecretType.STRIPE_TEST_SECRET, _B + r"sk_test_[a-zA-Z0-9]{24,}", Severity.LOW,
       "stripe-test-secret-key"),
    _p(SecretType.STRIPE_TEST_PUBLISHABLE, _B + r"pk_test_[a-zA-Z0-9]{24,}", Severity.INFO,
       "stripe-test-publishable-key"),
    _p(SecretType.SENDGRID, _B + r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", Severity.HIGH,
       "sendgrid-api-key"),
    _p(SecretType.SLACK_BOT, _B + r"xoxb-[0-9]{6,14}-[0-9]{6,14}-[a-zA-Z0-9]{16,32}", Severity.HIGH,
       "slack-bot-token"),
    _p(SecretType.SLACK_TOKEN, _B + r"xox[pars]-[0-9A-Za-z-]{20,}", Severity.HIGH,
       "slack-token"),
    _p(SecretType.SLACK_WEBHOOK,
       r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
       Severity.MEDIUM, "slack-webhook-url"),
    _p(SecretType.TWILIO, _B + r"AC[a-zA-Z0-9]{32}" + _E, Severity.HIGH, "twilio-account-sid",
       requires_context=True,
       context_keywords=["twilio", "TWILIO", "account_sid", "AccountSid"]),
    _p(SecretType.SHOPIFY_TOKEN, _B + r"shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}" + _E, Severity.HIGH,
       "shopify-token"),
    _p(SecretType.TELEGRAM_BOT, _B + r"[0-9]{8,10}:AA[A-Za-z0-9_-]{33}" + _E, Severity.HIGH,
       "telegram-bot-token"),
    _p(SecretType.DIGITALOCEAN_TOKEN, _B + r"dop_v1_[a-f0-9]{64}" + _E, Severity.HIGH,
       "digitalocean-token"),
    _p(SecretType.DATABRICKS_TOKEN, _B + r"dapi[a-f0-9]{32}" + _E, Severity.HIGH,
       "databricks-token"),
    _p(SecretType.POSTMAN_KEY, _B + r"PMAK-[a-f0-9]{24}-[a-f0-9]{34}" + _E, Severity.HIGH,
       "postman-api-key"),
    _p(SecretType.LINEAR_KEY, _B + r"lin_api_[A-Za-z0-9]{40}" + _E, Severity.HIGH,
       "linear-api-key"),
    _p(SecretType.NOTION_TOKEN, _B + r"ntn_[A-Za-z0-9]{40,}" + _E, Severity.HIGH,
       "notion-token"),
    _p(SecretType.PLANETSCALE_TOKEN, _B + r"pscale_(?:tkn|pw|oauth)_[A-Za-z0-9_.-]{32,}", Severity.HIGH,
       "planetscale-token"),
    _p(SecretType.SUPABASE_TOKEN, _B + r"sbp_[a-f0-9]{40}" + _E, Severity.HIGH,
       "supabase-access-token"),
    _p(SecretType.HEROKU, _B + r"HRKU-[A-Za-z0-9_-]{30,}", Severity.HIGH, "heroku-api-key"),
    _p(SecretType.HEROKU,
       r"(?<![0-9a-fA-F-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9a-fA-F-])",
       Severity.HIGH, "heroku-api-key-legacy", requires_context=True,
       context_keywords=["heroku", "HEROKU", "HEROKU_API_KEY", "heroku_api_key"]),

    # --- Cryptographic material / connection strings / tokens ------------
    _p(SecretType.PRIVATE_KEY,
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----",
       Severity.CRITICAL, "private-key"),
    _p(SecretType.AGE_SECRET_KEY, _B + r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
       Severity.CRITICAL, "age-secret-key"),
    _p(SecretType.DATABASE_URL,
       r"(?i)(?<![A-Za-z0-9+])(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)"
       r"://[^:@\s/]*:[^@\s]+@[^\s'\"]+",
       Severity.HIGH, "database-url", validator=_db_url_ok, adjust_severity=_db_url_severity),
    _p(SecretType.JWT,
       r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
       Severity.MEDIUM, "jwt"),

    # --- Generic assignments (heuristic; filtered for placeholders) ------
    _p(SecretType.GENERIC,
       r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|api[_-]?secret|access[_-]?token"
       r"|auth[_-]?token|private[_-]?key|token|totp|signing[_-]?key|encryption[_-]?key)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9!@#$%^&*_+\-=./~:]{8,})[\"']?",
       Severity.MEDIUM, "generic-secret-assignment", value_group=1, check_dummy=True,
       min_entropy=2.8),
]

# ---------------------------------------------------------------------------
# User-defined rules (from config)
# ---------------------------------------------------------------------------

_custom_lock = threading.Lock()
_CUSTOM_PATTERNS: list[SecretPattern] = []


def register_custom_patterns(patterns: list[SecretPattern]) -> None:
    with _custom_lock:
        _CUSTOM_PATTERNS.clear()
        _CUSTOM_PATTERNS.extend(patterns)


def get_all_patterns() -> list[SecretPattern]:
    with _custom_lock:
        return PATTERNS + list(_CUSTOM_PATTERNS)
