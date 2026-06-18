from aysal_scan.scanner.file_scanner import scan_content
from aysal_scan.models import SecretType

def test_detects_aws_key():
    content = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    findings, _ = scan_content(content, "test.env")
    assert any(f.secret_type == SecretType.AWS_ACCESS_KEY for f in findings)


def test_detects_github_token():
    content = "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012"
    findings, _ = scan_content(content, "test.env")
    assert any(f.secret_type == SecretType.GITHUB_TOKEN for f in findings)


def test_detects_openai_key():
    content = "OPENAI_KEY=sk-aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuV"
    findings, _ = scan_content(content, "test.py")
    assert any(f.secret_type == SecretType.OPENAI_KEY for f in findings)


def test_detects_stripe_secret():
    key = "sk_live_" + "a" * 24
    content = f"STRIPE_SECRET={key}"
    findings, _ = scan_content(content, "config.py")
    assert any(f.secret_type == SecretType.STRIPE_SECRET for f in findings)


def test_detects_database_url():
    content = "DATABASE_URL=postgres://admin:pass123@db.example.com/prod"
    findings, _ = scan_content(content, ".env")
    assert any(f.secret_type == SecretType.DATABASE_URL for f in findings)


def test_masked_value_hides_secret():
    content = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    findings, _ = scan_content(content, "test.env")
    aws = next(f for f in findings if f.secret_type == SecretType.AWS_ACCESS_KEY)
    assert "AKIAIOSFODNN7EXAMPLE" not in aws.masked_value
    assert "****" in aws.masked_value


def test_no_false_positive_in_clean_file():
    content = "print('Hello, world!')\nx = 42\n"
    findings, _ = scan_content(content, "clean.py")
    regex_findings = [
        f for f in findings
        if f.secret_type != SecretType.HIGH_ENTROPY
    ]
    assert len(regex_findings) == 0

def test_detects_gcp_service_account():
    content = '{"type": "service_account", "project_id": "my-project", "client_email": "sa@my-project.iam.gserviceaccount.com"}'
    findings, _ = scan_content(content, "credentials.json")
    assert any(f.secret_type == SecretType.GCP_SERVICE_ACCOUNT for f in findings)

def test_detects_stripe_test_secret():
    key = "sk_test_" + "a" * 24
    content = f"STRIPE_KEY={key}"
    findings, _ = scan_content(content, "config.py")
    assert any(f.secret_type == SecretType.STRIPE_TEST_SECRET for f in findings)


def test_detects_stripe_test_publishable():
    content = "STRIPE_PK=pk_test_aBcDeFgHiJkLmNoPqRsTuVwXy"
    findings, _ = scan_content(content, "config.py")
    assert any(f.secret_type == SecretType.STRIPE_TEST_PUBLISHABLE for f in findings)

def test_detects_azure_client_secret():
    content = "AZURE_CLIENT_SECRET=aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgH"
    findings, _ = scan_content(content, ".env")
    assert any(f.secret_type == SecretType.AZURE_CLIENT_SECRET for f in findings)

def test_azure_generic_placeholder_ignored():
    content = "AZURE_CLIENT_SECRET=changeme"
    findings, _ = scan_content(content, ".env")
    azure = [f for f in findings if f.secret_type == SecretType.AZURE_CLIENT_SECRET]
    assert azure == []