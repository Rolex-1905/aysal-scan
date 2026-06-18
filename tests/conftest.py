"""
Shared pytest fixtures for aysal-scan tests.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def write_file(tmp_path):
    """Write a named file into tmp_path and return its Path."""
    def _write(name: str, content: str) -> Path:
        p = tmp_path / name
        p.write_text(content, encoding="utf-8")
        return p
    return _write


# ---------------------------------------------------------------------------
# Fake secret content fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def aws_key_content():
    return (
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )

@pytest.fixture
def github_token_content():
    return "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012\n"

@pytest.fixture
def stripe_key_content():
    return "STRIPE_SECRET=" + "sk" + "_live_" + "a"*24 + "\n"

@pytest.fixture
def openai_key_content():
    return "OPENAI_KEY=sk-aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuV\n"

@pytest.fixture
def database_url_content():
    return "DATABASE_URL=postgres://admin:pass123@db.example.com/prod\n"

@pytest.fixture
def private_key_content():
    return "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"

@pytest.fixture
def gcp_service_account_content():
    return json.dumps({
        "type": "service_account",
        "project_id": "my-test-project",
        "private_key_id": "abc123",
        "client_email": "sa@my-test-project.iam.gserviceaccount.com",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----\n",
    }, indent=2)

@pytest.fixture
def clean_content():
    return "print('Hello, world!')\nx = 42\n"


# ---------------------------------------------------------------------------
# Fake git repo fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_git_repo(tmp_path):
    """
    Creates a minimal git repo in tmp_path with one commit.
    Returns the repo Path.
    """
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@aysal-scan.local"],
        cwd=tmp_path, check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Aysal-Scan Test"],
        cwd=tmp_path, check=True, capture_output=True,
    )

    # Initial clean commit
    readme = tmp_path / "README.md"
    readme.write_text("# Test repo\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=tmp_path, check=True, capture_output=True,
    )
    return tmp_path


@pytest.fixture
def fake_git_repo_with_secret(fake_git_repo):
    """
    Extends fake_git_repo with a second commit that leaks a Stripe key.
    Returns the repo Path.
    """
    secret_file = fake_git_repo / "config.env"
    secret_file.write_text(
        "STRIPE_SECRET=" + "sk" + "_live_" + "a"*24 + "\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "."], cwd=fake_git_repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Add config (oops)"],
        cwd=fake_git_repo, check=True, capture_output=True,
    )
    return fake_git_repo


# ---------------------------------------------------------------------------
# Mock HTTP response helper
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_http_response():
    """
    Factory fixture — returns a callable that builds a MagicMock HTTP response.
    Usage: resp = mock_http_response(200, {"login": "testuser"}, {"X-OAuth-Scopes": "repo"})
    """
    def _make(status: int, body: dict | None = None, headers: dict | None = None):
        resp = MagicMock()
        resp.status_code = status
        resp.json.return_value = body or {}
        resp.headers = headers or {}
        return resp
    return _make
