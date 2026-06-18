"""
Blast radius checker tests — all HTTP calls are mocked so no real API
credentials or network access are required.
"""
from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from aysal_scan.blast_radius.github import GitHubChecker
from aysal_scan.blast_radius.openai_checker import OpenAIChecker
from aysal_scan.blast_radius.npm import NpmChecker
from aysal_scan.blast_radius.stripe import StripeChecker
from aysal_scan.blast_radius.gcp import GCPServiceAccountChecker


class TestGitHubChecker:
    def test_inactive_key(self, mock_http_response):
        with patch("httpx.get", return_value=mock_http_response(401)):
            result = GitHubChecker().check("ghp_faketoken")
        assert result.is_active is False
        assert result.check_performed is True

    def test_active_key_with_scopes(self, mock_http_response):
        user_mock = mock_http_response(
            200,
            {"login": "testuser"},
            {"X-OAuth-Scopes": "repo, read:org, delete_repo"},
        )
        repos_mock = mock_http_response(200, [])
        with patch("httpx.get", side_effect=[user_mock, repos_mock]):
            result = GitHubChecker().check("ghp_faketoken")
        assert result.is_active is True
        assert "repo" in result.permissions
        assert "read:org" in result.permissions
        assert "testuser" in result.account_info

    def test_delete_repo_scope_flagged(self, mock_http_response):
        user_mock = mock_http_response(
            200,
            {"login": "testuser"},
            {"X-OAuth-Scopes": "repo, delete_repo"},
        )
        repos_mock = mock_http_response(200, [])
        with patch("httpx.get", side_effect=[user_mock, repos_mock]):
            result = GitHubChecker().check("ghp_faketoken")
        assert result.is_active is True
        assert "delete_repo" in result.permissions
        assert "CAN DELETE" in result.risk_summary

    def test_repos_call_network_error_still_returns_active(self, mock_http_response):
        """Second HTTP call failing should not cause the whole check to fail."""
        user_mock = mock_http_response(
            200,
            {"login": "testuser"},
            {"X-OAuth-Scopes": "repo"},
        )
        with patch("httpx.get", side_effect=[user_mock, Exception("timeout")]):
            result = GitHubChecker().check("ghp_faketoken")
        assert result.is_active is True
        assert result.check_performed is True

    def test_network_error_degrades_gracefully(self):
        with patch("httpx.get", side_effect=Exception("Connection refused")):
            result = GitHubChecker().check("ghp_faketoken")
        assert result.is_active is None
        assert result.check_error is not None
        assert result.check_performed is True

    def test_unexpected_status_returns_result(self, mock_http_response):
        with patch("httpx.get", return_value=mock_http_response(500, {})):
            result = GitHubChecker().check("ghp_faketoken")
        assert result.check_performed is True


class TestOpenAIChecker:
    def test_inactive_key(self, mock_http_response):
        with patch("httpx.get", return_value=mock_http_response(401)):
            result = OpenAIChecker().check("sk-fakekey")
        assert result.is_active is False

    def test_active_key(self, mock_http_response):
        with patch("httpx.get", return_value=mock_http_response(200, {"data": []})):
            result = OpenAIChecker().check("sk-fakekey")
        assert result.is_active is True

    def test_network_timeout(self):
        with patch("httpx.get", side_effect=httpx.TimeoutException("timeout")):
            result = OpenAIChecker().check("sk-fakekey")
        assert result.check_error is not None
        assert result.check_performed is True


class TestNpmChecker:
    def test_inactive_token(self, mock_http_response):
        with patch("httpx.get", return_value=mock_http_response(401)):
            result = NpmChecker().check("npm_faketoken")
        assert result.is_active is False

    def test_active_token(self, mock_http_response):
        with patch("httpx.get", return_value=mock_http_response(200, {"username": "npmuser"})):
            result = NpmChecker().check("npm_faketoken")
        assert result.is_active is True
        assert "npmuser" in result.account_info

    def test_network_error_degrades_gracefully(self):
        with patch("httpx.get", side_effect=Exception("Connection refused")):
            result = NpmChecker().check("npm_faketoken")
        assert result.is_active is None
        assert result.check_performed is True


class TestStripeChecker:
    def test_inactive_key(self, mock_http_response):
        with patch("httpx.get", return_value=mock_http_response(401)):
            result = StripeChecker().check("stripe_live_FAKE")
        assert result.is_active is False

    def test_active_key(self, mock_http_response):
        body = {"available": [{"amount": 10000, "currency": "usd"}]}
        with patch("httpx.get", return_value=mock_http_response(200, body)):
            result = StripeChecker().check("stripe_live_FAKE")
        assert result.is_active is True

    def test_network_error_degrades_gracefully(self):
        with patch("httpx.get", side_effect=Exception("Connection refused")):
            result = StripeChecker().check("stripe_live_FAKE")
        assert result.is_active is None
        assert result.check_performed is True


class TestGCPServiceAccountChecker:
    def test_valid_service_account_json(self, gcp_service_account_content):
        result = GCPServiceAccountChecker().check(gcp_service_account_content)
        assert result.is_active is True
        assert result.check_performed is True
        assert "my-test-project" in result.account_info
        assert "sa@my-test-project.iam.gserviceaccount.com" in result.account_info

    def test_malformed_json_degrades_gracefully(self):
        result = GCPServiceAccountChecker().check('{"type": "service_account", broken json')
        assert result.check_performed is True
        assert result.check_error is not None

    def test_missing_json_blob(self):
        result = GCPServiceAccountChecker().check("no json here at all")
        assert result.check_performed is False

    def test_remediation_present(self, gcp_service_account_content):
        result = GCPServiceAccountChecker().check(gcp_service_account_content)
        assert "console.cloud.google.com" in result.remediation
        assert "git filter-repo" in result.remediation
