"""Success-path and edge-case tests for the verifiers added or rewritten in 1.1."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from aysal_scan.blast_radius.anthropic_checker import AnthropicChecker
from aysal_scan.blast_radius.digitalocean import DigitalOceanChecker
from aysal_scan.blast_radius.gitlab import GitLabChecker
from aysal_scan.blast_radius.huggingface import HuggingFaceChecker
from aysal_scan.blast_radius.sendgrid import SendGridChecker
from aysal_scan.blast_radius.slack import SlackChecker
from aysal_scan.blast_radius.slack_webhook import SlackWebhookChecker
from aysal_scan.blast_radius.stripe import StripeChecker


def resp(status=200, body=None, headers=None, text=""):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = body if body is not None else {}
    r.headers = headers or {}
    r.text = text
    return r


# ---------------------------------------------------------------- Anthropic
def test_anthropic_active_key_lists_models_and_sends_the_right_headers():
    seen = {}

    def fake_get(url, **kw):
        seen.update(url=url, headers=kw["headers"])
        return resp(200, {"data": [{"id": "claude-a"}, {"id": "claude-b"}]})

    with patch("httpx.get", side_effect=fake_get):
        r = AnthropicChecker().check("sk-ant-api03-xxxx")
    assert r.is_active is True and r.privilege == "write" and r.resources == ["claude-a", "claude-b"]
    assert seen["url"] == "https://api.anthropic.com/v1/models"
    assert seen["headers"]["x-api-key"] == "sk-ant-api03-xxxx" and "anthropic-version" in seen["headers"]
    assert "Authorization" not in seen["headers"]


def test_anthropic_network_error_is_unverified():
    with patch("httpx.get", side_effect=RuntimeError("boom")):
        r = AnthropicChecker().check("sk-ant-x")
    assert r.is_active is None and "boom" in r.check_error


# ------------------------------------------------------------- Hugging Face
@pytest.mark.parametrize("role,privilege", [("write", "write"), ("read", "read"), ("fineGrained", None)])
def test_huggingface_role_maps_to_privilege(role, privilege):
    body = {"name": "alice", "auth": {"accessToken": {"role": role}}}
    with patch("httpx.get", return_value=resp(200, body)):
        r = HuggingFaceChecker().check("hf_x")
    assert r.is_active is True and r.privilege == privilege and "alice" in r.account_info


def test_huggingface_write_token_warns_about_models():
    body = {"name": "alice", "auth": {"accessToken": {"role": "write"}}}
    with patch("httpx.get", return_value=resp(200, body)):
        assert "WRITE" in HuggingFaceChecker().check("hf_x").risk_summary


def test_huggingface_missing_auth_block_is_tolerated():
    with patch("httpx.get", return_value=resp(200, {"name": "alice"})):
        r = HuggingFaceChecker().check("hf_x")
    assert r.is_active is True and r.privilege is None


# ------------------------------------------------------------------- GitLab
def _gitlab(scopes, user=None, me_status=200):
    user = user or {"username": "dev"}
    return [resp(200, user), resp(me_status, {"scopes": scopes})]


@pytest.mark.parametrize("scopes,privilege", [
    (["api"], "write"), (["read_api"], "read"), (["api", "sudo"], "admin"), (["write_repository"], "write"),
])
def test_gitlab_scopes_map_to_privilege(scopes, privilege):
    with patch("httpx.get", side_effect=_gitlab(scopes)):
        r = GitLabChecker().check("glpat-x")
    assert r.is_active is True and r.privilege == privilege and r.permissions == scopes


def test_gitlab_instance_admin_is_admin():
    with patch("httpx.get", side_effect=_gitlab([], user={"username": "root", "is_admin": True})):
        assert GitLabChecker().check("glpat-x").privilege == "admin"


def test_gitlab_scope_lookup_failure_does_not_break_the_result():
    with patch("httpx.get", side_effect=[resp(200, {"username": "dev"}), RuntimeError("net")]):
        r = GitLabChecker().check("glpat-x")
    assert r.is_active is True and r.privilege is None and r.permissions == ["Scopes not exposed"]


# ------------------------------------------------------------- DigitalOcean
def test_digitalocean_active_token():
    with patch("httpx.get", return_value=resp(200, {"account": {"email": "me@example.com"}})):
        r = DigitalOceanChecker().check("dop_v1_x")
    assert r.is_active is True and "me@example.com" in r.account_info


def test_digitalocean_malformed_account_body_is_tolerated():
    with patch("httpx.get", return_value=resp(200, {"account": "weird"})):
        assert DigitalOceanChecker().check("dop_v1_x").is_active is True


# ----------------------------------------------------------------- SendGrid
@pytest.mark.parametrize("scopes,privilege", [
    (["mail.send"], "write"), (["billing.read", "full_access"], "admin"), (["alerts.read"], "read"),
])
def test_sendgrid_privilege_levels(scopes, privilege):
    with patch("httpx.get", return_value=resp(200, {"scopes": scopes})):
        assert SendGridChecker().check("SG.x").privilege == privilege


# -------------------------------------------------------------------- Slack
def test_slack_ok_token_reports_scopes_and_privilege():
    r_ok = resp(200, {"ok": True, "team": "acme", "user": "bot", "bot_id": "B1"},
                {"x-oauth-scopes": "chat:write,files:write"})
    with patch("aysal_scan.blast_radius.slack.httpx.post", return_value=r_ok):
        r = SlackChecker().check("xoxb-x")
    assert r.is_active is True and r.privilege == "write" and "Can send messages" in r.risk_summary


@pytest.mark.parametrize("error", ["account_inactive", "token_expired", "invalid_auth", "token_revoked", "not_authed"])
def test_slack_dead_token_errors_are_inactive(error):
    with patch("aysal_scan.blast_radius.slack.httpx.post", return_value=resp(200, {"ok": False, "error": error})):
        assert SlackChecker().check("xoxb-x").is_active is False


def test_slack_rate_limit_is_unverified_and_retryable():
    with patch("aysal_scan.blast_radius.slack.httpx.post", return_value=resp(200, {"ok": False, "error": "ratelimited"})):
        r = SlackChecker().check("xoxb-x")
    assert r.is_active is None and "HTTP 429" in r.check_error
    with patch("aysal_scan.blast_radius.slack.httpx.post", return_value=resp(429)):
        assert "HTTP 429" in SlackChecker().check("xoxb-x").check_error


# ------------------------------------------------------------ Slack webhook
HOOK = "https://hooks.slack.com/services/T0/B0/xyz"


def test_slack_webhook_never_contacts_other_hosts():
    with patch("httpx.post", side_effect=AssertionError("must not be called")):
        r = SlackWebhookChecker().check("https://evil.example.com/services/T0/B0/x")
    assert r.is_active is None and r.check_performed is False


def test_slack_webhook_no_text_means_live_and_deleted_means_dead():
    with patch("aysal_scan.blast_radius.slack_webhook.httpx.post", return_value=resp(400, text="no_text")):
        assert SlackWebhookChecker().check(HOOK).is_active is True
    with patch("aysal_scan.blast_radius.slack_webhook.httpx.post", return_value=resp(404, text="no_service")):
        assert SlackWebhookChecker().check(HOOK).is_active is False


def test_slack_webhook_unexpected_status_is_unverified():
    with patch("aysal_scan.blast_radius.slack_webhook.httpx.post", return_value=resp(500, text="oops")):
        r = SlackWebhookChecker().check(HOOK)
    assert r.is_active is None and "HTTP 500" in r.check_error


# ------------------------------------------------------------------- Stripe
def test_stripe_restricted_live_key_with_balance_access():
    with patch("httpx.get", return_value=resp(200, {"available": [{"amount": 500, "currency": "usd"}]})):
        r = StripeChecker().check("rk_live_" + "a" * 24)
    assert r.is_active is True and r.privilege == "write" and "5.00 USD" in r.resources[0]
