"""Regression tests for every detection / scanning bug found in the v1 audit."""
from __future__ import annotations

import os

import pytest

from aysal_scan.models import SecretType, Severity
from aysal_scan.scanner.file_scanner import (
    _mask,
    configure_ignore,
    scan_content,
    scan_directory,
    scan_directory_ex,
    scan_file,
)


def types(findings):
    return [f.secret_type for f in findings]


@pytest.fixture(autouse=True)
def _reset_ignore():
    configure_ignore(None, False)
    yield
    configure_ignore(None, False)


# --------------------------------------------------------------------------
# Provider confusion / boundaries
# --------------------------------------------------------------------------

def test_kebab_slug_containing_sk_is_not_an_openai_key():
    text = "name = my-disk-encryption-configuration-for-production-servers-in-datacenter-one"
    assert SecretType.OPENAI_KEY not in types(scan_content(text, "x.py")[0])


def test_standalone_lowercase_slug_starting_with_sk_is_not_an_openai_key():
    text = "x = sk-encryption-configuration-for-production-servers-in-datacenter-one"
    assert SecretType.OPENAI_KEY not in types(scan_content(text, "x.py")[0])


def test_anthropic_key_is_classified_as_anthropic_not_openai():
    key = "sk-ant-api03-" + "Ab1_" * 23
    found = types(scan_content("KEY=" + key, "x.env")[0])
    assert SecretType.ANTHROPIC_KEY in found
    assert SecretType.OPENAI_KEY not in found


def test_legacy_and_project_openai_keys_still_detected():
    legacy = "sk-" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5nP7rT9vX1zB3"
    proj = "sk-proj-" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5nP7rT9vX1zB3_x-Y"
    assert SecretType.OPENAI_KEY in types(scan_content("K=" + legacy, "a")[0])
    assert SecretType.OPENAI_KEY in types(scan_content("K=" + proj, "a")[0])


def test_aws_key_embedded_in_longer_token_is_not_matched():
    text = "id=" + "Q" * 6 + "AKIAIOSFODNN7EXAMPLE" + "Q" * 6
    assert SecretType.AWS_ACCESS_KEY not in types(scan_content(text, "x")[0])


def test_aws_temporary_key_is_high_not_critical():
    f, _ = scan_content("K=" + "ASIA" + "A" * 16, "x")
    aws = [x for x in f if x.secret_type == SecretType.AWS_ACCESS_KEY]
    assert aws and aws[0].severity == Severity.HIGH


@pytest.mark.parametrize("prefix,expected", [
    ("ghs_", SecretType.GITHUB_TOKEN),
    ("ghu_", SecretType.GITHUB_TOKEN),
    ("ghr_", SecretType.GITHUB_TOKEN),
])
def test_additional_github_token_prefixes(prefix, expected):
    assert expected in types(scan_content("T=" + prefix + "a1B2" * 9, "x")[0])


@pytest.mark.parametrize("secret,expected", [
    ("hf_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3j", SecretType.HUGGINGFACE_TOKEN),
    ("glpat-" + "aB3dE5gH7jK9mN1pQ3sT", SecretType.GITLAB_TOKEN),
    ("dop_v1_" + "a1b2c3d4" * 8, SecretType.DIGITALOCEAN_TOKEN),
    ("rk_live_" + "a1B2c3D4" * 3, SecretType.STRIPE_RESTRICTED),
    ("xoxp-" + "1234567890-" * 3 + "a1b2c3d4e5f6", SecretType.SLACK_TOKEN),
    ("shpat_" + "a1b2c3d4" * 4, SecretType.SHOPIFY_TOKEN),
    ("GOCSPX-" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9b", SecretType.GOOGLE_OAUTH_SECRET),
    ("dckr_pat_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9", SecretType.DOCKERHUB_TOKEN),
    ("AGE-SECRET-KEY-1" + "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L" + "QPZRY9X8GF2TVDW0S3JN54KHCE", SecretType.AGE_SECRET_KEY),
    ("123456789:AA" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3", SecretType.TELEGRAM_BOT),
    ("HRKU-" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5", SecretType.HEROKU),
])
def test_new_provider_prefixes(secret, expected):
    assert expected in types(scan_content("TOKEN=" + secret, "x.env")[0])


# --------------------------------------------------------------------------
# Database URLs
# --------------------------------------------------------------------------

def test_placeholder_database_urls_are_not_reported():
    for url in ("postgres://user:password@localhost:5432/mydb",
                "postgres://<user>:<password>@host/db",
                "mysql://root:changeme@db/app",
                "postgres://u:${DB_PASSWORD}@host/db"):
        assert SecretType.DATABASE_URL not in types(scan_content(url, "x")[0]), url


def test_redis_url_with_empty_username_is_detected():
    f, _ = scan_content("REDIS_URL=redis://:S3cretPw9xyz@cache.example-corp.net:6379/0", "x")
    assert SecretType.DATABASE_URL in types(f)


def test_database_url_on_local_host_is_medium_remote_is_high():
    local = scan_content("U=postgres://app:S3cretPw9xyz@localhost:5432/app", "x")[0][0]
    remote = scan_content("U=postgres://app:S3cretPw9xyz@db.prod.acme-corp.net:5432/app", "x")[0][0]
    assert local.severity == Severity.MEDIUM
    assert remote.severity == Severity.HIGH


# --------------------------------------------------------------------------
# False-positive filters
# --------------------------------------------------------------------------

@pytest.mark.parametrize("line", [
    "clientSecret = process.env.AZURE_CLIENT_SECRET_FROM_KEYVAULT_VALUE",
    "client_secret = settings.azure_ad_client_secret_value_here_xx",
    "password = get_password()",
    "secret_key = os.environ.get",
    "api_key = config.api_key_value",
    "token: ${{ secrets.DEPLOY_TOKEN }}",
])
def test_code_references_are_not_secrets(line):
    f, _ = scan_content(line, "x.py")
    assert [x for x in f if x.severity != Severity.INFO] == []


def test_real_looking_generic_password_is_still_detected():
    f, _ = scan_content('db_password = "xK9#mP2$vL8qR4"', "x.py")
    assert SecretType.GENERIC in types(f)


# --------------------------------------------------------------------------
# Private keys
# --------------------------------------------------------------------------

def _pem(kind="RSA PRIVATE KEY", seed="A"):
    body = "\n".join(seed * 4 + "bC3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5nP7rT9vX1zB3d" for _ in range(3))
    return f"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----\n"


def test_two_different_private_keys_are_two_findings():
    f1, _ = scan_content(_pem(seed="A"), "a.pem")
    f2, _ = scan_content(_pem(seed="Z"), "b.pem")
    pk1 = [x for x in f1 if x.secret_type == SecretType.PRIVATE_KEY]
    pk2 = [x for x in f2 if x.secret_type == SecretType.PRIVATE_KEY]
    assert len(pk1) == len(pk2) == 1
    assert pk1[0].id != pk2[0].id


def test_same_key_has_same_id_regardless_of_location():
    a, _ = scan_content(_pem(), "a.pem")
    b, _ = scan_content("# copy\n" + _pem(), "other/b.pem")
    assert a[0].id == b[0].id


@pytest.mark.parametrize("kind", [
    "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY", "PRIVATE KEY", "PGP PRIVATE KEY BLOCK",
])
def test_private_key_variants_detected(kind):
    f, _ = scan_content(_pem(kind), "k")
    assert SecretType.PRIVATE_KEY in types(f)


def test_pem_body_lines_do_not_create_entropy_noise():
    f, _ = scan_content(_pem(), "k.pem")
    assert types(f) == [SecretType.PRIVATE_KEY]


def test_header_mentioned_in_code_is_not_a_key():
    code = 'if "-----BEGIN RSA PRIVATE KEY-----" in text:\n    return True\n'
    assert SecretType.PRIVATE_KEY not in types(scan_content(code, "check.py")[0])


# --------------------------------------------------------------------------
# GCP
# --------------------------------------------------------------------------

def _sa(project):
    import json
    return json.dumps({
        "type": "service_account", "project_id": project, "private_key_id": "k-" + project,
        "client_email": f"sa@{project}.iam.gserviceaccount.com",
        "private_key": "-----BEGIN PRIVATE KEY-----\n" + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC" * 2 + "\n-----END PRIVATE KEY-----\n",
    }, indent=2)


def test_different_service_account_files_are_distinct_findings():
    a, _ = scan_content(_sa("proj-a"), "a.json")
    b, _ = scan_content(_sa("proj-b"), "b.json")
    assert a[0].id != b[0].id


def test_service_account_json_does_not_also_report_embedded_pem():
    f, _ = scan_content(_sa("proj-a"), "a.json")
    assert SecretType.PRIVATE_KEY not in types(f)
    assert types(f).count(SecretType.GCP_SERVICE_ACCOUNT) == 1


# --------------------------------------------------------------------------
# IDs, masking, entropy, context
# --------------------------------------------------------------------------

def test_entropy_id_does_not_depend_on_variable_name():
    tok = "Zk3Fq9Yv8nLpWm2xRtBjHcDeAoUiKsGy"
    a, _ = scan_content(f"A_KEY={tok}", "x")
    b, _ = scan_content(f"OTHER={tok}", "x")
    c, _ = scan_content(tok, "x")
    assert a[0].id == b[0].id == c[0].id


def test_short_secrets_are_masked_more_aggressively():
    assert _mask("hunter2023") == "hu******23"
    assert _mask("short") == "****"
    assert _mask("A" * 40).count("*") == 32


def test_example_files_are_one_severity_lower():
    key = "STRIPE=sk_live_" + "a1B2c3D4" * 3
    normal = scan_content(key, "config.env")[0][0]
    example = scan_content(key, ".env.example")[0][0]
    assert normal.severity == Severity.CRITICAL
    assert example.severity == Severity.HIGH
    assert "example-file" in example.tags


def test_id_salt_changes_ids(monkeypatch):
    import aysal_scan.scanner.file_scanner as fs
    plain = fs._secret_id("value")
    monkeypatch.setattr(fs, "_ID_SALT", "team-secret")
    assert fs._secret_id("value") != plain


# --------------------------------------------------------------------------
# Directory walking
# --------------------------------------------------------------------------

KEY = "sk_live_" + "a1B2c3D4" * 3


def _w(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def test_lock_files_are_skipped_by_name(tmp_path):
    blob = '{"integrity":"sha512-Zk3Fq9Yv8nLpWm2xRtBjHcDeAoUiKsGyTnVhXlQwEr7MaPbOz1CdJfSg4uN6IvY5kLmQ"}'
    _w(tmp_path, "package-lock.json", blob)
    _w(tmp_path, "pnpm-lock.yaml", blob)
    findings, _, n = scan_directory(tmp_path)
    assert findings == [] and n == 0


@pytest.mark.parametrize("d", ["logs", "bin", "env", "tmp", "output", "site"])
def test_directories_that_commonly_hold_secrets_are_scanned(tmp_path, d):
    _w(tmp_path, f"{d}/app.env", f"STRIPE={KEY}\n")
    findings, _, _ = scan_directory(tmp_path)
    assert SecretType.STRIPE_SECRET in types(findings)


def test_node_modules_is_pruned_not_scanned(tmp_path):
    _w(tmp_path, "node_modules/pkg/c.env", f"STRIPE={KEY}\n")
    _w(tmp_path, "src/a.txt", "hello\n")
    findings, _, n = scan_directory(tmp_path)
    assert findings == [] and n == 1


def test_virtualenv_detected_by_pyvenv_cfg_whatever_its_name(tmp_path):
    _w(tmp_path, "myenv/pyvenv.cfg", "home = /usr/bin\n")
    _w(tmp_path, "myenv/lib/x.env", f"STRIPE={KEY}\n")
    assert scan_directory(tmp_path)[0] == []


def test_substring_directory_names_are_not_skipped(tmp_path):
    _w(tmp_path, "contests/fixtures/a.env", f"STRIPE={KEY}\n")
    _w(tmp_path, "mypublic/builder/a.env", f"STRIPE={KEY}\n")
    findings, _, stats = scan_directory_ex(tmp_path)
    assert stats.files_scanned == 2
    assert len(findings) == 2  # one per file; cross-file dedup happens later


def test_symlinks_are_not_followed(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "_outside.txt")
    outside.write_text(f"STRIPE={KEY}\n")
    scan_root = tmp_path / "repo"
    scan_root.mkdir()
    try:
        os.symlink(outside, scan_root / "link.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    findings, _, stats = scan_directory_ex(scan_root)
    assert findings == [] and stats.skipped_symlinks == 1


def test_binary_and_oversized_files_are_skipped_and_counted(tmp_path):
    (tmp_path / "data.dat").write_bytes(b"\x00\x01" + KEY.encode())
    (tmp_path / "huge.txt").write_text("x" * 100)
    findings, _, stats = scan_directory_ex(tmp_path, max_file_size=50)
    assert findings == []
    assert stats.skipped_binary == 1 and stats.skipped_large == 1
    assert len(stats.warnings()) == 2


def test_single_file_scan_ignores_directory_skip_rules(tmp_path):
    f = _w(tmp_path, "build/output/app.env", f"STRIPE={KEY}\n")
    assert SecretType.STRIPE_SECRET in types(scan_file(f)[0])


def test_single_file_scan_of_lock_file_is_honoured(tmp_path):
    f = _w(tmp_path, "package-lock.json", f"STRIPE={KEY}\n")
    assert SecretType.STRIPE_SECRET in types(scan_file(f)[0])


# --------------------------------------------------------------------------
# AysalScanignore (gitignore semantics)
# --------------------------------------------------------------------------

def _reported(tmp_path):
    return sorted(
        os.path.relpath(f.file_path, tmp_path).replace(os.sep, "/")
        for f in scan_directory(tmp_path)[0]
        if f.secret_type == SecretType.STRIPE_SECRET
        for _ in [0]
    )


@pytest.fixture
def tree(tmp_path):
    for i, rel in enumerate(["docs/a.env", "src/deep/b.env", "src/c.env", "keep/d.env", "a.env"]):
        _w(tmp_path, rel, f"STRIPE=sk_live_{i}{'aB3dE5gH' * 3}\n")
    return tmp_path


def test_directory_pattern(tree):
    _w(tree, "AysalScanignore", "docs/\n")
    assert "docs/a.env" not in _reported(tree)


def test_root_anchored_pattern_only_matches_at_root(tree):
    _w(tree, "AysalScanignore", "/a.env\n")
    got = _reported(tree)
    assert "a.env" not in got and "docs/a.env" in got


def test_double_star_pattern(tree):
    _w(tree, "AysalScanignore", "**/deep/\n")
    got = _reported(tree)
    assert "src/deep/b.env" not in got and "src/c.env" in got


def test_single_star_does_not_cross_directories(tree):
    _w(tree, "AysalScanignore", "src/*.env\n")
    got = _reported(tree)
    assert "src/c.env" not in got and "src/deep/b.env" in got


def test_negation(tree):
    _w(tree, "AysalScanignore", "*.env\n!keep/d.env\n")
    assert _reported(tree) == ["keep/d.env"]


def test_bom_does_not_break_first_pattern(tree):
    (tree / "AysalScanignore").write_bytes("\ufeffa.env\n".encode("utf-8"))
    assert "a.env" not in _reported(tree)


def test_explicit_ignore_file_overrides_repo_file(tree, tmp_path_factory):
    _w(tree, "AysalScanignore", "*\n")  # hostile repo hides everything
    trusted = tmp_path_factory.mktemp("trusted") / "mine.ignore"
    trusted.write_text("docs/\n")
    configure_ignore(trusted, False)
    got = _reported(tree)
    assert got and "docs/a.env" not in got


def test_ignore_file_can_be_disabled_for_untrusted_repos(tree):
    _w(tree, "AysalScanignore", "*\n")
    configure_ignore(None, True)
    assert len(_reported(tree)) == 5


def test_ignore_discovery_stops_at_repository_root(tmp_path):
    outer = tmp_path / "outer"
    inner = outer / "repo"
    (inner / ".git").mkdir(parents=True)
    _w(outer, "AysalScanignore", "*\n")     # stray file ABOVE the repo root
    _w(inner, "a.env", f"STRIPE={KEY}\n")
    assert SecretType.STRIPE_SECRET in types(scan_directory(inner)[0])


# --------------------------------------------------------------------------
# Paired secrets, context-gated generic secrets, scoring of heuristics
# --------------------------------------------------------------------------

def test_aws_secret_key_is_not_reported_twice():
    text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    f, raw = scan_content(text, "x.env")
    assert [x.secret_type for x in f] == [SecretType.AWS_ACCESS_KEY]
    assert raw[f[0].id].endswith("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")


def test_aws_secret_key_before_the_key_id_is_also_paired():
    text = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    f, _ = scan_content(text, "x.env")
    assert [x.secret_type for x in f] == [SecretType.AWS_ACCESS_KEY]


@pytest.mark.parametrize("line", [
    "token=9f86d081884c7d659a2feaa0c55ad015",
    "totp=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    "https://x.io/cb?token=aB3dE5gH7jK9mN1p",
])
def test_hex_base32_and_query_string_tokens_are_found_by_context(line):
    assert SecretType.GENERIC in types(scan_content(line, "x.py")[0])


@pytest.mark.parametrize("line", [
    "token = tokenizer.encode(text)", "def f(token: str) -> None:", "next_token = get_token()",
    "token = None", "<input name='token' value='{{ csrf_token }}'>",
])
def test_token_keyword_false_positives_stay_quiet(line):
    assert scan_content(line, "x.py")[0] == []


def test_internal_hostnames_are_not_treated_as_dev_databases():
    f, _ = scan_content("U=postgres://app:S3cretPw9xyz@db.prod.corp.internal:5432/x", "x")
    assert f[0].severity == Severity.HIGH


def test_heuristic_findings_score_much_lower_than_specific_credentials():
    from aysal_scan.scoring import score_finding
    entropy = scan_content("Zk3Fq9Yv8nLpWm2xRtBjHcDeAoUiKsGy", "x")[0][0]
    stripe = scan_content("S=sk_live_" + "a1B2c3D4" * 3, "x")[0][0]
    assert score_finding(stripe)[0] - score_finding(entropy)[0] >= 25


@pytest.mark.parametrize("line", [
    "OPENAI_API_KEY=sk-your-key-here",
    "api_key = your-api-key-goes-here",
    "SECRET=my-secret-value-example",
    "password: replace-with-real-password",
    "token=insert_token_here_please",
])
def test_documentation_placeholders_are_not_secrets(line):
    assert scan_content(line, "README.md")[0] == []


def test_placeholder_filter_does_not_hide_real_looking_values():
    f, _ = scan_content('db_password = "xK9#mP2$vL8qR4"', "x.py")
    assert SecretType.GENERIC in types(f)


# --------------------------------------------------------------------------
# Private-key false positives found by scanning this very project
# --------------------------------------------------------------------------

def test_header_inside_a_python_string_followed_by_code_is_not_a_key():
    source = (
        "decoys = {\n"
        "    'pem_header_in_code': ('check.py', 'if \"-----BEGIN RSA PRIVATE KEY-----\" in text:\\n    raise ValueError\\n'),\n"
        "    'type_hint_token': ('sig.py', 'def verify(token: str, secret: bytes) -> bool:'),\n"
        "    'another': ('x.py', 'ProbablyAVeryLongIdentifierNameThatKeepsGoing'),\n"
        "}\n"
    )
    assert SecretType.PRIVATE_KEY not in types(scan_content(source, "corpus.py")[0])


def test_unterminated_key_with_real_body_is_still_reported():
    body = "\n".join("MIIEowIBAAKCAQEAfakeFAKEfakeFAKEabcdEFGHijklMNOPqrstUVWX012345678"[:64] for _ in range(3))
    f, _ = scan_content("-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n", "truncated.pem")
    assert SecretType.PRIVATE_KEY in types(f)


def test_json_escaped_single_line_key_is_detected():
    line = '{"private_key": "-----BEGIN PRIVATE KEY-----\\n' + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC" * 2 + '\\n-----END PRIVATE KEY-----\\n"}'
    assert SecretType.PRIVATE_KEY in types(scan_content(line, "creds.json")[0])


def test_pgp_armor_headers_do_not_break_detection():
    body = "\n".join("lQdGBF" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5nP7rT9vX1zB3" for _ in range(3))
    text = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\n" + body + "\n-----END PGP PRIVATE KEY BLOCK-----\n"
    assert SecretType.PRIVATE_KEY in types(scan_content(text, "k.asc")[0])
