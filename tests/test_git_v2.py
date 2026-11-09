"""Regression tests for the git layer (v1 audit findings)."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from aysal_scan.models import SecretType
from aysal_scan.scanner.file_scanner import configure_ignore
from aysal_scan.scanner.git_utils import (
    GitScanError,
    parse_added_lines,
    parse_multi_file_diff,
    scan_commits,
    scan_commits_ex,
    scan_staged,
)

KEY = "sk_live_" + "a1B2c3D4" * 3


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture(autouse=True)
def _reset_ignore():
    configure_ignore(None, False)
    yield
    configure_ignore(None, False)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.email", "t@t.t")
    git(r, "config", "user.name", "t")
    return r


def commit(repo, rel, text, msg="c", mode="w"):
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, mode, encoding="utf-8") as fh:
        fh.write(text)
    git(repo, "add", "-f", rel)
    git(repo, "commit", "-qm", msg)
    return git(repo, "rev-parse", "--short=7", "HEAD")


# --------------------------------------------------------------------------
# Fail closed
# --------------------------------------------------------------------------

def test_scan_commits_on_non_git_directory_raises(tmp_path):
    (tmp_path / "a.env").write_text(f"S={KEY}\n")
    with pytest.raises(GitScanError):
        scan_commits(tmp_path)


def test_scan_staged_on_non_git_directory_raises(tmp_path):
    with pytest.raises(GitScanError):
        scan_staged(tmp_path)


def test_empty_repository_is_not_an_error(repo):
    assert scan_commits(repo)[3] == 0
    assert scan_staged(repo)[2] == 0


# --------------------------------------------------------------------------
# Line numbers
# --------------------------------------------------------------------------

def test_history_line_number_is_the_real_file_line(repo):
    commit(repo, "big.txt", "\n".join(f"line {i}" for i in range(1, 61)) + "\n")
    commit(repo, "big.txt", f"STRIPE={KEY}\n", mode="a")  # real line 61
    findings, *_ = scan_commits(repo)
    assert [f.line_number for f in findings] == [61]


def test_staged_line_number_is_the_real_file_line(repo):
    commit(repo, "big.txt", "\n".join(f"line {i}" for i in range(1, 11)) + "\n")
    (repo / "big.txt").write_text("\n".join(f"line {i}" for i in range(1, 11)) + f"\nSTRIPE={KEY}\n")
    git(repo, "add", "big.txt")
    findings, _, n = scan_staged(repo)
    assert n == 1 and [f.line_number for f in findings] == [11]


def test_parse_added_lines_handles_multiple_hunks_and_no_newline_marker():
    patch = (
        "@@ -1,2 +1,3 @@\n a\n+b\n c\n"
        "@@ -10,0 +12,2 @@\n+x\n+y\n\\ No newline at end of file\n"
    )
    assert parse_added_lines(patch) == [(2, "b"), (12, "x"), (13, "y")]


def test_parse_added_lines_keeps_lines_that_start_with_plus_signs():
    assert parse_added_lines("@@ -0,0 +1 @@\n+++secret\n") == [(1, "++secret")]


def test_parse_multi_file_diff_handles_spaces_in_paths():
    diff = (
        "diff --git a/my file.txt b/my file.txt\n--- /dev/null\n+++ b/my file.txt\t\n"
        "@@ -0,0 +1 @@\n+hello\n"
    )
    assert parse_multi_file_diff(diff) == {"my file.txt": [(1, "hello")]}


# --------------------------------------------------------------------------
# Staged scanning
# --------------------------------------------------------------------------

def test_staged_scan_works_from_a_subdirectory(repo):
    (repo / "sub").mkdir()
    (repo / "sub" / "x.env").write_text(f"S={KEY}\n")
    git(repo, "add", ".")
    findings, *_ = scan_staged(repo / "sub")
    assert SecretType.STRIPE_SECRET in [f.secret_type for f in findings]


def test_staged_scan_handles_non_ascii_filenames(repo):
    (repo / "café.env").write_text(f"S={KEY}\n")
    git(repo, "add", ".")
    findings, _, n = scan_staged(repo)
    assert n == 1 and findings and findings[0].file_path == "café.env"


def test_staged_scan_honours_skip_rules_and_ignore_file(repo):
    (repo / "AysalScanignore").write_text("ignored.env\n")
    (repo / "ignored.env").write_text(f"S={KEY}\n")
    (repo / "node_modules" / "pkg").mkdir(parents=True)
    (repo / "node_modules" / "pkg" / "c.env").write_text(f"S={KEY}\n")
    (repo / "package-lock.json").write_text('{"i":"sha512-Zk3Fq9Yv8nLpWm2xRtBjHcDeAoUiKsGyTnVhXlQwEr7MaPbOz1CdJfSg4uN6IvY5kLmQ"}\n')
    (repo / "real.env").write_text(f"S={KEY}\n")
    git(repo, "add", "-f", ".")
    findings, *_ = scan_staged(repo)
    assert sorted({f.file_path for f in findings}) == ["real.env"]


def test_staged_scan_only_flags_added_lines_not_existing_ones(repo):
    commit(repo, "old.env", f"S={KEY}\n")            # already committed
    (repo / "old.env").write_text(f"S={KEY}\nOTHER=1\n")
    git(repo, "add", "old.env")
    assert scan_staged(repo)[0] == []


# --------------------------------------------------------------------------
# History
# --------------------------------------------------------------------------

def test_secret_is_attributed_to_the_commit_that_introduced_it(repo):
    commit(repo, "a.txt", "hi\n", "base")
    git(repo, "checkout", "-qb", "feature")
    introducing = commit(repo, "leak.env", f"S={KEY}\n", "oops")
    git(repo, "checkout", "-q", "main")
    commit(repo, "b.txt", "other\n", "main work")
    git(repo, "merge", "--no-ff", "-qm", "merge feature", "feature")
    findings, *_ = scan_commits(repo)
    assert len(findings) == 1
    assert findings[0].commit_hash == introducing


def test_same_secret_in_later_commits_becomes_extra_locations(repo):
    first = commit(repo, "a.env", f"S={KEY}\n", "one")
    commit(repo, "b.env", f"S={KEY}\n", "two")
    findings, *_ = scan_commits(repo)
    assert len(findings) == 1 and findings[0].commit_hash == first
    assert [l.file_path for l in findings[0].locations] == ["b.env"]


def test_full_history_scans_other_branches_but_head_only_does_not(repo):
    commit(repo, "a.txt", "hi\n", "base")
    git(repo, "checkout", "-qb", "feature")
    commit(repo, "leak.env", f"S={KEY}\n", "oops")
    git(repo, "checkout", "-q", "main")
    assert scan_commits(repo)[0] == []
    assert len(scan_commits(repo, all_refs=True)[0]) == 1


def test_partial_history_flag_when_limiting_commits(repo):
    for i in range(4):
        commit(repo, f"f{i}.txt", f"{i}\n", f"c{i}")
    _, _, _, scanned, partial = scan_commits(repo, n_commits=2)
    assert scanned == 2 and partial is True
    assert scan_commits(repo, n_commits=10)[4] is False


def test_n_commits_scans_the_newest_ones(repo):
    commit(repo, "old.env", f"S={KEY}\n", "old leak")
    for i in range(3):
        commit(repo, f"f{i}.txt", f"{i}\n", f"c{i}")
    assert scan_commits(repo, n_commits=2)[0] == []
    assert len(scan_commits(repo, n_commits=4)[0]) == 1


def test_in_head_distinguishes_removed_secrets(repo):
    commit(repo, "gone.env", f"S={KEY}\n", "add")
    git(repo, "rm", "-q", "gone.env")
    git(repo, "commit", "-qm", "remove")
    commit(repo, "kept.env", "T=sk_live_" + "Z9y8X7w6" * 3 + "\n", "add2")
    by_file = {f.file_path: f for f in scan_commits_ex(repo).findings}
    assert by_file["gone.env"].in_head is False
    assert by_file["kept.env"].in_head is True


def test_time_budget_reports_partial_history(repo):
    for i in range(3):
        commit(repo, f"f{i}.txt", f"{i}\n", f"c{i}")
    result = scan_commits_ex(repo, max_seconds=-1)
    assert result.partial_history is True and result.warnings
