"""The streaming `git log -p` backend must behave exactly like the GitPython backend."""
from __future__ import annotations

import subprocess

import pytest

import aysal_scan.scanner.git_utils as gu
from aysal_scan.scanner.file_scanner import configure_ignore

KEY = "sk_live_" + "a1B2c3D4" * 3
KEY2 = "sk_live_" + "Z9y8X7w6" * 3
TOKEN = "ghp_" + "a1B2" * 9


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture(autouse=True)
def _reset():
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


def tricky_history(repo):
    commit(repo, "base.txt", "hello\n" * 5, "base")
    commit(repo, "config/app.env", f"S={KEY}\n", "leak one")
    commit(repo, "config/copy.env", f"S={KEY}\n", "same secret elsewhere")
    git(repo, "mv", "config/app.env", "config/renamed.env"); git(repo, "commit", "-qm", "rename")
    git(repo, "rm", "-q", "config/copy.env"); git(repo, "commit", "-qm", "delete")
    commit(repo, "café.env", f"T={TOKEN}\n", "unicode name")
    git(repo, "checkout", "-qb", "feature")
    commit(repo, "feat.env", f"S={KEY2}\n", "feature leak")
    git(repo, "checkout", "-q", "main")
    commit(repo, "main.txt", "x\n", "main work")
    git(repo, "merge", "--no-ff", "-qm", "merge feature", "feature")
    (repo / "blob.bin").write_bytes(b"\x00\x01\x02" * 100)
    git(repo, "add", "blob.bin"); git(repo, "commit", "-qm", "binary")
    git(repo, "checkout", "-qb", "unmerged")
    commit(repo, "side.env", f"S={'Q1w2E3r4' * 3}_x\n".replace("_x", ""), "unmerged note")


def summarize(result):
    return sorted(
        (f.id, f.file_path, f.line_number, f.commit_hash, f.commit_date, f.in_head,
         sorted((l.file_path, l.line_number, l.commit_hash) for l in f.locations))
        for f in result.findings
    )


@pytest.mark.parametrize("kwargs", [{}, {"all_refs": True}, {"n_commits": 4}])
def test_streaming_backend_matches_gitpython_backend(repo, kwargs):
    tricky_history(repo)
    fast = gu._scan_commits_stream(repo, kwargs.get("n_commits"), kwargs.get("all_refs", False), None)
    slow = gu._scan_commits_gitpython(repo, kwargs.get("n_commits"), kwargs.get("all_refs", False), None)
    assert summarize(fast) == summarize(slow)
    assert fast.commits_scanned == slow.commits_scanned
    assert fast.partial_history == slow.partial_history
    assert fast.findings  # the comparison is not vacuous


def test_streaming_backend_handles_empty_repository(repo):
    for all_refs in (False, True):
        r = gu._scan_commits_stream(repo, None, all_refs, None)
        assert r.findings == [] and r.commits_scanned == 0


def test_streaming_backend_reports_partial_history_and_time_budget(repo):
    for i in range(4):
        commit(repo, f"f{i}.txt", f"{i}\n", f"c{i}")
    assert gu._scan_commits_stream(repo, 2, False, None).partial_history is True
    assert gu._scan_commits_stream(repo, 10, False, None).partial_history is False
    timed = gu._scan_commits_stream(repo, None, False, -1)
    assert timed.partial_history is True and timed.warnings


def test_non_repository_still_raises_from_the_public_entry_point(tmp_path):
    with pytest.raises(gu.GitScanError):
        gu.scan_commits_ex(tmp_path)


def test_public_entry_point_falls_back_when_streaming_is_unavailable(repo, monkeypatch):
    commit(repo, "a.env", f"S={KEY}\n")
    monkeypatch.setattr(gu, "_git_version", lambda: (2, 0))   # too old for --diff-merges
    called = {"slow": 0}
    real = gu._scan_commits_gitpython
    monkeypatch.setattr(gu, "_scan_commits_gitpython", lambda *a, **k: (called.__setitem__("slow", 1), real(*a, **k))[1])
    assert len(gu.scan_commits_ex(repo).findings) == 1 and called["slow"] == 1


def test_environment_variable_forces_the_gitpython_backend(repo, monkeypatch):
    commit(repo, "a.env", f"S={KEY}\n")
    monkeypatch.setenv("AYSAL_SCAN_GIT_BACKEND", "gitpython")
    monkeypatch.setattr(gu, "_scan_commits_stream", lambda *a, **k: (_ for _ in ()).throw(AssertionError("streaming used")))
    assert len(gu.scan_commits_ex(repo).findings) == 1


def test_streaming_backend_honours_the_ignore_file(repo):
    commit(repo, "AysalScanignore", "secrets.env\n")
    commit(repo, "secrets.env", f"S={KEY}\n")
    commit(repo, "real.env", f"S={KEY2}\n")
    assert [f.file_path for f in gu._scan_commits_stream(repo, None, False, None).findings] == ["real.env"]


def test_added_lines_starting_with_plus_signs_survive_streaming(repo):
    commit(repo, "x.txt", f"+++S={KEY}\n")   # a line whose content begins with '++'
    assert len(gu._scan_commits_stream(repo, None, False, None).findings) == 1
