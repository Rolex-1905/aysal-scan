"""Parallel directory scanning must give exactly the same answer as single-process scanning."""
from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

import aysal_scan.scanner.file_scanner as fs
from aysal_scan.cli import app
from aysal_scan.config import compile_rules
from aysal_scan.models import SecretType
from aysal_scan.scanner.file_scanner import configure_ignore, resolve_jobs, scan_directory_ex
from aysal_scan.scanner.patterns import register_custom_patterns

KEY = "sk_live_" + "a1B2c3D4" * 3


@pytest.fixture(autouse=True)
def _reset():
    configure_ignore(None, False)
    register_custom_patterns([])
    yield
    configure_ignore(None, False)
    register_custom_patterns([])


@pytest.fixture
def tree(tmp_path):
    for i in range(60):
        d = tmp_path / f"pkg{i % 6}"
        d.mkdir(exist_ok=True)
        text = f"value_{i} = {i}\n" + (f"STRIPE=sk_live_{i:02d}{'aB3dE5gH' * 3}\n" if i % 4 == 0 else "")
        (d / f"m{i}.py").write_text(text)
    (tmp_path / "blob.dat").write_bytes(b"\x00\x01" * 10)
    (tmp_path / "big.txt").write_text("x" * 500)
    return tmp_path


def summarize(findings):
    return sorted((f.id, Path(f.file_path).name, f.line_number, f.severity.value) for f in findings)


def test_parallel_and_sequential_results_are_identical(tree):
    seq_f, seq_r, seq_s = scan_directory_ex(tree, max_file_size=200, jobs=1)
    par_f, par_r, par_s = scan_directory_ex(tree, max_file_size=200, jobs=2, parallel_threshold=1)
    assert summarize(par_f) == summarize(seq_f) and len(seq_f) == 15
    assert par_r == seq_r
    assert (par_s.files_scanned, par_s.skipped_binary, par_s.skipped_large) == (
        seq_s.files_scanned, seq_s.skipped_binary, seq_s.skipped_large) == (60, 1, 1)
    assert par_s.notes == []


def test_findings_keep_a_deterministic_order(tree):
    a, _, _ = scan_directory_ex(tree, jobs=2, parallel_threshold=1)
    b, _, _ = scan_directory_ex(tree, jobs=3, parallel_threshold=1)
    c, _, _ = scan_directory_ex(tree, jobs=1)
    assert [f.file_path for f in a] == [f.file_path for f in b] == [f.file_path for f in c]


def test_small_trees_never_start_worker_processes(tree, monkeypatch):
    monkeypatch.setattr(fs, "ProcessPoolExecutor", lambda *a, **k: (_ for _ in ()).throw(AssertionError("pool used")))
    findings, _, stats = scan_directory_ex(tree)          # automatic mode, 62 files < threshold
    assert len(findings) == 15 and stats.notes == []


def test_pool_failure_falls_back_to_one_process_with_a_note(tree, monkeypatch):
    def broken(*a, **k):
        raise OSError("fork not permitted")
    monkeypatch.setattr(fs, "ProcessPoolExecutor", broken)
    expected, _, _ = scan_directory_ex(tree, jobs=1)
    findings, _, stats = scan_directory_ex(tree, jobs=4, parallel_threshold=1)
    assert summarize(findings) == summarize(expected)
    assert any("Parallel scanning was unavailable" in w for w in stats.warnings())


def test_custom_rules_reach_the_worker_processes(tmp_path):
    for i in range(8):
        (tmp_path / f"f{i}.env").write_text("ACME_TOKEN=acme_" + f"{i}a1b2" * 6 + "ab\n")
    register_custom_patterns(compile_rules([{"id": "acme", "regex": "acme_[a-z0-9]{32}", "keywords": ["acme"]}]))
    findings, _, _ = scan_directory_ex(tmp_path, jobs=2, parallel_threshold=1)
    assert len(findings) == 8 and {f.secret_type for f in findings} == {SecretType.CUSTOM}


def test_uninspectable_files_are_counted_not_fatal(tmp_path, monkeypatch):
    (tmp_path / "ok.env").write_text(f"S={KEY}\n")
    (tmp_path / "gone.env").write_text("x")
    real_stat = Path.stat

    def flaky(self, *a, **k):
        if self.name == "gone.env":
            raise PermissionError("denied")
        return real_stat(self, *a, **k)

    monkeypatch.setattr(Path, "stat", flaky)
    findings, _, stats = scan_directory_ex(tmp_path, jobs=1)   # used to crash with PermissionError
    assert stats.unreadable == 1 and stats.files_scanned == 1 and len(findings) == 1
    assert any("could not be read" in w for w in stats.warnings())


@pytest.mark.parametrize("jobs,n,expected", [(None, 10, 1), (0, 10, 1), (1, 9999, 1), (3, 5, 3), (-4, 5, 1)])
def test_resolve_jobs(jobs, n, expected):
    assert resolve_jobs(jobs, n) == expected


def test_resolve_jobs_automatic_uses_cpus_for_big_trees(monkeypatch):
    monkeypatch.setattr(fs.os, "cpu_count", lambda: 4)
    assert resolve_jobs(None, 5000) == 4
    monkeypatch.setattr(fs.os, "cpu_count", lambda: 64)
    assert resolve_jobs(None, 5000) == fs.MAX_AUTO_WORKERS
    monkeypatch.setattr(fs.os, "cpu_count", lambda: None)
    assert resolve_jobs(None, 5000) == 1


def test_cli_jobs_option(tree):
    runner = CliRunner()
    ok = runner.invoke(app, ["scan", str(tree), "--no-blast-radius", "--no-fail", "--jobs", "2"])
    assert ok.exit_code == 0 and "Critical" in ok.output
    assert runner.invoke(app, ["scan", str(tree), "--no-blast-radius", "--jobs", "-1"]).exit_code == 2
