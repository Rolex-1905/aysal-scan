"""Output and crash behaviour: a scan must never abort because of how its output is displayed,
and an unexpected crash must never look like "secrets found"."""
from __future__ import annotations

import io
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

import aysal_scan.cli as cli

KEY = "sk_live_" + "a1B2c3D4" * 3


def run_cli(args, encoding="cp1252", extra_env=None):
    env = {**os.environ, "PYTHONIOENCODING": encoding, **(extra_env or {})}
    env.pop("PYTHONUTF8", None)
    return subprocess.run(
        [sys.executable, "-m", "aysal_scan.cli", *args],
        capture_output=True, env=env, timeout=120,
    )


@pytest.fixture
def clean_dir(tmp_path):
    (tmp_path / "a.py").write_text("print('hi')\n")
    return tmp_path


@pytest.fixture
def leaky_dir(tmp_path):
    (tmp_path / "a.env").write_text(f"S={KEY}\n")
    return tmp_path


# ----------------------------------------------------------------- legacy code page output

@pytest.mark.parametrize("report", ["terminal", "markdown", "json", "sarif"])
def test_clean_scan_survives_a_legacy_codepage_pipe(clean_dir, report):
    p = run_cli(["scan", str(clean_dir), "--no-blast-radius", "--report", report])
    assert p.returncode == 0, p.stderr.decode("utf-8", "replace")
    assert b"Traceback" not in p.stderr and b"UnicodeEncodeError" not in p.stderr


@pytest.mark.parametrize("report", ["terminal", "markdown"])
def test_findings_report_survives_a_legacy_codepage_pipe(leaky_dir, report):
    p = run_cli(["scan", str(leaky_dir), "--no-blast-radius", "--report", report])
    assert p.returncode == 1, p.stderr.decode("utf-8", "replace")     # findings, not a crash
    assert b"Traceback" not in p.stderr
    assert b"Stripe" in p.stdout


def test_verbose_and_ascii_streams_also_work(leaky_dir):
    p = run_cli(["scan", str(leaky_dir), "--no-blast-radius", "--verbose"], encoding="ascii")
    assert p.returncode == 1 and b"Traceback" not in p.stderr


def test_ensure_unicode_streams_switches_a_legacy_stream_to_utf8(monkeypatch):
    legacy = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", legacy)
    monkeypatch.setattr(sys, "stderr", io.TextIOWrapper(io.BytesIO(), encoding="utf-8"))
    cli._ensure_unicode_streams()
    assert legacy.encoding.lower().replace("-", "") == "utf8"
    legacy.write("✓ 🔴 …")            # would raise UnicodeEncodeError before the fix
    legacy.flush()


def test_ensure_unicode_streams_leaves_utf8_and_unconfigurable_streams_alone(monkeypatch):
    class Plain:                       # no .reconfigure (e.g. a captured stream)
        encoding = "cp1252"
    monkeypatch.setattr(sys, "stdout", Plain())
    monkeypatch.setattr(sys, "stderr", io.TextIOWrapper(io.BytesIO(), encoding="utf-8"))
    cli._ensure_unicode_streams()      # must not raise


# ----------------------------------------------------------------- crashes are exit code 2

def test_unexpected_exception_exits_2_with_a_short_message(monkeypatch, capsys):
    def boom():
        raise RuntimeError("something odd")
    monkeypatch.setattr(cli, "app", boom)
    monkeypatch.delenv("AYSAL_SCAN_DEBUG", raising=False)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "unexpected RuntimeError" in err and "something odd" in err and "Traceback" not in err


def test_debug_variable_shows_the_original_exception(monkeypatch):
    def boom():
        raise RuntimeError("something odd")
    monkeypatch.setattr(cli, "app", boom)
    monkeypatch.setenv("AYSAL_SCAN_DEBUG", "1")
    with pytest.raises(RuntimeError):
        cli.main()


def test_normal_exit_codes_pass_through_main(monkeypatch):
    for code in (0, 1, 2):
        monkeypatch.setattr(cli, "app", lambda c=code: (_ for _ in ()).throw(SystemExit(c)))
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == code


def test_ctrl_c_exits_130(monkeypatch):
    def interrupted():
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "app", interrupted)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 130


def test_console_script_points_at_the_wrapper_not_the_raw_app():
    meta = tomllib.loads((Path(__file__).resolve().parent.parent / "pyproject.toml").read_text())
    assert meta["project"]["scripts"]["aysal-scan"] == "aysal_scan.cli:main"


def test_real_crash_inside_a_scan_is_exit_2_not_1(clean_dir):
    """End to end through the real entry point: an internal failure must not look like findings."""
    env_code = (
        "import aysal_scan.cli as c, aysal_scan.scanner.file_scanner as f;"
        "f.scan_directory_ex = lambda *a, **k: (_ for _ in ()).throw(ZeroDivisionError('x'));"
        "c.scan_directory_ex = f.scan_directory_ex;"
        "import sys; sys.argv = ['aysal-scan', 'scan', sys.argv[1], '--no-blast-radius'];"
        "c.main()"
    )
    p = subprocess.run([sys.executable, "-c", env_code, str(clean_dir)], capture_output=True, timeout=120,
                       env={k: v for k, v in os.environ.items() if k != "AYSAL_SCAN_DEBUG"})
    assert p.returncode == 2, (p.stdout + p.stderr).decode("utf-8", "replace")
    assert b"Traceback" not in p.stderr
