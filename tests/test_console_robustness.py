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
from aysal_scan import safe_output

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

@pytest.mark.parametrize("encoding", ["cp1252", "cp437", "ascii", "latin-1"])
def test_clean_scan_survives_legacy_encodings(clean_dir, encoding):
    p = run_cli(["scan", str(clean_dir), "--no-blast-radius"], encoding=encoding)
    assert p.returncode == 0, p.stderr.decode("utf-8", "replace")
    assert b"Traceback" not in p.stderr and b"UnicodeEncodeError" not in p.stderr
    out = p.stdout.decode(encoding, "strict")          # decodes cleanly in the stream's OWN encoding
    assert "No secrets found" in out and "OK" in out   # check mark became readable ASCII


@pytest.mark.parametrize("report", ["markdown", "json", "sarif"])
def test_other_reports_survive_a_legacy_codepage_pipe(clean_dir, report):
    p = run_cli(["scan", str(clean_dir), "--no-blast-radius", "--report", report])
    assert p.returncode == 0, p.stderr.decode("utf-8", "replace")
    assert b"Traceback" not in p.stderr


def test_legacy_output_contains_no_mojibake_question_marks_for_symbols(clean_dir):
    out = run_cli(["scan", str(clean_dir), "--no-blast-radius"], encoding="ascii").stdout.decode("ascii")
    assert "???" not in out                            # v1 of the fix produced '???' per symbol


@pytest.mark.parametrize("report", ["terminal", "markdown"])
def test_findings_report_survives_a_legacy_codepage_pipe(leaky_dir, report):
    p = run_cli(["scan", str(leaky_dir), "--no-blast-radius", "--report", report])
    assert p.returncode == 1, p.stderr.decode("utf-8", "replace")     # findings, not a crash
    assert b"Traceback" not in p.stderr
    assert b"Stripe" in p.stdout


def test_verbose_and_ascii_streams_also_work(leaky_dir):
    p = run_cli(["scan", str(leaky_dir), "--no-blast-radius", "--verbose"], encoding="ascii")
    assert p.returncode == 1 and b"Traceback" not in p.stderr


def test_file_names_with_invalid_bytes_do_not_crash_utf8_output(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX file names can hold arbitrary bytes")
    bad = os.fsdecode(b"leak_\xff\xfe.env")            # decodes to lone surrogates
    (tmp_path / bad).write_text(f"S={KEY}\n")
    p = run_cli(["scan", str(tmp_path), "--no-blast-radius"], encoding="utf-8")
    assert p.returncode == 1 and b"Traceback" not in p.stderr


# ----------------------------------------------------------------- the handler itself

def test_handler_maps_known_symbols_and_questions_the_rest():
    assert safe_output.to_ascii("\u2713 done \u2026 \U0001f534 \u4e2d") == "OK done ...  ?"
    assert safe_output.to_ascii("plain") == "plain"
    assert safe_output.to_ascii("\u26a0\ufe0f") == "!"


def test_install_keeps_the_encoding_and_replaces_only_what_it_cannot_encode(monkeypatch):
    legacy = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", legacy)
    monkeypatch.setattr(sys, "stderr", io.TextIOWrapper(io.BytesIO(), encoding="utf-8"))
    safe_output.install()
    assert legacy.encoding.lower() == "cp1252"          # NOT forced to UTF-8
    legacy.write("\u2713 caf\u00e9 \u2026 \U0001f534 x")   # e-acute and ellipsis exist in cp1252
    legacy.flush()
    assert legacy.buffer.getvalue() == "OK caf\u00e9 \u2026  x".encode("cp1252")


def test_install_is_idempotent_and_tolerates_streams_without_reconfigure(monkeypatch):
    class Plain:
        encoding = "cp1252"
    monkeypatch.setattr(sys, "stdout", Plain())
    monkeypatch.setattr(sys, "stderr", Plain())
    safe_output.install()
    safe_output.install()                               # must not raise


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
