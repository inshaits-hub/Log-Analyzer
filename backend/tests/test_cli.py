"""Pytest tests for the standalone CLI (src/main.py)."""

import json
import os
from pathlib import Path

import pytest

from src import database
from src import main as cli


@pytest.fixture
def restore_db_path():
    """CLI tests redirect DB_PATH - put the environment back afterwards."""
    previous = os.environ.get("DB_PATH")
    yield
    if previous is None:
        os.environ.pop("DB_PATH", None)
    else:
        os.environ["DB_PATH"] = previous


def test_cli_end_to_end(tmp_path, demo_log_path, capsys, restore_db_path):
    reports_dir = tmp_path / "reports"
    db_path = tmp_path / "cli.db"

    code = cli.main(
        [
            "--log",
            str(demo_log_path),
            "--export",
            "both",
            "--output",
            str(reports_dir),
            "--db",
            str(db_path),
            "--top",
            "3",
        ]
    )

    assert code == 0
    out = capsys.readouterr().out
    assert "EXECUTIVE SUMMARY" in out
    assert "Threats detected" in out
    assert "TOP ALERTS" in out

    html_files = sorted(reports_dir.glob("*.html"))
    json_files = sorted(reports_dir.glob("*.json"))
    assert html_files, "an HTML report must be written"
    assert json_files, "a JSON report must be written"

    payload = json.loads(json_files[0].read_text(encoding="utf-8"))
    assert payload["summary"]["total_events"] > 0
    assert payload["summary"]["total_threats"] > 0
    assert payload["threats"]

    counts = database.get_summary(db_path=db_path)
    assert counts["total_events"] == payload["summary"]["total_events"]
    assert counts["total_threats"] == payload["summary"]["total_threats"]


def test_cli_quiet_prints_only_report_path(tmp_path, demo_log_path, capsys, restore_db_path):
    code = cli.main(
        [
            "--log",
            str(demo_log_path),
            "--export",
            "html",
            "--output",
            str(tmp_path),
            "--no-save",
            "--quiet",
        ]
    )

    assert code == 0
    out = capsys.readouterr().out.strip()
    assert out.endswith(".html")
    assert Path(out).exists()


def test_cli_no_save_skips_database(tmp_path, demo_log_path, capsys, restore_db_path):
    db_path = tmp_path / "unused.db"
    code = cli.main(
        [
            "--log",
            str(demo_log_path),
            "--export",
            "none",
            "--db",
            str(db_path),
            "--no-save",
            "--quiet",
        ]
    )

    assert code == 0
    assert not db_path.exists()


def test_cli_missing_file_returns_error(tmp_path, capsys, restore_db_path):
    code = cli.main(["--log", str(tmp_path / "missing.log"), "--no-save"])

    assert code == 1
    assert "cannot read log file" in capsys.readouterr().err


def test_cli_threshold_flag(tmp_path, demo_log_path, capsys, restore_db_path):
    code = cli.main(
        [
            "--log",
            str(demo_log_path),
            "--export",
            "none",
            "--no-save",
            "--threshold",
            "100",
            "--top",
            "20",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    # threshold 100: no brute-force alerts, but web exploits still fire
    assert "SSH Brute-Force" not in out
    assert "SQL Injection" in out


def test_cli_output_is_plain_without_a_tty(tmp_path, demo_log_path, capsys, restore_db_path):
    """capsys is not a terminal, so ANSI codes must stay out of the output."""
    code = cli.main(["--log", str(demo_log_path), "--export", "none", "--no-save"])

    assert code == 0
    assert "\033[" not in capsys.readouterr().out


def test_cli_color_flag_emits_ansi(tmp_path, demo_log_path, capsys, restore_db_path):
    code = cli.main(
        ["--log", str(demo_log_path), "--export", "none", "--no-save", "--color"]
    )

    assert code == 0
    out = capsys.readouterr().out
    assert "\033[" in out
    # Badges are colored, but the readable text survives intact.
    assert "CRITICAL" in out
    assert "SSH Brute-Force" in out


def test_cli_no_color_flag_and_env_override(
    tmp_path, demo_log_path, capsys, restore_db_path, monkeypatch
):
    args = ["--log", str(demo_log_path), "--export", "none", "--no-save"]
    assert cli.main(args + ["--color"]) == 0
    assert "\033[" in capsys.readouterr().out

    assert cli.main(args + ["--no-color"]) == 0
    assert "\033[" not in capsys.readouterr().out

    monkeypatch.setenv("NO_COLOR", "1")
    assert cli.main(args + ["--color"]) == 0
    # An explicit --color still wins over the environment.
    assert "\033[" in capsys.readouterr().out


def test_cli_quiet_prints_bare_paths_even_with_color(
    tmp_path, demo_log_path, capsys, restore_db_path
):
    code = cli.main(
        [
            "--log",
            str(demo_log_path),
            "--export",
            "json",
            "--output",
            str(tmp_path),
            "--no-save",
            "--quiet",
            "--color",
        ]
    )

    assert code == 0
    out = capsys.readouterr().out
    assert "\033[" not in out, "quiet mode is consumed by scripts, never colorize it"
    assert out.strip().endswith(".json")
