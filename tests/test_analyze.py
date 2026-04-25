from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from analyze import _extract_date, analyze_logs, is_text_log, resolve_cli_paths, safe_output_path, validate_input_directory


def test_validate_input_directory_rejects_missing(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        validate_input_directory(tmp_path / "missing")


def test_validate_input_directory_rejects_path_traversal(tmp_path: Path) -> None:
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(ValueError):
        validate_input_directory(base / ".." / "outside", base)


def test_safe_output_path_accepts_path(tmp_path: Path) -> None:
    out = safe_output_path(tmp_path / "report.txt")
    assert out.name == "report.txt"


def test_safe_output_path_rejects_path_traversal(tmp_path: Path) -> None:
    base = tmp_path / "reports"
    base.mkdir()
    with pytest.raises(ValueError):
        safe_output_path(Path("../report.txt"), base)


def test_resolve_cli_paths_rejects_tainted_args(tmp_path: Path) -> None:
    base = tmp_path / "base"
    base.mkdir()
    (tmp_path / "outside").mkdir()
    with pytest.raises(ValueError):
        resolve_cli_paths("../outside", "report.txt", base)


def test_is_text_log_accepts_rotated_and_xorg() -> None:
    assert is_text_log("auth.log")
    assert is_text_log("syslog.log.1")
    assert is_text_log("Xorg.0.log")
    assert not is_text_log("random.txt")


def test_extract_date_handles_bad_and_new_dates() -> None:
    parsed = _extract_date("bad timestamp here", datetime.strptime("2025-02-20", "%Y-%m-%d"))
    assert parsed == "Unknown"


def test_analyze_logs_parses_and_writes_report(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text(
        "2025-02-19 10:10:10 Failed password for invalid user admin from 10.0.0.1\n"
        "2025-02-19 10:11:10 sudo: pam_unix(sudo:session): session opened for user root by user=alice\n",
        encoding="utf-8",
    )
    out = tmp_path / "report.txt"
    findings = analyze_logs(tmp_path, out)
    assert "Failed SSH login" in findings
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "Detection: Failed SSH login" in content
    assert "10.0.0.1" in content


def test_analyze_logs_ignores_future_by_policy(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text(
        "2025-03-01 12:00:00 Failed password for invalid user root from 8.8.8.8\n",
        encoding="utf-8",
    )
    out = tmp_path / "report.txt"
    findings = analyze_logs(tmp_path, out)
    assert not findings
    assert "No suspicious activity found" in out.read_text(encoding="utf-8")

