from __future__ import annotations

import argparse
import logging
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024
MAX_LINE_LENGTH = 8000
MAX_FINDINGS_PER_CATEGORY = 1000
ALLOWED_TEXT_LOG_RE = re.compile(r".*\.log(\.\d{1,2})?$")
DEFAULT_IGNORE_DATE = datetime.strptime("2025-02-20", "%Y-%m-%d")

SUSPICIOUS_PATTERNS = {
    "Failed SSH login": re.compile(r"Failed password for"),
    "Successful root login": re.compile(r"session opened for user root"),
    "Multiple authentication failures": re.compile(r"authentication failure"),
    "Privilege escalation (sudo)": re.compile(r"sudo:.*?user=(\S+)"),
    "Potential malware execution": re.compile(r"execve|wget|curl|nc|ncat"),
    "Unexpected shutdown or reboot": re.compile(r"shutdown|reboot"),
    "Kernel errors": re.compile(r"kernel panic|segfault|BUG:"),
}
DATE_PATTERN = re.compile(r"\b(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\b")
USER_PATTERN = re.compile(r"user(?:=| )([\w-]+)")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass(frozen=True)
class Finding:
    category: str
    log_date: str
    user: str
    ip_address: str
    filename: str
    line_num: int
    entry: str


def build_logger() -> logging.Logger:
    logger = logging.getLogger("secure_analysis_engine")
    logger.handlers.clear()
    logger.setLevel("INFO")
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(handler)
    return logger


def validate_input_directory(directory: Path) -> Path:
    resolved = directory.resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise ValueError("Input directory does not exist or is not a directory")
    return resolved


def safe_output_path(output_file: Path) -> Path:
    output_dir = output_file.parent.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    resolved = output_file.resolve()
    if output_dir not in resolved.parents and output_dir != resolved:
        raise ValueError("Refusing to write report outside output directory")
    return resolved


def is_text_log(filename: str) -> bool:
    return bool(ALLOWED_TEXT_LOG_RE.match(filename) or "Xorg" in filename)


def _parse_binary_log(filepath: Path, logger: logging.Logger) -> list[str]:
    try:
        result = subprocess.run(
            ["last", "-f", str(filepath)],
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=10,
            check=False,
        )
        if result.returncode not in (0, 1):
            logger.warning("Binary log parser returned non-standard status for %s", filepath.name)
        return result.stdout.splitlines()
    except (OSError, subprocess.TimeoutExpired):
        logger.warning("Could not parse binary log %s safely", filepath.name)
        return []


def _extract_date(line: str, ignore_date: datetime) -> str | None:
    match_date = DATE_PATTERN.search(line)
    if not match_date:
        return "Unknown"
    try:
        parsed = datetime.strptime(match_date.group(1), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return "Unknown"
    if parsed >= ignore_date:
        return None
    return str(parsed)


def _extract_user(line: str) -> str:
    match_user = USER_PATTERN.search(line)
    return match_user.group(1) if match_user else "Unknown"


def _extract_ip(line: str) -> str:
    match_ip = IP_PATTERN.search(line)
    return match_ip.group() if match_ip else "Unknown"


def analyze_logs(directory: Path, output_file: Path, ignore_date: datetime = DEFAULT_IGNORE_DATE) -> dict[str, list[Finding]]:
    logger = build_logger()
    input_dir = validate_input_directory(directory)
    report_path = safe_output_path(output_file)

    findings: dict[str, list[Finding]] = defaultdict(list)

    for filepath in sorted(input_dir.iterdir()):
        if not filepath.is_file():
            continue
        if filepath.stat().st_size > MAX_FILE_SIZE_BYTES:
            logger.warning("Skipping oversized file: %s", filepath.name)
            continue

        filename = filepath.name
        if filename in {"btmp", "wtmp", "btmp.1", "wtmp.1"}:
            for line_num, line in enumerate(_parse_binary_log(filepath, logger), 1):
                if not line or len(line) > MAX_LINE_LENGTH:
                    continue
                parts = line.split()
                user = parts[0] if len(parts) >= 1 else "Unknown"
                log_date = " ".join(parts[1:3]) if len(parts) >= 3 else "Unknown"
                findings["Login Activity"].append(
                    Finding("Login Activity", log_date, user, "Unknown", filename, line_num, line.strip())
                )
            continue

        if not is_text_log(filename):
            continue

        try:
            with filepath.open("r", encoding="utf-8", errors="ignore") as handle:
                for line_num, line in enumerate(handle, 1):
                    if "\x00" in line or len(line) > MAX_LINE_LENGTH:
                        continue

                    date_str = _extract_date(line, ignore_date)
                    if date_str is None:
                        continue
                    user = _extract_user(line)
                    ip_address = _extract_ip(line)
                    clean = line.strip()

                    for category, pattern in SUSPICIOUS_PATTERNS.items():
                        if len(findings[category]) >= MAX_FINDINGS_PER_CATEGORY:
                            continue
                        if pattern.search(clean):
                            findings[category].append(
                                Finding(category, date_str, user, ip_address, filename, line_num, clean)
                            )
        except OSError:
            logger.warning("Failed to process file safely: %s", filename)

    _write_report(report_path, findings)
    logger.info("Analysis complete. Report: %s", report_path)
    return findings


def _write_report(output_file: Path, findings: dict[str, list[Finding]]) -> None:
    with output_file.open("w", encoding="utf-8") as out:
        if not findings:
            out.write("No suspicious activity found in logs.\n")
            return
        for category, entries in findings.items():
            out.write(f"[+] Detection: {category}\n")
            out.write("=" * 100 + "\n")
            header = "{:<20} {:<15} {:<15} {:<20} {:<10} {}".format(
                "Date/Time", "User", "IP Address", "Filename", "Line Number", "Log Entry"
            )
            out.write(header + "\n")
            out.write("-" * 100 + "\n")
            for finding in entries:
                row = "{:<20} {:<15} {:<15} {:<20} {:<10} {}".format(
                    finding.log_date[:20],
                    finding.user[:14],
                    finding.ip_address[:14],
                    finding.filename[:19],
                    str(finding.line_num)[:9],
                    finding.entry,
                )
                out.write(row + "\n")
            out.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Secure Analysis Engine for defensive log review")
    parser.add_argument("--input-dir", default=".", help="Directory containing logs to inspect")
    parser.add_argument("--output", default="suspicious_activity_report.txt", help="Output report file path")
    parser.add_argument("--ignore-after", default="2025-02-20", help="Ignore entries on/after YYYY-MM-DD")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        ignore_date = datetime.strptime(args.ignore_after, "%Y-%m-%d")
        analyze_logs(Path(args.input_dir), Path(args.output), ignore_date=ignore_date)
        return 0
    except ValueError as exc:
        print(f"Input validation error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
