import os
import re
import subprocess
from datetime import datetime
from collections import defaultdict

def parse_binary_log(filepath):
    """
    Parses binary logs like btmp and wtmp using the `last` command.
    """
    try:
        result = subprocess.run(["last", "-f", filepath], capture_output=True, text=True, errors='ignore')
        return result.stdout.splitlines()
    except Exception as e:
        print(f"Error reading binary log {filepath}: {e}")
        return []

def analyze_logs(directory, output_file):
    suspicious_patterns = {
        "Failed SSH login": re.compile(r"Failed password for"),
        "Successful root login": re.compile(r"session opened for user root"),
        "Multiple authentication failures": re.compile(r"authentication failure"),
        "Privilege escalation (sudo)": re.compile(r"sudo:.*?user=(\S+)"),
        "Potential malware execution": re.compile(r"execve|wget|curl|nc|ncat"),
        "Unexpected shutdown or reboot": re.compile(r"shutdown|reboot"),
        "Kernel errors": re.compile(r"kernel panic|segfault|BUG:"),
    }
    
    date_pattern = re.compile(r'\b(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\b')
    user_pattern = re.compile(r'user(?:=| )([\w-]+)')
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    categorized_findings = defaultdict(list)
    ignore_date = datetime.strptime("2025-02-20", "%Y-%m-%d")

    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)

        if os.path.isfile(filepath):
            if filename in ["btmp", "wtmp", "btmp.1", "wtmp.1"]:
                binary_logs = parse_binary_log(filepath)
                for line_num, line in enumerate(binary_logs, 1):
                    parts = line.split()
                    if len(parts) >= 3:
                        user = parts[0]
                        log_date = " ".join(parts[1:3])
                    else:
                        user = "Unknown"
                        log_date = "Unknown"
                    categorized_findings["Login Activity"].append((log_date, user, "Unknown", filename, line_num, line))
                continue

            elif re.match(r'.*\.log(\.\d{1,2})?$', filename) or "Xorg" in filename:
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                        lines = file.readlines()

                    for line_num, line in enumerate(lines, 1):
                        if "\x00" in line:
                            continue

                        match_date = date_pattern.search(line)
                        if match_date:
                            log_date = datetime.strptime(match_date.group(1), "%Y-%m-%d %H:%M:%S")
                            if log_date >= ignore_date:
                                continue
                        else:
                            log_date = "Unknown"

                        match_user = user_pattern.search(line)
                        user = match_user.group(1) if match_user else "Unknown"

                        match_ip = ip_pattern.search(line)
                        ip = match_ip.group() if match_ip else "Unknown"

                        for pattern_name, pattern in suspicious_patterns.items():
                            if pattern.search(line):
                                categorized_findings[pattern_name].append((log_date, user, ip, filename, line_num, line.strip()))

                except Exception as e:
                    print(f"Error processing {filename}: {e}")

    with open(output_file, 'w', encoding='utf-8') as output:
        if categorized_findings:
            for category, entries in categorized_findings.items():
                output.write(f"[+] Detection: {category}\n")
                output.write("=" * 100 + "\n")
                header = "{:<20} {:<15} {:<15} {:<20} {:<10} {}".format(
                    "Date/Time", "User", "IP Address", "Filename", "Line Number", "Log Entry"
                )
                output.write(header + "\n")
                output.write("-" * 100 + "\n")
                for detection in entries:
                    log_entry = "{:<20} {:<15} {:<15} {:<20} {:<10} {}".format(
                        str(detection[0]), detection[1][:14], detection[2][:14], detection[3][:19], str(detection[4])[:9], detection[5]
                    )
                    output.write(log_entry + "\n")
                output.write("\n")
        else:
            output.write("No suspicious activity found in logs.\n")

if __name__ == "__main__":
    log_directory = os.getcwd()
    output_file = "suspicious_activity_report.txt"
    analyze_logs(log_directory, output_file)
    print(f"Analysis complete. Check the report: {output_file}")
