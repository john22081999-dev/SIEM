import re
from datetime import datetime
import time
import json
import argparse

TIME_WINDOW_SECONDS = 60
FAILURES_IN_WINDOW = 3
FAILED_LOGIN_THRESHOLD = 3
USERNAME_ENUMERATION_THRESHOLD = 5
CHECKPOINT_FILE = "/home/akuma/SIEM/parser_checkpoint.txt"
ALERT_FILE = "/home/akuma/SIEM/alert.jsonl"
SCAN_THRESHOLD = 5


def load_offset():
    try:
        with open(CHECKPOINT_FILE, "r") as f:
            return int(f.read())
    except FileNotFoundError:
        return 0  # First run — start from the beginning of the log file


def save_offset(offset):
    with open(CHECKPOINT_FILE, "w") as f:
        f.write(str(offset))


def check_file_rotation(file, last_offset):
    file.seek(0, 2)  # Move the cursor to the end of the file
    current_size = file.tell()
    if current_size < last_offset:
        return True  # Log file has been rotated
    return False


def failed_attempts_within_timeframe(timestamps):
    timestamps.sort()
    for i in range(len(timestamps) - FAILURES_IN_WINDOW + 1):
        if (
            timestamps[i + FAILURES_IN_WINDOW - 1] - timestamps[i]
        ).total_seconds() <= TIME_WINDOW_SECONDS:
            return True
    return False


def check_and_alert(ip):
    if ip not in alerted_ips:
        if failed_login_count[
            ip
        ] >= FAILED_LOGIN_THRESHOLD or failed_attempts_within_timeframe(
            failed_login_timeframe[ip]
        ):
            print(
                f"[MEDIUM] Multiple Failed Login Attempts detected from IP: {ip} with {len(failed_login_timeframe[ip])} failed attempts."
            )
            alert = {
                "severity": "MEDIUM",
                "ip": ip,
                "type": "bruteforce_attempt",
                "failed_attempts": failed_login_count[ip],
                "reverse_dns_mismatch": ip
                in break_in_ips,  # True if this IP also had a reverse-DNS mismatch — combines a weak signal with a strong one for higher confidence
                "timestamp": datetime.now().isoformat(),
            }
            alerted_ips.add(ip)
            log_alert(alert)


def log_alert(alert):
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")


def check_enumeration(ip):
    if (
        len(username_attempts[ip]) >= USERNAME_ENUMERATION_THRESHOLD
        and ip not in enumerated_ips
    ):
        print(
            f"[MEDIUM] Username enumeration from IP: {ip} {len(username_attempts[ip])} distinct usernames tried"
        )
        alert = {
            "severity": "MEDIUM",
            "ip": ip,
            "type": "username_enumeration",
            "distinct_usernames": len(username_attempts[ip]),
            "timestamp": datetime.now().isoformat(),
        }
        log_alert(alert)
        enumerated_ips.add(ip)


def check_compromise(ip):
    if (
        failed_login_count.get(ip, 0) >= FAILED_LOGIN_THRESHOLD
        and ip not in compromised_ips
    ):
        print(
            f"[HIGH] Successful brute force — IP {ip} logged in after {failed_login_count[ip]} failed attempts."
        )
        alert = {
            "severity": "HIGH",
            "ip": ip,
            "type": "successful_bruteforce",
            "failed_attempts": failed_login_count[ip],
            "reverse_dns_mismatch": ip
            in break_in_ips,  # True if this IP also had a reverse-DNS mismatch — combines a weak signal with a strong one for higher confidence
            "timestamp": datetime.now().isoformat(),
        }
        log_alert(alert)
        compromised_ips.add(ip)


def check_scan(ip):
    if scan_count[ip] >= SCAN_THRESHOLD and ip not in scanned_ips:
        print(f"[LOW] Possible scan - IP {ip}")
        alert = {
            "severity": "LOW",
            "ip": ip,
            "type": "possible_scan",
            "count": scan_count[ip],
            "timestamp": datetime.now().isoformat(),
        }
        log_alert(alert)
        scanned_ips.add(ip)


failed_login_count = {}
failed_login_timeframe = {}
accepted_login_count = {}
alerted_ips = set()
username_attempts = {}
enumerated_ips = set()
compromised_ips = set()
break_in_ips = (
    set()
)  # IPs flagged by sshd for reverse-DNS mismatch; used to enrich alerts, not to alert on its own
scan_count = {}
scanned_ips = set()

parser = argparse.ArgumentParser(description="Real-time SSH brute-force SIEM")
parser.add_argument(
    "logfile",
    nargs="?",
    default="/var/log/lab/10.10.10.150.log",
    help="Path to the auth log to monitor",
)
args = parser.parse_args()

LOG_FILE = args.logfile

offset = load_offset()
with open(LOG_FILE, "r", errors='replace') as file:
    if check_file_rotation(file, offset):
        offset = 0  # Log file has been rotated, reset offset to 0
    file.seek(offset)  # Move the cursor to the last known position
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)  # Sleep briefly to avoid busy waiting
            continue
        try:
            event_time = datetime.fromisoformat(line[:25])
        except ValueError:
            continue
        if match := re.search(
            r"Invalid user ([\w\s]+) from ([\d.]+)", line, re.IGNORECASE
        ):
            ip = match.group(2)
            username = match.group(1)
            if ip not in username_attempts:
                username_attempts[ip] = set()
            username_attempts[ip].add(username)
            check_enumeration(ip)
        elif match := re.search(
            r"Failed password for ([\w\s]+) from ([\d.]+)", line, re.IGNORECASE
        ):
            ip = match.group(2)
            failed_login_count[ip] = failed_login_count.get(ip, 0) + 1
            if ip not in failed_login_timeframe:
                failed_login_timeframe[ip] = []
            failed_login_timeframe[ip].append(event_time)
            check_and_alert(ip)
        elif match := re.search(
            r"PAM (\d+) .* rhost=([\d.]+)", line
        ):  # not using IGNORECASE here because PAM logs are case-sensitive
            ip = match.group(2)
            for _ in range(int(match.group(1))):
                failed_login_count[ip] = failed_login_count.get(ip, 0) + 1
                if ip not in failed_login_timeframe:
                    failed_login_timeframe[ip] = []
                failed_login_timeframe[ip].append(event_time)
            check_and_alert(ip)
        elif match := re.search(
            r"Accepted password for ([\w\s]+) from ([\d.]+)", line, re.IGNORECASE
        ):
            ip = match.group(2)
            accepted_login_count[ip] = accepted_login_count.get(ip, 0) + 1
            check_compromise(ip)
        elif match := re.search(
            r"\[([\d.]+)\] failed - POSSIBLE BREAK-IN ATTEMPT", line, re.IGNORECASE
        ):
            ip = match.group(1)
            break_in_ips.add(ip)
        elif match := re.search(
            r"Did not receive identification string from ([\d.]+)", line
        ):
            ip = match.group(1)
            scan_count[ip] = scan_count.get(ip, 0) + 1
            check_scan(ip)
        offset = (
            file.tell()
        )  # Update the offset to the current position after reading the line
        save_offset(offset)  # Save the current offset to the checkpoint file
