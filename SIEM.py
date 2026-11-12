import re
from datetime import datetime
import time
import json

TIME_WINDOW_SECONDS = 60
FAILURES_IN_WINDOW = 3
FAILED_LOGIN_THRESHOLD = 3
USERNAME_ENUMERATION_THRESHOLD = 5
CHECKPOINT_FILE = "/home/akuma/SIEM/parser_checkpoint.txt"
LOG_FILE = "/var/log/lab/10.10.10.150.log"
ALERT_FILE = "/home/akuma/SIEM/alert.jsonl"


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
            if ip in accepted_login_count:
                print(
                    f"[HIGH] Successful Brute Force Attack detected from IP: {ip} with {failed_login_count[ip]} failed attempts."
                )
                alert = {
                    "severity": "HIGH",
                    "ip": ip,
                    "type": "successful_bruteforce",
                    "failed_attempts": failed_login_count[ip],
                    "timestamp": datetime.now().isoformat(),
                }
            else:
                print(
                    f"[MEDIUM] Multiple Failed Login Attempts detected from IP: {ip} with {len(failed_login_timeframe[ip])} failed attempts."
                )
                alert = {
                    "severity": "MEDIUM",
                    "ip": ip,
                    "type": "bruteforce_attempt",
                    "failed_attempts": failed_login_count[ip],
                    "timestamp": datetime.now().isoformat(),
                }
            alerted_ips.add(ip)
            log_alert(alert)


def log_alert(alert):
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")


failed_login_count = {}
failed_login_timeframe = {}
accepted_login_count = {}
alerted_ips = set()
username_attempts = {}
enumerated_ips = set()

offset = load_offset()
with open(LOG_FILE, "r") as file:
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
        elif match := re.search(
            r"\[([\d.]+)\] failed - POSSIBLE BREAK-IN ATTEMPT", line, re.IGNORECASE
        ):
            ip = match.group(1)
        offset = (
            file.tell()
        )  # Update the offset to the current position after reading the line
        save_offset(offset)  # Save the current offset to the checkpoint file
