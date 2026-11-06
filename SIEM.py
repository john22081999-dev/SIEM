import re
from datetime import datetime
import time

TIME_WINDOW_SECONDS = 60   
FAILURES_IN_WINDOW = 3
FAILED_LOGIN_THRESHOLD = 3

def failed_attempts_within_timeframe(timestamps):
    timestamps.sort()
    for i in range(len(timestamps) - FAILURES_IN_WINDOW + 1):
        if (timestamps[i + FAILURES_IN_WINDOW - 1] - timestamps[i]).total_seconds() <= TIME_WINDOW_SECONDS:
            return True
       
    return False

def check_and_alert(ip):
    if ip not in alerted_ips:
        if failed_login_count[ip] >= FAILED_LOGIN_THRESHOLD or failed_attempts_within_timeframe(failed_login_timeframe[ip]):
            if ip in accepted_login_count:
                print(f"[HIGH] Successful Brute Force Attack detected from IP: {ip} with {failed_login_count[ip]} failed attempts.")
            else:
                print(f"[MEDIUM] Multiple Failed Login Attempts Within Timeframe detected from IP: {ip} with {len(failed_login_timeframe[ip])} failed attempts.")
            alerted_ips.add(ip)

events = []
failed_login_count = {}
failed_login_timeframe = {}
accepted_login_count = {}
alerted_ips = set()

with open('/var/log/lab/10.10.10.150.log', 'r') as file:
    file.seek(0, 2)  # Move the cursor to the end of the file
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)  # Sleep briefly to avoid busy waiting
            continue
        try:
            event_time = datetime.fromisoformat(line[:25])
        except ValueError:
            continue
        if re.search(r"Invalid user", line, re.IGNORECASE):
            match = re.search(r'Invalid user ([\w\s]+) from ([\d.]+)', line, re.IGNORECASE)
            if match:
                ip = match.group(2)
                events.append({
                    "type": "invalid_user",
                    "user": match.group(1),
                    "ip": ip,
                    "time": event_time
                })
        elif re.search(r"Failed password", line, re.IGNORECASE):
            match = re.search(r'Failed password for ([\w\s]+) from ([\d.]+)', line, re.IGNORECASE)
            if match:
                ip = match.group(2)
                events.append({
                    "type": "failed_password",
                    "user": match.group(1),
                    "ip": ip,
                    "time": event_time
                })
                failed_login_count[ip] = failed_login_count.get(ip, 0) + 1
                if ip not in failed_login_timeframe:
                    failed_login_timeframe[ip] = []
                failed_login_timeframe[ip].append(event_time)
                check_and_alert(ip)
        elif re.search(r"PAM", line): # not using IGNORECASE here because PAM logs are case-sensitive
            match = re.search(r"PAM ([\d]) .* rhost=([\d.]+)", line)
            if match:
                ip = match.group(2)
                for _ in range(int(match.group(1))):
                    events.append({
                        "type": "pam_failure",
                        "ip": ip,
                        "time": event_time
                    })
                    failed_login_count[ip] = failed_login_count.get(ip, 0) + 1
                    if ip not in failed_login_timeframe:
                        failed_login_timeframe[ip] = []
                    failed_login_timeframe[ip].append(event_time)
                check_and_alert(ip)
        elif re.search(r"Accepted password", line, re.IGNORECASE):
            match = re.search(r'Accepted password for ([\w\s]+) from ([\d.]+)', line, re.IGNORECASE)
            if match:
                ip = match.group(2)
                events.append({
                    "type": "accepted_password",
                    "user": match.group(1),
                    "ip": ip,
                    "time": event_time
                })
                accepted_login_count[ip] = accepted_login_count.get(ip, 0) + 1
        elif re.search(r"POSSIBLE BREAK-IN ATTEMPT", line, re.IGNORECASE):
            match = re.search(r'\[([\d.]+)\] failed - POSSIBLE BREAK-IN ATTEMPT', line, re.IGNORECASE)
            if match:
                ip = match.group(1)
                events.append({
                    "type": "possible_break_in",
                    "ip": ip,
                    "time": event_time
                })
   


