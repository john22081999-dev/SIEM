import re
from datetime import datetime

TIME_WINDOW_SECONDS = 60   
FAILURES_IN_WINDOW = 3
FAILED_LOGIN_THRESHOLD = 3

def failed_attempts_within_timeframe(timestamps):
    timestamps.sort()
    for i in range(len(timestamps) - FAILURES_IN_WINDOW + 1):
        if (timestamps[i + FAILURES_IN_WINDOW - 1] - timestamps[i]).total_seconds() <= TIME_WINDOW_SECONDS:
            return True
       
    return False
    
events = []
failed_login_count = {}
failed_login_timeframe = {}
accepted_login_count = {}
alerts = []

with open('/var/log/lab/10.10.10.150.log', 'r') as file:
    for line in file:
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
        
for ip, count in failed_login_count.items():
    if count >= FAILED_LOGIN_THRESHOLD:
        if ip in accepted_login_count:
            alerts.append({
                "severity": "High",
                "type": "Successful Brute Force Attack",
                "ip": ip,
                "failed_attempts": count
            })
        else:
            alerts.append({
                "severity": "Medium",
                "type": "Possible Brute Force Attack",
                "ip": ip,
                "failed_attempts": count
            })
for ip, timestamps in failed_login_timeframe.items():
    if failed_attempts_within_timeframe(timestamps):
        alerts.append({
            "severity": "Medium",
            "type": "Multiple Failed Login Attempts Within Timeframe",
            "ip": ip,
            "failed_attempts": len(timestamps)
        })
print(alerts)
