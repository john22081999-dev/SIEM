import re

FAILED_LOGIN_THRESHOLD = 3
events = []
failed_login_count = {}
accepted_login_count = {}
alerts = []

with open('sample_auth.txt', 'r') as file:
    for line in file:
        if re.search(r"Invalid user", line, re.IGNORECASE):
            match = re.search(r'Invalid user ([\w\s]+) from ([\d.]+)', line, re.IGNORECASE)
            if match:
                events.append({
                    "type": "invalid_user",
                    "user": match.group(1),
                    "ip": match.group(2),
                    "time": line[:25]
                })
        elif re.search(r"Failed password", line, re.IGNORECASE):
            match = re.search(r'Failed password for ([\w\s]+) from ([\d.]+)', line, re.IGNORECASE)
            if match:
                events.append({
                    "type": "failed_password",
                    "user": match.group(1),
                    "ip": match.group(2),
                    "time": line[:25]
                })
                failed_login_count[match.group(2)] = failed_login_count.get(match.group(2), 0) + 1
                
        elif re.search(r"Accepted password", line, re.IGNORECASE):
            match = re.search(r'Accepted password for ([\w\s]+) from ([\d.]+)', line, re.IGNORECASE)
            if match:
                events.append({
                    "type": "accepted_password",
                    "user": match.group(1),
                    "ip": match.group(2),
                    "time": line[:25]
                })
                accepted_login_count[match.group(2)] = accepted_login_count.get(match.group(2), 0) + 1
        elif re.search(r"POSSIBLE BREAK-IN ATTEMPT", line, re.IGNORECASE):
            match = re.search(r'\[([\d.]+)\] failed - POSSIBLE BREAK-IN ATTEMPT', line, re.IGNORECASE)
            if match:
                events.append({
                    "type": "possible_break_in",
                    "ip": match.group(1),
                    "time": line[:25]
                })
        else:
            pass

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

print(alerts)