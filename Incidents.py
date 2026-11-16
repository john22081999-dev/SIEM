SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

class Incident:
    def __init__(self, ip, event_time):
        self.ip = ip
        self.first_seen = event_time
        self.last_seen = event_time
        self.severity = "LOW"
        self.signals = set()
        self.details = {}

    def add_signal(self, signal_type, severity, event_time, **details):
        self.signals.add(signal_type)
        self.last_seen = event_time
        if SEVERITY_RANK[severity] > SEVERITY_RANK[self.severity]:
            self.severity = severity
        self.details.update(details)

    def to_dict(self):
        return {
            "ip": self.ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "severity": self.severity,
            "signals": sorted(self.signals),
            "details": self.details,
        }