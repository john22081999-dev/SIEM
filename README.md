# Mini-SIEM — Real-Time SSH Attack Detection

A lightweight, real-time Security Information and Event Management (SIEM) tool written in Python. It tails live Linux authentication logs forwarded from a monitored host, parses them into structured security events, and raises severity-rated alerts across the stages of an SSH attack — from early-stage scanning, through username enumeration and brute-force, to a successful compromise — including attacks whose log lines have been collapsed by syslog deduplication.

Built and tested end-to-end in a self-contained home lab (attacker → target → collector), so every alert fires on real attack traffic, not synthetic samples.

---

## What it detects

| Alert | Trigger | Severity |
|-------|---------|----------|
| Possible scan / probe | ≥ N bare TCP connections to SSH that never send a protocol banner, from one IP | LOW |
| Username enumeration | ≥ N distinct usernames tried from one IP | MEDIUM |
| Brute-force attempt | ≥ N failed logins from one IP | MEDIUM |
| Brute-force burst | ≥ N failed logins from one IP within a time window | MEDIUM |
| Successful compromise | Failed logins from an IP that then logs in successfully | HIGH |

Brute-force and compromise alerts are additionally **enriched** with a `reverse_dns_mismatch` field (see *Signal correlation* below).

Thresholds (`FAILED_LOGIN_THRESHOLD`, `FAILURES_IN_WINDOW`, `TIME_WINDOW_SECONDS`, `USERNAME_ENUMERATION_THRESHOLD`, `SCAN_THRESHOLD`) are configurable constants at the top of the script.

---

## Lab architecture

The tool is developed and run inside an isolated virtualization lab:

```
                 Ubuntu 24.04 host  (KVM / libvirt, UFW firewall)
                 ├─────────────────────────────────────────────┐
   Kali VM  ─────┤ default NAT network   (internet access)      │
  (attacker)     │                                              │
       │         │ lab-isolated network  10.10.10.0/24          │
       │ attacks │   (no internet, no home-network route)       │
       ▼         │                                              │
  Metasploitable 2 ── syslog/UDP 514 ──►  rsyslog ──► /var/log/lab/10.10.10.150.log
   (target, 10.10.10.150)                     │
                                              ▼
                                        SIEM.py  (tails the live log, detects, alerts)
```

- **Host:** Ubuntu 24.04 LTS laptop running KVM/QEMU with `virt-manager`. Full-disk encryption, UFW firewall (deny inbound except SSH), managed over SSH from a separate workstation.
- **Attacker:** Kali Linux VM, on both the NAT network (for tooling/updates) and the isolated lab network.
- **Target:** Metasploitable 2, attached **only** to the isolated network — it cannot reach the internet or the home LAN (isolation verified by test). It forwards its authentication logs to the host, where the SIEM reads them.

**Why KVM over Proxmox:** the lab lives on a laptop that also needs a GUI and Wi-Fi; KVM + virt-manager gives a desktop-friendly hypervisor, while Proxmox is server-only and awkward on wireless. KVM is also the native Linux hypervisor used in production infrastructure.

---

## How it works

1. **Log forwarding.** The target's syslog daemon forwards all events over UDP to the host's `rsyslog`, which writes per-source files under `/var/log/lab/`.
2. **Resumable tailing.** On startup `SIEM.py` reads a saved **byte offset** (checkpoint) and seeks there, so it catches up on events logged while it was down instead of only seeing new ones. It then continuously reads newly appended lines (a `tail -f`–style loop). The log is opened with `errors="replace"` so a stray non-UTF-8 byte (e.g. from a scanner's binary probe) can't crash the reader.
3. **Parsing.** Each line is matched against a set of regex patterns and turned into a structured event (`possible_scan`, `invalid_user`, `failed_password`, `pam_failure`, `accepted_password`, `possible_break_in`), capturing the timestamp, source IP, and username where present. Malformed lines are skipped, not fatal.
4. **Detection.** Per-IP counters and failure timestamps are maintained as running state. After each relevant event, a dedicated `check_*` routine evaluates its thresholds (and, for brute-force, a time window) and emits a structured alert if warranted. Per-IP dedup sets (`scanned_ips`, `enumerated_ips`, `alerted_ips`, `compromised_ips`) suppress duplicate alerts for an IP already flagged.
5. **Alerting.** Every alert is printed to stdout **and** appended to a persistent JSON Lines file (see below).

---

## Alert output

Alerts are written to `alert.jsonl` in [JSON Lines](https://jsonlines.org/) format — one self-contained JSON object per line, append-friendly and trivial to parse, grep, or feed into another tool. Example:

```json
{"severity": "LOW", "ip": "10.10.10.137", "type": "possible_scan", "count": 6, "timestamp": "2026-11-12T21:21:04.512388"}
{"severity": "MEDIUM", "ip": "10.10.10.137", "type": "username_enumeration", "distinct_usernames": 5, "timestamp": "2026-11-12T21:22:10.883201"}
{"severity": "MEDIUM", "ip": "10.10.10.137", "type": "bruteforce_attempt", "failed_attempts": 3, "reverse_dns_mismatch": true, "timestamp": "2026-11-12T21:23:28.525069"}
{"severity": "HIGH", "ip": "10.10.10.137", "type": "successful_bruteforce", "failed_attempts": 3, "reverse_dns_mismatch": true, "timestamp": "2026-11-12T21:24:01.104772"}
```

---

## Design decisions & challenges

These are the real problems encountered while building the lab and tool, and how they were handled — the parts that required judgment rather than just code.

### Syslog deduplication hid attack volume
Three failed passwords within a single SSH connection produce three **identical** log lines (same source port), which syslog collapses into one line plus `last message repeated N times`. The detector only saw a single failure and never reached its threshold — an attack that produced no alert. Disabling repeated-message reduction on the collector did not help, because the *target's* legacy `sysklogd` compresses the lines **before forwarding**.

**Solution:** rather than depend on reconfiguring every log source (not realistic in the field), the tool parses the companion `PAM N more authentication failures` summary line — which is **not** collapsed and states both the count and the source IP — and recovers the hidden failures. A single collapsed connection is now counted correctly (1 visible failure + N recovered = true total). This makes the detector resilient to messy, real-world logs instead of only clean ones.

### Logs contain arbitrary bytes, not clean text
A scanner's service-detection probes (`nmap -sV`) send **binary payloads** at the port, and fragments of that garbage ended up in the forwarded log. Reading the file in text mode, Python tried to UTF-8-decode a byte like `0xee`, raised `UnicodeDecodeError`, and crashed the whole tool.

**Solution:** open the log with `errors="replace"`, which substitutes undecodable bytes with a placeholder and keeps reading. The garbage line fails the timestamp parse and is skipped harmlessly. A second concrete example of the same principle as the dedup fix: **a log parser must degrade gracefully on malformed input, never assume pristine data.**

### Signal correlation: enriching alerts instead of adding noise
Old SSH logs a `POSSIBLE BREAK-IN ATTEMPT` warning when a source's forward/reverse DNS don't match. On its own this is a **weak, noisy** signal — it fires on every connection and has many benign causes (a host with no PTR record). Alerting on it directly would bury real findings.

**Solution:** the break-in line raises **no alert of its own**. Instead, each flagged IP is recorded, and brute-force / compromise alerts carry a `reverse_dns_mismatch` field. A weak signal (suspicious DNS) combined with a strong one (brute-force) yields a **higher-confidence** detection than either alone — standard SIEM correlation, with zero added noise.

### Scan detection is log-based, and that has limits
The tool flags an IP that opens repeated bare TCP connections to SSH without sending a protocol banner — the signature of a **connect-style** probe, which completes the TCP handshake and is therefore seen (and logged) by sshd as `Did not receive identification string`. This catches recon *before* any login attempt. But a stealthy **SYN / half-open scan** never completes the handshake, so the application never sees it and nothing is logged — such scans are invisible to a log-based detector and would need packet-level visibility (firewall/IDS) to catch. The current detector also counts connections to a *single* port, whereas a classic port scan sprays *many* ports once each. Documented as a known boundary of this approach, not a bug.

### Successful-compromise detection is one-directional
Detection runs on failure events. A HIGH "successful brute-force" alert fires only if the failure threshold is already crossed when the success arrives; a success that lands *before* enough failures are recorded won't retroactively upgrade the alert. The reverse-DNS enrichment shares this ordering sensitivity (the break-in line must be seen before the alert fires to be reflected). Noted as future work.

### Over-counting errs toward detection
The PAM-recovery approximation can, in rare configurations, count a failure more than once, and it attributes all recovered failures to a single timestamp. For a *detector*, over-flagging is safer than missing an attack, so this bias is intentional and documented rather than suppressed.

---

## Limitations & future work

- **Alert correlation.** Collapse multiple detections for the same IP/incident into a single correlated alert to reduce noise.
- **Escalate on later success.** Upgrade an existing MEDIUM alert to HIGH when a flagged IP subsequently authenticates successfully (currently one-directional).
- **Downtime vs. checkpoint.** Checkpointing resumes from the saved offset, but the checkpoint is tied to one log path; pointing the tool at a *different* log reuses an offset that is meaningless for it (mitigated only when the new file is smaller, via rotation detection). A per-log checkpoint would fix this.
- **Packet-level scan detection.** Catch SYN/half-open scans and multi-port sweeps that never reach the application log.
- **More log sources & attack types.** Additional services and non-SSH sources.
- **Dashboard / alerting.** Surface the JSON alert stream in a dashboard or push notifications rather than a file plus stdout.

---

## Running it

The tool tails a forwarded authentication log on the collector. The log path can be given as an optional argument; with no argument it falls back to the lab default near the top of `SIEM.py`.

```bash
python3 SIEM.py                         # watch the lab default log
python3 SIEM.py /var/log/auth.log       # watch any other log
python3 SIEM.py --help                  # usage
```

It runs continuously and prints alerts to the terminal as attacks occur, while also appending them to `alert.jsonl`. Stop it with `Ctrl+C`; on the next run it resumes from where it left off.

For offline testing, point the script at the included sample log instead of the live path.

---

## What I practiced

- Log pipeline engineering: syslog forwarding, `rsyslog` routing, and debugging why events did not arrive (wrong config file, port typo, daemon reload vs. restart, folder permissions, message deduplication).
- Streaming log analysis in Python: live file tailing, byte-offset checkpointing and rotation detection, regex event extraction, stateful per-IP aggregation, and time-window detection with `datetime`.
- Detection engineering judgment: thresholds and their false-positive/false-negative trade-offs, deduplication-resistant counting, signal correlation (enriching strong alerts with weak corroborating signals), and reasoning about what a log-based detector can and cannot see.
- Resilient parsing: tolerating malformed and binary input without crashing.
- Structured, persistent output (JSON Lines) and a configurable CLI (`argparse`).
- Virtualization and network isolation with KVM/libvirt; verifying that a deliberately vulnerable target cannot reach the outside world.
- The offensive side that generates the telemetry: port/service scanning, service enumeration, exploiting a backdoored service, offline password cracking, and authenticating with recovered credentials — producing the exact log patterns the SIEM is built to catch.