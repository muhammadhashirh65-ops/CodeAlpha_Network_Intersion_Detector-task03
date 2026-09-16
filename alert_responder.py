#!/usr/bin/env python3
"""
alert_responder.py — Response mechanism for Task 4 (Network Intrusion
Detection System).

Watches Suricata's eve.json alert log and reacts to new alerts:
  - Logs a structured incident record for every alert
  - Escalates repeated offenders from the same source IP
  - Simulates blocking an offending IP once it crosses a severity/frequency
    threshold, by generating the exact firewall command that would be run
    (this script does NOT touch real firewall rules; it demonstrates the
    decision + the command an operator/automation pipeline would execute)
  - Sends a (simulated) alert notification for high-severity events

Usage:
    python3 alert_responder.py eve.json               # process a log once
    python3 alert_responder.py eve.json --follow       # tail -f style, live
"""

import argparse
import json
import sys
import time
from collections import defaultdict
from datetime import datetime

# How many alerts from the same source IP within the tracking window
# before we escalate to a simulated block.
BLOCK_THRESHOLD = 2
HIGH_SEVERITY_MAX = 2  # Suricata severity: 1 = high priority, 3 = low

offender_counts = defaultdict(int)
blocked_ips = set()
incident_log = []


def handle_alert(event):
    src_ip = event.get("src_ip", "unknown")
    dest_ip = event.get("dest_ip", "unknown")
    dest_port = event.get("dest_port", "")
    alert = event.get("alert", {})
    signature = alert.get("signature", "unknown signature")
    severity = alert.get("severity", 3)
    timestamp = event.get("timestamp", datetime.now().isoformat())

    incident = {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "signature": signature,
        "severity": severity,
        "action_taken": [],
    }

    # --- Response 1: structured incident logging -------------------------
    print(f"[ALERT] {timestamp}  src={src_ip} -> {dest_ip}:{dest_port}  "
          f"sev={severity}  \"{signature}\"")
    incident["action_taken"].append("logged")

    # --- Response 2: high-severity notification (simulated) --------------
    if severity <= HIGH_SEVERITY_MAX:
        print(f"  [NOTIFY] Would page on-call / send Slack alert: "
              f"HIGH-severity event from {src_ip} — \"{signature}\"")
        incident["action_taken"].append("notified_oncall")

    # --- Response 3: adaptive blocking after repeated offenses -----------
    offender_counts[src_ip] += 1
    if offender_counts[src_ip] >= BLOCK_THRESHOLD and src_ip not in blocked_ips:
        blocked_ips.add(src_ip)
        block_cmd = f"iptables -A INPUT -s {src_ip} -j DROP"
        print(f"  [RESPONSE] {src_ip} crossed {BLOCK_THRESHOLD} alerts — "
              f"simulated block. Command that would run:\n"
              f"      {block_cmd}")
        incident["action_taken"].append(f"blocked ({block_cmd})")
    elif src_ip in blocked_ips:
        print(f"  [RESPONSE] {src_ip} is already blocked; alert suppressed from further action.")
        incident["action_taken"].append("already_blocked")

    incident_log.append(incident)


def process_file(path):
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                handle_alert(event)


def follow_file(path):
    """Tail -f style live monitoring."""
    with open(path, "r") as f:
        f.seek(0, 2)  # go to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                event = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                handle_alert(event)


def main():
    parser = argparse.ArgumentParser(description="NIDS alert response engine")
    parser.add_argument("eve_json", help="Path to Suricata's eve.json")
    parser.add_argument("--follow", action="store_true",
                         help="Continuously watch the file for new alerts (like tail -f)")
    parser.add_argument("--summary-out", default=None,
                         help="Write a JSON incident summary to this path on exit")
    args = parser.parse_args()

    try:
        if args.follow:
            follow_file(args.eve_json)
        else:
            process_file(args.eve_json)
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n--- Summary ---")
        print(f"Total alerts processed : {len(incident_log)}")
        print(f"Distinct source IPs    : {len(offender_counts)}")
        print(f"IPs simulated-blocked  : {len(blocked_ips)} -> {sorted(blocked_ips)}")
        if args.summary_out:
            with open(args.summary_out, "w") as f:
                json.dump(incident_log, f, indent=2)
            print(f"Incident summary written to {args.summary_out}")


if __name__ == "__main__":
    main()
