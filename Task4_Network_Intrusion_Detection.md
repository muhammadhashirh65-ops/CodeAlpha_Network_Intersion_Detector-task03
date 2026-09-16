# Task 4: Network Intrusion Detection System

## 1. Objective

Set up a network-based intrusion detection system using Suricata, configure
rules and alerts to detect suspicious or malicious activity, monitor traffic
for potential threats, implement response mechanisms for detected intrusions,
and visualize detected attacks using a dashboard.

---

## 2. Tool Selected

| Item | Detail |
|---|---|
| **NIDS engine** | [Suricata](https://suricata.io/) 7.0.3 (open-source, signature + anomaly-based NIDS/NIPS) |
| **Why Suricata over Snort** | Native multi-threading, built-in JSON (EVE) alert output that's trivial to pipe into a dashboard or response script, and modern protocol parsers (HTTP, DNS, TLS) that make writing application-layer rules straightforward |
| **Analysis mode** | Offline pcap analysis (`suricata -r file.pcap`) — this reproduces exactly how Suricata inspects live traffic on an interface, but runs safely against locally generated sample traffic instead of a real network |

```bash
apt-get install suricata      # installs the engine + default ruleset
suricata -V                   # This is Suricata version 7.0.3 RELEASE
```

---

## 3. Configuring Rules and Alerts

A custom ruleset (`custom.rules`, 13 signatures) was written covering six
attack categories, modeled on real detection logic used in production
rulesets (e.g. Emerging Threats):

| Category | Signatures | Detection logic |
|---|---|---|
| **Reconnaissance** | Port scan, Nmap NSE user-agent | High-rate SYNs from one source (`threshold` keyword); known scanner signature string |
| **Web application attacks** | SQL injection (UNION SELECT + tautology), XSS, directory traversal | Pattern matching against the HTTP URI buffer |
| **Credential / data exposure** | Plaintext password over HTTP, anonymous FTP login | Pattern matching against the HTTP request body / FTP command |
| **Brute force** | SSH connection flood, HTTP login brute force | Rate-based thresholding on SYNs / 401 responses from one source |
| **Malware / C2** | DNS tunneling (abnormal query length), reverse-shell callback port | Regex on DNS query name; known high-risk destination ports |
| **Network abuse** | Oversized ICMP echo request | Packet size threshold on ICMP type 8 |

Each rule follows the standard Suricata/Snort rule syntax:

```
action proto src_ip src_port -> dst_ip dst_port (options)
```

Example — the SQL injection rule:

```
alert http any any -> $HOME_NET any (msg:"NIDS - Possible SQL Injection Attempt (UNION SELECT)"; \
    flow:established,to_server; http.uri; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; \
    classtype:web-application-attack; sid:1000010; rev:1;)
```

The full ruleset is in **Section 7**.

**Validation** — before ever running against traffic, the ruleset was
syntax-checked with Suricata's built-in test mode:

```bash
suricata -T -c suricata.yaml -l logs/
# Info: detect: 1 rule files processed. 13 rules successfully loaded, 0 rules failed
```

---

## 4. Monitoring Network Traffic

In a real deployment, Suricata is pointed at a live interface (or a SPAN/mirror
port) and runs continuously:

```bash
suricata -c /etc/suricata/suricata.yaml -i eth0
```

For this exercise, continuous monitoring was demonstrated safely by:

1. Generating a synthetic pcap (`attack_traffic.pcap`) containing a mix of
   attack traffic and normal background traffic between private/reserved
   test IP ranges (RFC 5737 `203.0.113.0/24` as the "attacker", a private
   `192.168.1.10` as the "victim") — see **Section 6**.
2. Running Suricata against it in offline analysis mode, which exercises the
   exact same detection engine, rule matching, and alert pipeline as live
   monitoring:

```bash
suricata -c suricata.yaml -r attack_traffic.pcap -l logs/
```

3. All findings are written continuously to `eve.json` (Suricata's
   structured JSON event log) in real time as each packet is processed —
   this is the same file a live deployment streams to, so the monitoring,
   alerting, and response pipeline below is identical whether the source is
   a pcap file or a live interface.

**Result: 20 alerts generated across all 11 distinct attack signatures.**

```
 1x  NIDS - Possible TCP Port Scan (many SYNs, low data)
 1x  NIDS - Possible SQL Injection Attempt (UNION SELECT)
 1x  NIDS - Possible SQL Injection Attempt (tautology)
 1x  NIDS - Possible XSS Attempt (script tag in URI)
 1x  NIDS - Possible Directory Traversal Attempt
10x  NIDS - Plaintext Password Submitted Over HTTP
 1x  NIDS - Possible SSH Brute Force (rapid connection attempts)
 1x  NIDS - Possible DNS Tunneling (abnormally long query name)
 2x  NIDS - Possible Reverse Shell / C2 Callback Port
 1x  NIDS - Oversized ICMP Echo Request (possible covert channel)
 1x  NIDS - Possible Web Login Brute Force
```

---

## 5. Response Mechanisms

A Python response engine (`alert_responder.py`) tails Suricata's `eve.json`
and reacts to each new alert, implementing three layered responses:

1. **Structured incident logging** — every alert is recorded with timestamp,
   source/destination, signature, severity, and the action taken, giving a
   complete audit trail (`incident_summary.json`).
2. **Escalated notification** — alerts at severity 1–2 (Suricata's
   high/medium priority) trigger a simulated on-call notification (in
   production this would be a Slack webhook, PagerDuty API call, or email).
3. **Adaptive blocking** — once a source IP crosses a configurable alert
   threshold (default: 2 alerts), the script simulates blocking it and
   prints the exact firewall command an automated response pipeline would
   execute:

```
iptables -A INPUT -s 203.0.113.50 -j DROP
```

The script only *prints* the command rather than modifying real firewall
rules — this keeps the demonstration safe to run anywhere while still
showing the exact decision logic and output a SOAR (Security Orchestration,
Automation and Response) integration would consume.

```bash
python3 alert_responder.py eve.json --summary-out incident_summary.json
```

**Result in this run:** both traffic sources (`203.0.113.50` and
`192.168.1.10`, once it started exhibiting reverse-shell/C2 behavior) crossed
the threshold and were flagged for simulated blocking after their second
alert.

The full script is in **Section 8**.

---

## 6. Visualizing Detected Attacks

An interactive HTML dashboard (`NIDS_Dashboard.html`) was built from the
`eve.json` alert data and the response engine's incident log. It is fully
self-contained (Chart.js is embedded directly in the file, so it opens and
renders with no internet connection required) and shows:

- **KPI row** — total alerts, distinct signatures triggered, distinct source
  IPs, IPs auto-blocked, high-severity count
- **Alerts by category** (horizontal bar chart) — attack type breakdown
- **Severity distribution** (doughnut chart)
- **Alert timeline** (step-line chart) — sequence and severity of alerts as
  they occurred
- **Top offending source IPs** (bar chart, blocked IPs highlighted in red)
- **Full incident log table** — every alert with the response action taken

Open `NIDS_Dashboard.html` in any browser to view it.

---

## 7. Full Custom Ruleset (`custom.rules`)

```
# =============================================================================
# custom.rules — Hand-written detection rules for Task 4: Network Intrusion
# Detection System
#
# Rule syntax: action proto src_ip src_port -> dst_ip dst_port (options)
# =============================================================================

# --- Reconnaissance / Scanning ----------------------------------------------

# Detect a classic Nmap SYN/connect scan fingerprint by user-agent-less rapid
# connection attempts is normally done via flow/threshold tracking; here we
# flag the common Nmap default TCP SYN probe pattern on many ports quickly.
alert tcp any any -> $HOME_NET any (msg:"NIDS - Possible TCP Port Scan (many SYNs, low data)"; \
    flow:stateless; flags:S; threshold:type both, track by_src, count 20, seconds 5; \
    classtype:attempted-recon; sid:1000001; rev:1;)

# Detect Nmap's default OS-fingerprint / service-probe user-agent when it
# appears in an HTTP request (Nmap's http-headers script leaves a signature).
alert http any any -> $HOME_NET any (msg:"NIDS - Nmap Scripting Engine User-Agent Detected"; \
    flow:established,to_server; http.user_agent; content:"Nmap Scripting Engine"; \
    classtype:attempted-recon; sid:1000002; rev:1;)

# --- Web Application Attacks --------------------------------------------------

# Detect a common SQL injection pattern in an HTTP request (UNION SELECT)
alert http any any -> $HOME_NET any (msg:"NIDS - Possible SQL Injection Attempt (UNION SELECT)"; \
    flow:established,to_server; http.uri; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; \
    classtype:web-application-attack; sid:1000010; rev:1;)

# Detect classic SQLi tautology pattern ' OR 1=1 (matched against the
# normalized/decoded URI buffer, since Suricata percent-decodes http.uri
# by default before content matching).
alert http any any -> $HOME_NET any (msg:"NIDS - Possible SQL Injection Attempt (tautology)"; \
    flow:established,to_server; http.uri; content:"OR 1=1"; nocase; \
    classtype:web-application-attack; sid:1000011; rev:1;)

# Detect reflected XSS payload pattern in a request
alert http any any -> $HOME_NET any (msg:"NIDS - Possible XSS Attempt (script tag in URI)"; \
    flow:established,to_server; http.uri; content:"<script"; nocase; \
    classtype:web-application-attack; sid:1000012; rev:1;)

# Detect directory traversal attempt
alert http any any -> $HOME_NET any (msg:"NIDS - Possible Directory Traversal Attempt"; \
    flow:established,to_server; http.uri; content:"../../"; \
    classtype:web-application-attack; sid:1000013; rev:1;)

# --- Credential / Sensitive Data Exposure ------------------------------------

# Detect plaintext password field submitted over unencrypted HTTP
alert http any any -> $HOME_NET any (msg:"NIDS - Plaintext Password Submitted Over HTTP"; \
    flow:established,to_server; http.request_body; content:"password="; nocase; \
    classtype:policy-violation; sid:1000020; rev:1;)

# Detect an FTP login attempt using well-known default credentials
alert tcp any any -> $HOME_NET 21 (msg:"NIDS - FTP Login Attempt With Default Credentials (anonymous)"; \
    flow:established,to_server; content:"USER anonymous"; nocase; \
    classtype:policy-violation; sid:1000021; rev:1;)

# --- Brute Force -----------------------------------------------------------

# Detect repeated failed SSH connection attempts from a single source
# (SSH is encrypted, so this keys off connection attempt frequency, not content)
alert tcp any any -> $HOME_NET 22 (msg:"NIDS - Possible SSH Brute Force (rapid connection attempts)"; \
    flow:to_server; flags:S; threshold:type both, track by_src, count 10, seconds 30; \
    classtype:attempted-admin; sid:1000030; rev:1;)

# Detect repeated HTTP 401/403 responses to the same source hitting a login path
alert http $HOME_NET any -> any any (msg:"NIDS - Possible Web Login Brute Force"; \
    flow:established,to_client; http.stat_code; content:"401"; \
    threshold:type both, track by_dst, count 8, seconds 30; \
    classtype:attempted-admin; sid:1000031; rev:1;)

# --- Malware / C2 Indicators -------------------------------------------------

# Detect a DNS query for a suspicious very-long/high-entropy-looking subdomain
# (a common DNS-tunneling / C2 beacon indicator)
alert dns any any -> any any (msg:"NIDS - Possible DNS Tunneling (abnormally long query name)"; \
    dns.query; pcre:"/^[a-z0-9]{50,}\./i"; \
    classtype:trojan-activity; sid:1000040; rev:1;)

# Detect outbound connection to a known-bad-pattern raw IP over an
# uncommon high port often used by simple reverse shells (example range).
alert tcp $HOME_NET any -> any [4444,1337,31337] (msg:"NIDS - Possible Reverse Shell / C2 Callback Port"; \
    flow:to_server,established; \
    classtype:trojan-activity; sid:1000041; rev:1;)

# --- ICMP / Network Abuse ---------------------------------------------------

# Detect an unusually large ICMP echo request (classic "ping of death" style probe / covert channel)
alert icmp any any -> $HOME_NET any (msg:"NIDS - Oversized ICMP Echo Request (possible covert channel)"; \
    itype:8; dsize:>1000; \
    classtype:attempted-dos; sid:1000050; rev:1;)
```

---

## 8. Full Response Script (`alert_responder.py`)

```python
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
```

---

## 9. How to Reproduce End-to-End

```bash
# 1. Install Suricata
apt-get install suricata

# 2. Validate the custom ruleset
suricata -T -c suricata.yaml -l logs/

# 3. Generate sample attack traffic (safe, synthetic, local-only)
python3 generate_traffic.py

# 4. Run Suricata against the traffic
suricata -c suricata.yaml -r attack_traffic.pcap -l logs/

# 5. Feed alerts through the response engine
python3 alert_responder.py logs/eve.json --summary-out logs/incident_summary.json

# 6. Open NIDS_Dashboard.html in a browser to view results
```

**Note:** `generate_traffic.py` crafts packets locally with `scapy` between
private/reserved test IP ranges — no packets are sent over a real network.
In a production deployment, Suricata would instead run continuously against
a live interface or SPAN port (`suricata -i eth0`), and the same
`alert_responder.py` script would `--follow` the live `eve.json` stream.

---

## 10. Summary

| Metric | Result |
|---|---|
| Detection signatures written | 13 |
| Attack categories covered | 6 (recon, web app attacks, credential exposure, brute force, malware/C2, network abuse) |
| Alerts generated from sample traffic | 20, across 11 distinct signatures |
| Response actions demonstrated | Structured logging, high-severity notification, adaptive IP blocking |
| Visualization | Self-contained interactive HTML dashboard (4 charts + incident table) |

This exercise mirrors a real NIDS deployment workflow end-to-end: writing and
validating detection rules, running the engine against traffic, piping
alerts through an automated response layer, and visualizing the results —
all using the same Suricata engine, rule syntax, and alert format used in
production security operations.
