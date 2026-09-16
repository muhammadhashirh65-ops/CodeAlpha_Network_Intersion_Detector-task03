#!/usr/bin/env python3
"""
Generate a synthetic .pcap containing simulated attack traffic so the
custom Suricata ruleset can be demonstrated without needing a live,
real-world malicious source. All packets are crafted locally between
private RFC1918 addresses; nothing is sent over a real network.
"""

from scapy.all import (
    IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap
)

ATTACKER = "203.0.113.50"   # TEST-NET-3 (RFC 5737) - reserved for documentation
VICTIM = "192.168.1.10"     # private "home network" target

packets = []


def tcp_flow_with_data(src, dst, sport, dport, payload, resp_payload=b""):
    """Build a full TCP handshake + one data segment (+ optional response),
    so Suricata's stream engine treats it as an established flow and can
    hand the payload to the HTTP/app-layer parser."""
    isn_c = 1000
    isn_s = 5000
    pkts = []
    # 3-way handshake
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=isn_c))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=isn_s, ack=isn_c + 1))
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=isn_c + 1, ack=isn_s + 1))
    # client sends request
    pkts.append(
        IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags="PA", seq=isn_c + 1, ack=isn_s + 1)
        / Raw(load=payload)
    )
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A", seq=isn_s + 1, ack=isn_c + 1 + len(payload)))
    if resp_payload:
        pkts.append(
            IP(src=dst, dst=src)
            / TCP(sport=dport, dport=sport, flags="PA", seq=isn_s + 1, ack=isn_c + 1 + len(payload))
            / Raw(load=resp_payload)
        )
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=isn_c + 1 + len(payload), ack=isn_s + 1 + len(resp_payload)))
    return pkts

# ---------------------------------------------------------------------------
# 1. Port scan simulation: rapid SYNs to many ports (triggers sid:1000001)
# ---------------------------------------------------------------------------
for port in range(20, 45):
    pkt = IP(src=ATTACKER, dst=VICTIM) / TCP(sport=40000 + port, dport=port, flags="S")
    packets.append(pkt)

# ---------------------------------------------------------------------------
# 2. SQL Injection attempt over HTTP (triggers sid:1000010 / 1000011)
# ---------------------------------------------------------------------------
http_ok_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
http_401_resp = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"

sqli_payload = (
    b"GET /products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1\r\n"
    b"Host: shop.example\r\n"
    b"User-Agent: Mozilla/5.0\r\n\r\n"
)
packets += tcp_flow_with_data(ATTACKER, VICTIM, 51000, 80, sqli_payload, http_ok_resp)

tautology_payload = (
    b"GET /login.php?user=admin'%20OR%201%3D1--%20 HTTP/1.1\r\n"
    b"Host: shop.example\r\n\r\n"
)
packets += tcp_flow_with_data(ATTACKER, VICTIM, 51001, 80, tautology_payload, http_401_resp)

# ---------------------------------------------------------------------------
# 3. XSS attempt (triggers sid:1000012)
# ---------------------------------------------------------------------------
xss_payload = (
    b"GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1\r\n"
    b"Host: shop.example\r\n\r\n"
)
packets += tcp_flow_with_data(ATTACKER, VICTIM, 51002, 80, xss_payload, http_ok_resp)

# ---------------------------------------------------------------------------
# 4. Directory traversal (triggers sid:1000013)
# ---------------------------------------------------------------------------
traversal_payload = (
    b"GET /download?file=../../../../etc/passwd HTTP/1.1\r\n"
    b"Host: shop.example\r\n\r\n"
)
packets += tcp_flow_with_data(ATTACKER, VICTIM, 51003, 80, traversal_payload, http_ok_resp)

# ---------------------------------------------------------------------------
# 5. Plaintext password over HTTP (triggers sid:1000020)
# ---------------------------------------------------------------------------
login_body = b"username=admin&password=SuperSecret123"
login_payload = (
    b"POST /login HTTP/1.1\r\n"
    b"Host: shop.example\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Content-Length: " + str(len(login_body)).encode() + b"\r\n\r\n" + login_body
)
packets += tcp_flow_with_data(ATTACKER, VICTIM, 51004, 80, login_payload, http_ok_resp)

# A few repeated failed logins to the same login path -> feeds brute-force rule (sid:1000031)
for i in range(9):
    fail_body = f"username=admin&password=guess{i}".encode()
    fail_payload = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: shop.example\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(fail_body)).encode() + b"\r\n\r\n" + fail_body
    )
    packets += tcp_flow_with_data(ATTACKER, VICTIM, 51100 + i, 80, fail_payload, http_401_resp)

# ---------------------------------------------------------------------------
# 6. SSH brute force simulation: rapid SYNs to port 22 (triggers sid:1000030)
# ---------------------------------------------------------------------------
for i in range(15):
    pkt = IP(src=ATTACKER, dst=VICTIM) / TCP(sport=52000 + i, dport=22, flags="S")
    packets.append(pkt)

# ---------------------------------------------------------------------------
# 7. Suspicious long DNS query - possible tunneling (triggers sid:1000040)
# ---------------------------------------------------------------------------
long_label = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6aa"  # 51 chars
dns_pkt = (
    IP(src=VICTIM, dst="8.8.8.8")
    / UDP(sport=53000, dport=53)
    / DNS(rd=1, qd=DNSQR(qname=f"{long_label}.tunnel-example.net"))
)
packets.append(dns_pkt)

# ---------------------------------------------------------------------------
# 8. Reverse shell callback to a common C2 port (triggers sid:1000041)
# ---------------------------------------------------------------------------
packets += tcp_flow_with_data(VICTIM, ATTACKER, 53100, 4444, b"shell established\n")

# ---------------------------------------------------------------------------
# 9. Oversized ICMP echo request (triggers sid:1000050)
# ---------------------------------------------------------------------------
packets.append(
    IP(src=ATTACKER, dst=VICTIM) / ICMP(type=8) / Raw(load=b"A" * 1200)
)

# ---------------------------------------------------------------------------
# 10. Some normal, benign background traffic for contrast
# ---------------------------------------------------------------------------
benign_payload = b"GET /index.html HTTP/1.1\r\nHost: shop.example\r\n\r\n"
packets += tcp_flow_with_data("192.168.1.55", VICTIM, 60000, 80, benign_payload, http_ok_resp)

wrpcap("attack_traffic.pcap", packets)
print(f"Wrote {len(packets)} packets to attack_traffic.pcap")
