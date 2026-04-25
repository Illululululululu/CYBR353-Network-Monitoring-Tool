"""
test_generate.py – Generate a synthetic PCAP with a variety of attack patterns
for testing the network monitoring tool.
"""
import compat  # noqa
import os
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw
from scapy.utils import wrpcap

os.makedirs("samples", exist_ok=True)
pkts = []

# ── Normal HTTP traffic ───────────────────────────────────────────────────
for i in range(10):
    pkts.append(
        IP(src="192.168.1.1", dst="10.0.0.1") /
        TCP(sport=12000 + i, dport=80) /
        Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )

# Normal DNS (UDP)
for i in range(5):
    pkts.append(
        IP(src="192.168.1.2", dst="8.8.8.8") /
        UDP(sport=50000 + i, dport=53) /
        Raw(load=b"\x00\x01\x00\x00\x00\x01example\x03com\x00")
    )

# ── Attack payloads ───────────────────────────────────────────────────────

# SQL Injection
pkts.append(
    IP(src="192.168.1.10", dst="10.0.0.2") /
    TCP(sport=55000, dport=80) /
    Raw(load=b"GET /search?q=1+UNION+SELECT+username,password+FROM+users HTTP/1.1\r\n")
)
pkts.append(
    IP(src="192.168.1.10", dst="10.0.0.2") /
    TCP(sport=55001, dport=80) /
    Raw(load=b"POST /login HTTP/1.1\r\n\r\nuser=admin' OR 1=1--&pass=x")
)

# Command Injection
pkts.append(
    IP(src="192.168.1.10", dst="10.0.0.2") /
    TCP(sport=55002, dport=80) /
    Raw(load=b"GET /ping?host=127.0.0.1;/bin/bash+-c+whoami HTTP/1.1\r\n")
)

# Path Traversal
pkts.append(
    IP(src="192.168.1.11", dst="10.0.0.2") /
    TCP(sport=55010, dport=8080) /
    Raw(load=b"GET /../../../../etc/passwd HTTP/1.1\r\n")
)
pkts.append(
    IP(src="192.168.1.11", dst="10.0.0.2") /
    TCP(sport=55011, dport=8080) /
    Raw(load=b"GET /files?path=..%2F..%2F..%2Fetc%2Fshadow HTTP/1.1\r\n")
)

# XSS
pkts.append(
    IP(src="192.168.1.12", dst="10.0.0.3") /
    TCP(sport=55020, dport=80) /
    Raw(load=b"GET /page?name=<script>alert(document.cookie)</script> HTTP/1.1\r\n")
)

# PHP Webshell
pkts.append(
    IP(src="192.168.1.13", dst="10.0.0.4") /
    TCP(sport=55030, dport=80) /
    Raw(load=b"POST /upload.php HTTP/1.1\r\n\r\n<?php eval(base64_decode($_POST['cmd'])); ?>")
)

# Suspicious Login attempt
pkts.append(
    IP(src="192.168.1.14", dst="10.0.0.5") /
    TCP(sport=55040, dport=23) /          # Telnet
    Raw(load=b"login: admin\r\nPassword: admin123\r\n")
)

# Metasploit default listener port
pkts.append(
    IP(src="192.168.1.15", dst="10.0.0.7") /
    TCP(sport=55050, dport=4444) /
    Raw(load=b"\x90\x90\x90\x90\x90shellcode_payload\x90\x90")
)

# SMB (port 445) – potentially lateral movement
pkts.append(
    IP(src="192.168.1.20", dst="10.0.0.8") /
    TCP(sport=55060, dport=445) /
    Raw(load=b"\x00\x00\x00\x85\xffSMBr")
)

# ── Port scan: 30 SYN probes from same IP ─────────────────────────────────
for port in range(20, 52):
    pkts.append(
        IP(src="192.168.1.99", dst="10.0.0.6") /
        TCP(sport=60000, dport=port, flags="S")
    )

wrpcap("samples/test.pcap", pkts)
print(f"[test_generate] Written {len(pkts)} packets → samples/test.pcap  "
      f"({os.path.getsize('samples/test.pcap')} bytes)")
