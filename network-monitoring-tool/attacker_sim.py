"""
attacker_sim.py – Sends 10 suspicious packets to localhost for live capture testing.

Run AFTER the monitor is already listening:
    sudo python3 main.py --live --count 10 --iface lo0 --filter "tcp"

Then in a second terminal:
    sudo python3 attacker_sim.py

No server needs to be running on localhost — packets are crafted and injected
directly into the network stack via Scapy raw sockets.
"""

import compat  # noqa – must be first
import time
from scapy.all import IP, TCP, send
from scapy.packet import Raw

TARGET = "127.0.0.1"

attacks = [
    {
        "name": "SQL Injection",
        "dport": 80,
        "payload": b"GET /search?q=1 UNION SELECT username,password FROM users HTTP/1.1\r\nHost: localhost\r\n\r\n",
    },
    {
        "name": "SQL Injection 2 (OR bypass)",
        "dport": 80,
        "payload": b"POST /login HTTP/1.1\r\nHost: localhost\r\n\r\nuser=admin' OR 1=1--&pass=x",
    },
    {
        "name": "Command Injection",
        "dport": 8080,
        "payload": b"GET /ping?host=127.0.0.1;/bin/bash -c whoami HTTP/1.1\r\nHost: localhost\r\n\r\n",
    },
    {
        "name": "Path Traversal (etc/passwd)",
        "dport": 80,
        "payload": b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n",
    },
    {
        "name": "Path Traversal (etc/shadow)",
        "dport": 8080,
        "payload": b"GET /files?path=../../etc/shadow HTTP/1.1\r\nHost: localhost\r\n\r\n",
    },
    {
        "name": "XSS",
        "dport": 80,
        "payload": b"GET /page?name=<script>alert(document.cookie)</script> HTTP/1.1\r\nHost: localhost\r\n\r\n",
    },
    {
        "name": "PHP Web Shell",
        "dport": 80,
        "payload": b"POST /upload.php HTTP/1.1\r\nHost: localhost\r\n\r\n<?php eval(base64_decode($_POST['cmd'])); ?>",
    },
    {
        "name": "Suspicious Login (Basic Auth)",
        "dport": 80,
        "payload": b"GET /admin HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n",
    },
    {
        "name": "Metasploit Default Port",
        "dport": 4444,
        "payload": b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n\x90\x90\x90shellcode_payload",
    },
    {
        "name": "Telnet Suspicious Port + Credential",
        "dport": 23,
        "payload": b"login: admin\r\npassword: admin123\r\n",
    },
]

print("=" * 55)
print("  attacker_sim – Sending 10 suspicious packets")
print("=" * 55)

for i, attack in enumerate(attacks, 1):
    pkt = (
        IP(src="192.168.1.99", dst=TARGET)
        / TCP(sport=50000 + i, dport=attack["dport"], flags="PA")
        / Raw(load=attack["payload"])
    )
    send(pkt, verbose=False)
    print(f"  [{i:>2}/10] Sent  →  port {attack['dport']:<5}  {attack['name']}")
    time.sleep(0.3)   # small delay so the monitor can process each one

print("=" * 55)
print("  Done. Check Terminal 1 for alerts.")
print("=" * 55)
