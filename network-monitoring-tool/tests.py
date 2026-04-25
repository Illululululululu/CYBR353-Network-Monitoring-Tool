"""
tests.py – Automated unit tests for the network monitoring tool.

Run with:  python3 tests.py
"""

import compat  # noqa – must be first
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


# ── helpers ───────────────────────────────────────────────────────────────

def _make_packet_record(**kwargs):
    base = {
        "timestamp": "2026-04-24T12:00:00Z",
        "src_ip": "192.168.1.1",
        "dst_ip": "10.0.0.1",
        "protocol": "TCP",
        "src_port": 12345,
        "dst_port": 80,
        "payload": "",
        "packet_size": 100,
    }
    base.update(kwargs)
    return base


# ═══════════════════════════════════════════════════════════════════════════
# rules.py
# ═══════════════════════════════════════════════════════════════════════════

class TestRules(unittest.TestCase):

    def test_compute_severity_none(self):
        from rules import compute_severity
        self.assertEqual(compute_severity([]), "none")

    def test_compute_severity_low(self):
        from rules import compute_severity
        self.assertEqual(compute_severity(["SQL Injection"]), "low")

    def test_compute_severity_medium(self):
        from rules import compute_severity
        self.assertEqual(compute_severity(["A", "B"]), "medium")

    def test_compute_severity_high(self):
        from rules import compute_severity
        self.assertEqual(compute_severity(["A", "B", "C"]), "high")

    def test_suspicious_ports_contains_telnet(self):
        from rules import SUSPICIOUS_PORTS
        self.assertIn(23, SUSPICIOUS_PORTS)

    def test_suspicious_ports_contains_metasploit(self):
        from rules import SUSPICIOUS_PORTS
        self.assertIn(4444, SUSPICIOUS_PORTS)


# ═══════════════════════════════════════════════════════════════════════════
# analyzer.py
# ═══════════════════════════════════════════════════════════════════════════

class TestAnalyzer(unittest.TestCase):

    def _make_pkt(self, src="1.2.3.4", dst="5.6.7.8", dport=80,
                  proto="TCP", payload=b"hello"):
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.packet import Raw

        ip = IP(src=src, dst=dst)
        if proto == "TCP":
            transport = TCP(sport=10000, dport=dport)
        elif proto == "UDP":
            transport = UDP(sport=10000, dport=dport)
        else:
            transport = ICMP()

        if payload:
            return ip / transport / Raw(load=payload)
        return ip / transport

    def test_parse_tcp_packet(self):
        from analyzer import parse_packet
        pkt = self._make_pkt(proto="TCP", payload=b"GET / HTTP/1.1\r\n")
        record = parse_packet(pkt)
        self.assertIsNotNone(record)
        self.assertEqual(record["src_ip"], "1.2.3.4")
        self.assertEqual(record["dst_ip"], "5.6.7.8")
        self.assertEqual(record["protocol"], "TCP")
        self.assertEqual(record["dst_port"], 80)
        self.assertIn("GET / HTTP/1.1", record["payload"])

    def test_parse_udp_packet(self):
        from analyzer import parse_packet
        pkt = self._make_pkt(proto="UDP", payload=b"DNS query")
        record = parse_packet(pkt)
        self.assertIsNotNone(record)
        self.assertEqual(record["protocol"], "UDP")

    def test_parse_icmp_packet(self):
        from analyzer import parse_packet
        pkt = self._make_pkt(proto="ICMP", payload=None)
        record = parse_packet(pkt)
        self.assertIsNotNone(record)
        self.assertEqual(record["protocol"], "ICMP")

    def test_packet_size_recorded(self):
        from analyzer import parse_packet
        pkt = self._make_pkt(payload=b"X" * 200)
        record = parse_packet(pkt)
        self.assertGreater(record["packet_size"], 0)

    def test_timestamp_present(self):
        from analyzer import parse_packet
        pkt = self._make_pkt()
        record = parse_packet(pkt)
        self.assertIn("timestamp", record)
        self.assertTrue(record["timestamp"].endswith("Z"))


# ═══════════════════════════════════════════════════════════════════════════
# detector.py
# ═══════════════════════════════════════════════════════════════════════════

class TestDetector(unittest.TestCase):

    def test_normal_packet_not_flagged(self):
        from detector import detect_packet
        record = _make_packet_record(payload="GET / HTTP/1.1\r\nHost: example.com")
        result = detect_packet(record)
        self.assertEqual(result["status"], "normal")
        self.assertEqual(result["reasons"], [])

    def test_sql_injection_detected(self):
        from detector import detect_packet
        record = _make_packet_record(payload="SELECT * FROM users UNION SELECT password FROM admin")
        result = detect_packet(record)
        self.assertEqual(result["status"], "suspicious")
        self.assertIn("SQL Injection", result["reasons"])

    def test_command_injection_detected(self):
        from detector import detect_packet
        record = _make_packet_record(payload="/bin/bash -c whoami")
        result = detect_packet(record)
        self.assertEqual(result["status"], "suspicious")
        self.assertIn("Command Injection", result["reasons"])

    def test_xss_detected(self):
        from detector import detect_packet
        record = _make_packet_record(payload="<script>alert(1)</script>")
        result = detect_packet(record)
        self.assertEqual(result["status"], "suspicious")
        self.assertIn("XSS", result["reasons"])

    def test_path_traversal_detected(self):
        from detector import detect_packet
        record = _make_packet_record(payload="GET /../../../../etc/passwd HTTP/1.1")
        result = detect_packet(record)
        self.assertIn("Path Traversal", result["reasons"])

    def test_php_webshell_detected(self):
        from detector import detect_packet
        record = _make_packet_record(payload="<?php eval(base64_decode($_POST['cmd'])); ?>")
        result = detect_packet(record)
        self.assertIn("PHP/Web Shell", result["reasons"])

    def test_suspicious_port_flagged(self):
        from detector import detect_packet
        record = _make_packet_record(dst_port=4444, payload="")
        result = detect_packet(record)
        self.assertEqual(result["status"], "suspicious")
        self.assertTrue(any("4444" in r for r in result["reasons"]))

    def test_large_payload_flagged(self):
        from detector import detect_packet
        record = _make_packet_record(payload="A" * 1000, packet_size=15000)
        result = detect_packet(record)
        self.assertIn("Large Payload", result["reasons"])

    def test_severity_increases_with_reasons(self):
        from detector import detect_packet
        # Multiple hits → higher severity
        record = _make_packet_record(
            payload="UNION SELECT * FROM users <?php system() ?> <script>alert(1)</script>",
            dst_port=4444,
            packet_size=15000,
        )
        result = detect_packet(record)
        self.assertEqual(result["severity"], "high")


class TestIPTracker(unittest.TestCase):

    def _fill_tracker(self, tracker, src_ip, n_ports=0, n_ips=0, n_packets=0):
        for i in range(n_packets):
            tracker.update(_make_packet_record(
                src_ip=src_ip, dst_ip=f"10.0.{i}.1", dst_port=80 + i
            ))
        for i in range(n_ports):
            tracker.update(_make_packet_record(src_ip=src_ip, dst_port=1000 + i))
        for i in range(n_ips):
            tracker.update(_make_packet_record(src_ip=src_ip, dst_ip=f"172.16.{i}.1"))

    def test_normal_ip_not_flagged(self):
        from detector import IPTracker
        t = IPTracker()
        t.update(_make_packet_record(src_ip="1.1.1.1"))
        self.assertEqual(t.check_ip("1.1.1.1"), [])

    def test_port_scan_detected(self):
        from detector import IPTracker
        t = IPTracker()
        for port in range(1, 30):  # 29 unique ports > MAX_PORTS (15)
            t.update(_make_packet_record(src_ip="1.1.1.1", dst_port=port))
        flags = t.check_ip("1.1.1.1")
        self.assertTrue(any("Port Scan" in f for f in flags))

    def test_high_volume_detected(self):
        from detector import IPTracker
        t = IPTracker()
        for i in range(250):  # > MAX_PACKETS (200)
            t.update(_make_packet_record(src_ip="1.1.1.1"))
        flags = t.check_ip("1.1.1.1")
        self.assertTrue(any("High Traffic Volume" in f for f in flags))

    def test_lateral_movement_detected(self):
        from detector import IPTracker
        t = IPTracker()
        for i in range(25):  # 25 unique dst IPs > MAX_DEST_IPS (20)
            t.update(_make_packet_record(src_ip="1.1.1.1", dst_ip=f"10.0.{i}.1"))
        flags = t.check_ip("1.1.1.1")
        self.assertTrue(any("Lateral Movement" in f for f in flags))

    def test_brute_force_detected(self):
        from detector import IPTracker
        t = IPTracker()
        for _ in range(15):  # 15 attempts to same (dst_ip, dst_port) > MAX_ATTEMPTS (10)
            t.update(_make_packet_record(src_ip="1.1.1.1", dst_ip="10.0.0.1", dst_port=22))
        flags = t.check_ip("1.1.1.1")
        self.assertTrue(any("Brute-Force" in f for f in flags))

    def test_get_suspicious_ips(self):
        from detector import IPTracker
        t = IPTracker()
        for port in range(1, 25):
            t.update(_make_packet_record(src_ip="evil.ip", dst_port=port))
        suspicious = t.get_suspicious_ips()
        self.assertIn("evil.ip", suspicious)


# ═══════════════════════════════════════════════════════════════════════════
# secure_logger.py
# ═══════════════════════════════════════════════════════════════════════════

class TestSecureLogger(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_write_and_decrypt(self):
        from secure_logger import SecureLogger, decrypt_log
        log_path = self.tmp / "test.enc"
        key_path = self.tmp / "test.key"

        records = [
            {"packet": {"src_ip": "1.1.1.1"}, "detection": {"status": "normal"}},
            {"packet": {"src_ip": "2.2.2.2"}, "detection": {"status": "suspicious"}},
        ]

        with SecureLogger(log_path, key_path) as logger:
            for r in records:
                logger.write(r)

        decrypted = list(decrypt_log(log_path, key_path))
        self.assertEqual(len(decrypted), 2)
        self.assertEqual(decrypted[0]["packet"]["src_ip"], "1.1.1.1")
        self.assertEqual(decrypted[1]["detection"]["status"], "suspicious")

    def test_log_is_not_plaintext(self):
        from secure_logger import SecureLogger
        log_path = self.tmp / "enc.log"
        key_path = self.tmp / "enc.key"

        with SecureLogger(log_path, key_path) as logger:
            logger.write({"secret": "do not leak this value"})

        raw = log_path.read_bytes()
        self.assertNotIn(b"do not leak this value", raw)

    def test_key_is_created_automatically(self):
        from secure_logger import SecureLogger
        key_path = self.tmp / "auto.key"
        log_path = self.tmp / "auto.enc"
        self.assertFalse(key_path.exists())
        with SecureLogger(log_path, key_path):
            pass
        self.assertTrue(key_path.exists())

    def test_missing_log_raises(self):
        from secure_logger import decrypt_log
        with self.assertRaises(FileNotFoundError):
            list(decrypt_log(self.tmp / "does_not_exist.enc",
                             self.tmp / "key.key"))

    def test_context_manager_closes_cleanly(self):
        from secure_logger import SecureLogger, decrypt_log
        log_path = self.tmp / "ctx.enc"
        key_path = self.tmp / "ctx.key"
        with SecureLogger(log_path, key_path) as logger:
            logger.write({"ok": True})
        entries = list(decrypt_log(log_path, key_path))
        self.assertEqual(len(entries), 1)


# ═══════════════════════════════════════════════════════════════════════════
# capture.py – read_pcap
# ═══════════════════════════════════════════════════════════════════════════

class TestCapture(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def _write_small_pcap(self, n=3):
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Raw
        from scapy.utils import wrpcap
        path = self.tmp / "small.pcap"
        pkts = [IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=80) / Raw(load=b"x") for _ in range(n)]
        wrpcap(str(path), pkts)
        return path

    def test_read_pcap_calls_callback(self):
        from capture import read_pcap
        path = self._write_small_pcap(4)
        seen = []
        total = read_pcap(path, lambda pkt: seen.append(pkt))
        self.assertEqual(total, 4)
        self.assertEqual(len(seen), 4)

    def test_read_pcap_missing_file_raises(self):
        from capture import read_pcap
        with self.assertRaises(FileNotFoundError):
            read_pcap(self.tmp / "no.pcap", lambda p: None)


# ═══════════════════════════════════════════════════════════════════════════
# Integration: full pipeline
# ═══════════════════════════════════════════════════════════════════════════

class TestIntegration(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def _build_pcap(self):
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Raw
        from scapy.utils import wrpcap
        path = self.tmp / "integration.pcap"
        pkts = [
            # Normal
            IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=10000, dport=80) /
            Raw(load=b"GET / HTTP/1.1\r\n"),
            # SQL injection
            IP(src="3.3.3.3", dst="2.2.2.2") / TCP(sport=10001, dport=80) /
            Raw(load=b"GET /q?id=1 UNION SELECT * FROM users HTTP/1.1\r\n"),
            # XSS
            IP(src="4.4.4.4", dst="2.2.2.2") / TCP(sport=10002, dport=80) /
            Raw(load=b"GET /s?q=<script>alert(1)</script> HTTP/1.1\r\n"),
        ]
        wrpcap(str(path), pkts)
        return path

    def test_end_to_end(self):
        from main import run_capture
        from secure_logger import decrypt_log

        pcap = self._build_pcap()
        log_path = self.tmp / "out.enc"
        key_path = self.tmp / "out.key"

        run_capture(log_path, key_path, pcap=pcap)

        entries = list(decrypt_log(log_path, key_path))
        self.assertEqual(len(entries), 3)  # all packets logged

        statuses = [e["detection"]["status"] for e in entries]
        self.assertIn("normal", statuses)
        self.assertIn("suspicious", statuses)

        reasons_flat = [r for e in entries for r in e["detection"]["reasons"]]
        self.assertIn("SQL Injection", reasons_flat)
        self.assertIn("XSS", reasons_flat)

    def test_report_generated(self):
        from main import run_capture
        from report import generate_report

        pcap = self._build_pcap()
        log_path = self.tmp / "rep.enc"
        key_path = self.tmp / "rep.key"
        report_path = self.tmp / "report.txt"

        run_capture(log_path, key_path, pcap=pcap)
        generate_report(log_path, report_path, key_path=key_path)

        self.assertTrue(report_path.exists())
        text = report_path.read_text()
        self.assertIn("NETWORK MONITORING REPORT", text)
        self.assertIn("SQL Injection", text)
        self.assertIn("XSS", text)


# ─────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Network Monitoring Tool – Test Suite")
    print("=" * 60)
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
