"""
detector.py – Two-stage detection engine.

Stage 1: Packet-level regex + port checks (stateless).
Stage 2: IP-level behavioural analysis (stateful, maintained per run).
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional

from rules import (
    SUSPICIOUS_PATTERNS,
    SUSPICIOUS_PORTS,
    LARGE_PAYLOAD_THRESHOLD,
    MAX_PACKETS,
    MAX_PORTS,
    MAX_DEST_IPS,
    MAX_ATTEMPTS,
    compute_severity,
)

# ── Compiled regex cache ──────────────────────────────────────────────────

_COMPILED: dict[str, re.Pattern] = {
    name: re.compile(pattern)
    for name, pattern in SUSPICIOUS_PATTERNS.items()
}


# ── Stage 1: packet-level detection ──────────────────────────────────────

def detect_packet(record: dict) -> dict:
    """
    Inspect a single parsed packet record for suspicious content.

    Returns a result dict:
        {
            "status": "normal" | "suspicious",
            "severity": "none" | "low" | "medium" | "high",
            "reasons": [...]
        }
    """
    reasons: list[str] = []
    payload: str = record.get("payload", "")

    # 1. Regex pattern matching
    for name, pattern in _COMPILED.items():
        if pattern.search(payload):
            reasons.append(name)

    # 2. Large payload
    if record.get("packet_size", 0) > LARGE_PAYLOAD_THRESHOLD:
        reasons.append("Large Payload")

    # 3. Suspicious destination port
    dst_port = record.get("dst_port")
    if dst_port and dst_port in SUSPICIOUS_PORTS:
        reasons.append(f"Suspicious Port ({dst_port})")

    status = "suspicious" if reasons else "normal"
    return {
        "status": status,
        "severity": compute_severity(reasons),
        "reasons": reasons,
    }


# ── Stage 2: IP-level behavioural tracker ────────────────────────────────

class IPTracker:
    """
    Maintain per-source-IP statistics across a capture session and expose
    a method to check whether a given IP should be flagged.
    """

    def __init__(self) -> None:
        # ip → { packet_count, dest_ports, dest_ips, connection_attempts }
        self._stats: dict[str, dict] = defaultdict(lambda: {
            "packet_count": 0,
            "dest_ports": set(),
            "dest_ips": set(),
            "connection_attempts": defaultdict(int),
        })

    # ── Public API ────────────────────────────────────────────────────────

    def update(self, record: dict) -> None:
        """Register one packet record into the tracker."""
        src = record.get("src_ip")
        if not src:
            return

        s = self._stats[src]
        s["packet_count"] += 1

        dst_ip = record.get("dst_ip")
        dst_port = record.get("dst_port")

        if dst_ip:
            s["dest_ips"].add(dst_ip)
        if dst_port:
            s["dest_ports"].add(dst_port)
        if dst_ip and dst_port:
            s["connection_attempts"][(dst_ip, dst_port)] += 1

    def check_ip(self, src_ip: str) -> list[str]:
        """
        Return a (possibly empty) list of behavioural flags for *src_ip*.
        Called after update() has been applied for the packet in question.
        """
        if src_ip not in self._stats:
            return []

        s = self._stats[src_ip]
        flags: list[str] = []

        if s["packet_count"] > MAX_PACKETS:
            flags.append(f"High Traffic Volume ({s['packet_count']} pkts)")

        if len(s["dest_ports"]) > MAX_PORTS:
            flags.append(f"Port Scan ({len(s['dest_ports'])} ports)")

        if len(s["dest_ips"]) > MAX_DEST_IPS:
            flags.append(f"Lateral Movement ({len(s['dest_ips'])} IPs)")

        max_attempts = max(
            (cnt for cnt in s["connection_attempts"].values()),
            default=0,
        )
        if max_attempts > MAX_ATTEMPTS:
            flags.append(f"Brute-Force / Repeated Attempts ({max_attempts}x)")

        return flags

    def get_suspicious_ips(self) -> dict[str, list[str]]:
        """Return {ip: [reasons]} for every IP that has at least one flag."""
        result = {}
        for ip in self._stats:
            flags = self.check_ip(ip)
            if flags:
                result[ip] = flags
        return result

    def stats_for(self, src_ip: str) -> Optional[dict]:
        """Return raw stats dict for an IP (for reporting)."""
        return self._stats.get(src_ip)


# ── Combined: merge packet + IP results ──────────────────────────────────

def merge_results(pkt_result: dict, ip_flags: list[str]) -> dict:
    """
    Combine packet-level and IP-level detection into a single result dict.
    """
    all_reasons = pkt_result["reasons"] + ip_flags
    status = "suspicious" if all_reasons else "normal"
    return {
        "status": status,
        "severity": compute_severity(all_reasons),
        "reasons": all_reasons,
    }
