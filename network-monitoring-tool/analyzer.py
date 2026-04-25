"""
analyzer.py – Parse raw Scapy packets into structured dictionaries.
"""

from __future__ import annotations

import compat  # noqa: F401 – must precede all scapy imports
import datetime
from typing import Optional

from scapy.packet import Packet, Raw  # noqa: F401
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6


def parse_packet(pkt: Packet) -> Optional[dict]:
    """
    Convert a Scapy packet into a structured dictionary.

    Returns None for packets that carry no meaningful network information
    (e.g. pure Layer-2 frames with no IP layer).
    """
    record: dict = {}

    # ── Timestamp ─────────────────────────────────────────────────────────
    ts = getattr(pkt, "time", None)
    if ts is not None:
        record["timestamp"] = datetime.datetime.utcfromtimestamp(
            float(ts)
        ).isoformat() + "Z"
    else:
        record["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"

    # ── IP layer ──────────────────────────────────────────────────────────
    if pkt.haslayer(IP):
        ip = pkt[IP]
        record["src_ip"] = ip.src
        record["dst_ip"] = ip.dst
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        record["src_ip"] = ip6.src
        record["dst_ip"] = ip6.dst
    else:
        # No IP layer – skip
        return None

    # ── Transport layer ───────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        record["protocol"] = "TCP"
        record["src_port"] = int(tcp.sport)
        record["dst_port"] = int(tcp.dport)
        record["tcp_flags"] = _tcp_flags(tcp.flags)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        record["protocol"] = "UDP"
        record["src_port"] = int(udp.sport)
        record["dst_port"] = int(udp.dport)
    elif pkt.haslayer(ICMP):
        record["protocol"] = "ICMP"
        record["src_port"] = None
        record["dst_port"] = None
    else:
        record["protocol"] = "OTHER"
        record["src_port"] = None
        record["dst_port"] = None

    # ── Payload ───────────────────────────────────────────────────────────
    try:
        raw = bytes(pkt)
        record["payload"] = raw.decode("utf-8", errors="ignore")
    except Exception:
        record["payload"] = ""

    # ── Size ──────────────────────────────────────────────────────────────
    record["packet_size"] = len(pkt)

    return record


# ── Helpers ───────────────────────────────────────────────────────────────

def _tcp_flags(flags) -> str:
    """Return a compact flag string, e.g. 'SA', 'F', 'PA'."""
    flag_map = {
        "F": "FIN",
        "S": "SYN",
        "R": "RST",
        "P": "PSH",
        "A": "ACK",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }
    try:
        return "".join(k for k in flag_map if k in str(flags))
    except Exception:
        return str(flags)
