"""
capture.py – Input layer: PCAP file reading and live sniffing.

Both modes normalise their output into the same callback interface:
    callback(packet)   ← raw Scapy packet
"""

from __future__ import annotations

import compat  # noqa: F401 – must precede all scapy imports
from pathlib import Path
from typing import Callable

from scapy.all import rdpcap, sniff
from scapy.packet import Packet


# ── PCAP file mode ────────────────────────────────────────────────────────

def read_pcap(
    path: str | Path,
    callback: Callable[[Packet], None],
) -> int:
    """
    Read all packets from *path* and call *callback* for each one.

    Returns the total number of packets read.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    print(f"[capture] Reading PCAP: {path}")
    packets = rdpcap(str(path))
    total = len(packets)
    print(f"[capture] {total} packets loaded.")

    for pkt in packets:
        callback(pkt)

    return total


# ── Live sniffing mode ────────────────────────────────────────────────────

def live_sniff(
    callback: Callable[[Packet], None],
    count: int = 100,
    iface: str | None = None,
    bpf_filter: str | None = None,
) -> int:
    """
    Sniff *count* packets from the network and call *callback* for each one.

    Parameters
    ----------
    callback    : function to call with each captured packet
    count       : number of packets to capture (0 = unlimited until Ctrl-C)
    iface       : network interface to sniff on (None = Scapy default)
    bpf_filter  : optional BPF filter string, e.g. "tcp port 80"

    Returns the number of packets captured.
    """
    kwargs: dict = {"prn": callback, "store": False}
    if count:
        kwargs["count"] = count
    if iface:
        kwargs["iface"] = iface
    if bpf_filter:
        kwargs["filter"] = bpf_filter

    iface_label = iface or "default"
    print(f"[capture] Live sniffing on interface '{iface_label}'"
          f" (count={count or '∞'}"
          + (f", filter='{bpf_filter}'" if bpf_filter else "")
          + ") …  Press Ctrl-C to stop.")

    captured = sniff(**kwargs)
    total = len(captured) if captured else count
    print(f"[capture] Capture finished. Packets processed: {total}")
    return total
