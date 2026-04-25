"""
main.py – Network Monitoring Tool – CLI entry point.

Usage examples
--------------
# Analyse a PCAP file:
    python main.py --pcap samples/suspicious.pcap

# Live capture (requires root / administrator):
    python main.py --live --count 100

# Live capture on a specific interface with a BPF filter:
    python main.py --live --count 200 --iface eth0 --filter "tcp port 80"

# Decrypt log and generate report:
    python main.py --decrypt logs/traffic.enc --report reports/report.txt

# Custom key and log paths:
    python main.py --pcap samples/test.pcap --log logs/run1.enc --key mykey.key
"""

from __future__ import annotations

import compat  # noqa: F401 – must be first; patches Scapy IPv6 route issue
import argparse
import sys
from pathlib import Path

from analyzer import parse_packet
from capture import live_sniff, read_pcap
from detector import IPTracker, detect_packet, merge_results
from report import generate_report
from secure_logger import SecureLogger


# ── Core processing pipeline ──────────────────────────────────────────────

def run_capture(
    log_path: Path,
    key_path: Path,
    *,
    pcap: Path | None = None,
    live: bool = False,
    count: int = 100,
    iface: str | None = None,
    bpf_filter: str | None = None,
) -> None:
    """Shared pipeline for both PCAP-file and live-sniff modes."""

    ip_tracker = IPTracker()
    stats = {"total": 0, "suspicious": 0, "normal": 0}

    with SecureLogger(log_path, key_path) as logger:

        def handle_packet(raw_pkt) -> None:
            # 1. Parse
            record = parse_packet(raw_pkt)
            if record is None:
                return  # non-IP packet – skip

            stats["total"] += 1

            # 2. Packet-level detection
            pkt_result = detect_packet(record)

            # 3. Update IP tracker, then check behavioural flags
            src_ip = record.get("src_ip", "")
            ip_tracker.update(record)
            ip_flags = ip_tracker.check_ip(src_ip) if src_ip else []

            # 4. Merge results
            final_result = merge_results(pkt_result, ip_flags)

            if final_result["status"] == "suspicious":
                stats["suspicious"] += 1
                _print_alert(record, final_result)
            else:
                stats["normal"] += 1

            # 5. Encrypt and log
            log_entry = {"packet": record, "detection": final_result}
            logger.write(log_entry)

        # ── Dispatch to correct input source ──────────────────────────────
        if pcap:
            read_pcap(pcap, handle_packet)
        elif live:
            live_sniff(handle_packet, count=count, iface=iface, bpf_filter=bpf_filter)
        else:
            print("[main] Error: specify --pcap or --live.", file=sys.stderr)
            sys.exit(1)

    # ── Session summary ───────────────────────────────────────────────────
    print("\n" + "=" * 50)
    print("  SESSION SUMMARY")
    print("=" * 50)
    print(f"  Total packets  : {stats['total']}")
    print(f"  Normal         : {stats['normal']}")
    print(f"  Suspicious     : {stats['suspicious']}")
    print(f"  Encrypted log  : {log_path}")

    suspicious_ips = ip_tracker.get_suspicious_ips()
    if suspicious_ips:
        print("\n  Flagged IPs:")
        for ip, reasons in suspicious_ips.items():
            print(f"    {ip}  →  {', '.join(reasons)}")
    print("=" * 50)


def _print_alert(record: dict, result: dict) -> None:
    """Print a one-line alert for a suspicious packet."""
    src = record.get("src_ip", "?")
    dst = record.get("dst_ip", "?")
    dport = record.get("dst_port", "?")
    proto = record.get("protocol", "?")
    sev = result.get("severity", "?").upper()
    reasons = ", ".join(result.get("reasons", []))
    ts = record.get("timestamp", "")
    print(f"  [ALERT][{sev}] {ts}  {src} → {dst}:{dport} [{proto}]  {reasons}")


# ── CLI ───────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="network-monitor",
        description="Network Monitoring Tool – powered by Scapy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # ── Input modes (mutually exclusive) ──────────────────────────────────
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--pcap", metavar="FILE",
        help="Analyse a PCAP capture file.",
    )
    mode.add_argument(
        "--live", action="store_true",
        help="Capture packets from a live network interface.",
    )

    # ── Decrypt / report ──────────────────────────────────────────────────
    p.add_argument(
        "--decrypt", metavar="ENC_FILE",
        help="Encrypted log file to decrypt (requires --report).",
    )
    p.add_argument(
        "--report", metavar="TXT_FILE",
        default="reports/report.txt",
        help="Path to write the human-readable report (default: reports/report.txt).",
    )

    # ── Live sniff options ────────────────────────────────────────────────
    p.add_argument(
        "--count", type=int, default=100, metavar="N",
        help="Number of packets to capture in live mode (default: 100).",
    )
    p.add_argument(
        "--iface", metavar="INTERFACE",
        help="Network interface for live sniffing (default: Scapy picks).",
    )
    p.add_argument(
        "--filter", dest="bpf_filter", metavar="BPF",
        help="BPF filter string for live sniffing, e.g. 'tcp port 80'.",
    )

    # ── Paths ─────────────────────────────────────────────────────────────
    p.add_argument(
        "--log", metavar="FILE", default="logs/traffic.enc",
        help="Encrypted log output path (default: logs/traffic.enc).",
    )
    p.add_argument(
        "--key", metavar="FILE", default="key.key",
        help="Fernet key file path (default: key.key; created if absent).",
    )

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    log_path = Path(args.log)
    key_path = Path(args.key)

    # ── Mode: decrypt + report ────────────────────────────────────────────
    if args.decrypt:
        enc_path = Path(args.decrypt)
        report_path = Path(args.report)
        print(f"[main] Decrypting {enc_path} and generating report …")
        generate_report(enc_path, report_path, key_path=key_path)
        return

    # ── Mode: PCAP or live ────────────────────────────────────────────────
    if args.pcap:
        run_capture(
            log_path, key_path,
            pcap=Path(args.pcap),
        )
    elif args.live:
        run_capture(
            log_path, key_path,
            live=True,
            count=args.count,
            iface=args.iface,
            bpf_filter=args.bpf_filter,
        )
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
