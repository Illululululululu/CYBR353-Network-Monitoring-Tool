"""
report.py – Generate a human-readable network monitoring report.

Reads decrypted log entries and produces a text summary.
"""

from __future__ import annotations

import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

from secure_logger import decrypt_log

# Maximum sample packets to print in the report
MAX_SAMPLES = 10


def generate_report(
    log_path: str | Path,
    report_path: str | Path,
    key_path: Path = Path("key.key"),
) -> None:
    """
    Read *log_path*, compute statistics, write a report to *report_path*,
    and also print a summary to stdout.
    """
    log_path = Path(log_path)
    report_path = Path(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    # ── Collect stats ─────────────────────────────────────────────────────
    total = 0
    normal = 0
    suspicious_count = 0
    reason_counter: Counter = Counter()
    suspicious_ips: dict[str, set] = defaultdict(set)
    samples: list[dict] = []

    for entry in decrypt_log(log_path, key_path):
        total += 1
        result = entry.get("detection", {})
        status = result.get("status", "normal")

        if status == "suspicious":
            suspicious_count += 1
            reasons = result.get("reasons", [])
            reason_counter.update(reasons)
            src_ip = entry.get("packet", {}).get("src_ip", "unknown")
            for reason in reasons:
                suspicious_ips[src_ip].add(reason)
            if len(samples) < MAX_SAMPLES:
                samples.append(entry)
        else:
            normal += 1

    # ── Build report text ─────────────────────────────────────────────────
    lines: list[str] = []
    _h = lines.append  # shorthand

    _h("=" * 60)
    _h("         NETWORK MONITORING REPORT")
    _h("=" * 60)
    _h("")
    _h(f"  Total packets analysed : {total}")
    _h(f"  Normal                 : {normal}")
    _h(f"  Suspicious             : {suspicious_count}")
    _h("")

    # Suspicious IPs
    _h("-" * 60)
    _h("  SUSPICIOUS SOURCE IPs")
    _h("-" * 60)
    if suspicious_ips:
        for ip, reasons in sorted(suspicious_ips.items()):
            _h(f"  {ip}")
            # Collapse repeated "Port Scan (N ports)" labels into one summary
            scan_counts = [r for r in reasons if r.startswith("Port Scan (")]
            other = [r for r in reasons if not r.startswith("Port Scan (")]
            deduplicated = sorted(set(other))
            if scan_counts:
                # Pick the highest port count seen
                max_scan = max(scan_counts, key=lambda s: int(s.split("(")[1].split()[0]))
                deduplicated.append(max_scan)
            for r in deduplicated:
                _h(f"      → {r}")
    else:
        _h("  None detected.")
    _h("")

    # Top reasons
    _h("-" * 60)
    _h("  TOP DETECTION REASONS")
    _h("-" * 60)
    if reason_counter:
        for reason, count in reason_counter.most_common(10):
            _h(f"  {count:>5}x  {reason}")
    else:
        _h("  No suspicious activity detected.")
    _h("")

    # Sample suspicious packets
    _h("-" * 60)
    _h(f"  SAMPLE SUSPICIOUS PACKETS (up to {MAX_SAMPLES})")
    _h("-" * 60)
    if samples:
        for i, entry in enumerate(samples, 1):
            pkt = entry.get("packet", {})
            det = entry.get("detection", {})
            src = pkt.get("src_ip", "?")
            dst = pkt.get("dst_ip", "?")
            dport = pkt.get("dst_port", "?")
            proto = pkt.get("protocol", "?")
            severity = det.get("severity", "?")
            reasons = ", ".join(det.get("reasons", []))
            ts = pkt.get("timestamp", "")
            _h(f"  [{i}] {ts}")
            _h(f"       {src} → {dst}:{dport}  [{proto}]  severity={severity}")
            _h(f"       Reasons: {reasons}")
            _h("")
    else:
        _h("  No suspicious packets to display.")

    _h("=" * 60)
    _h("  END OF REPORT")
    _h("=" * 60)

    report_text = "\n".join(lines)

    # ── Write to file ─────────────────────────────────────────────────────
    report_path.write_text(report_text, encoding="utf-8")
    print(report_text)
    print(f"\n[report] Saved to {report_path}")
