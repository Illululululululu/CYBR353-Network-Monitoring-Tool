"""
rules.py – Detection patterns and threshold constants.
"""

# ── Regex patterns ──────────────────────────────────────────────────────────

SUSPICIOUS_PATTERNS = {
    "SQL Injection": (
        r"(?i)(union\s+select|select\s+.+from|or\s+1\s*=\s*1|drop\s+table"
        r"|insert\s+into|delete\s+from|update\s+.+set)"
    ),
    "Command Injection": (
        r"(?i)(cmd\.exe|powershell|/bin/sh|/bin/bash|whoami"
        r"|net\s+user|passwd|shadow|wget\s+http|curl\s+http)"
    ),
    "Path Traversal": (
        r"(?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini"
        r"|/proc/self|/windows/system32)"
    ),
    "PHP/Web Shell": (
        r"(?i)(<\?php|eval\s*\(|base64_decode\s*\(|shell_exec\s*\("
        r"|system\s*\(|passthru\s*\(|exec\s*\(|popen\s*\()"
    ),
    "XSS": (
        r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\("
        r"|document\.cookie|<iframe|<img\s+src\s*=)"
    ),
    "Suspicious Login": (
        r"(?i)(admin|login|password|passwd|credential|username"
        r"|Authorization:|basic\s+[a-z0-9+/=]{8,})"
    ),
}

# Ports that warrant a flag on their own
SUSPICIOUS_PORTS = {
    21,    # FTP
    23,    # Telnet
    445,   # SMB
    1433,  # MSSQL
    3306,  # MySQL
    3389,  # RDP
    4444,  # Metasploit default
    5900,  # VNC
    6666,  # IRC / RAT
    6667,
    8080,  # Alt-HTTP – flag only when combined with payload hits
    9200,  # Elasticsearch (open)
    27017, # MongoDB (open)
}

# Payload size that triggers a "large payload" flag (bytes)
LARGE_PAYLOAD_THRESHOLD = 10_000

# ── IP-behaviour thresholds ─────────────────────────────────────────────────

# Packets from one source IP before flagging high-volume
MAX_PACKETS = 200

# Unique destination ports before classifying as port-scan
MAX_PORTS = 15

# Unique destination IPs before flagging lateral movement
MAX_DEST_IPS = 20

# Repeated connection attempts to the same (dst_ip, dst_port) pair
MAX_ATTEMPTS = 10

# ── Severity mapping ────────────────────────────────────────────────────────

def compute_severity(reasons: list) -> str:
    """Map number of detection reasons → severity label."""
    n = len(reasons)
    if n == 0:
        return "none"
    elif n == 1:
        return "low"
    elif n == 2:
        return "medium"
    else:
        return "high"
