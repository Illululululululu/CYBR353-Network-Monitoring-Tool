"""
secure_logger.py – Encrypt packet analysis results to disk and decrypt them.

Each log entry is stored as one Base64-encoded Fernet token per line.
The encryption key is stored in key.key next to the log file by default.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterator

from cryptography.fernet import Fernet


# ── Key management ────────────────────────────────────────────────────────

DEFAULT_KEY_PATH = Path("key.key")


def load_or_create_key(key_path: Path = DEFAULT_KEY_PATH) -> bytes:
    """Load an existing Fernet key or create and save a fresh one."""
    if key_path.exists():
        return key_path.read_bytes()
    key = Fernet.generate_key()
    key_path.write_bytes(key)
    print(f"[secure_logger] New encryption key saved to: {key_path}")
    return key


def get_fernet(key_path: Path = DEFAULT_KEY_PATH) -> Fernet:
    return Fernet(load_or_create_key(key_path))


# ── SecureLogger ──────────────────────────────────────────────────────────


class SecureLogger:
    """
    Append-only encrypted log writer.

    Usage::

        logger = SecureLogger("logs/traffic.enc")
        logger.write(record_dict)   # called for every analysed packet
        logger.close()              # flush & close (or use as context manager)
    """

    def __init__(
        self,
        log_path: str | Path,
        key_path: Path = DEFAULT_KEY_PATH,
    ) -> None:
        self._log_path = Path(log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._fernet = get_fernet(key_path)
        self._fh = self._log_path.open("ab")

    # ── Context-manager support ───────────────────────────────────────────

    def __enter__(self) -> "SecureLogger":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ── Write ─────────────────────────────────────────────────────────────

    def write(self, record: dict) -> None:
        """Serialize *record* to JSON, encrypt it, and append one line."""
        json_bytes = json.dumps(record, default=str).encode("utf-8")
        token = self._fernet.encrypt(json_bytes)
        self._fh.write(token + b"\n")

    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        self._fh.flush()
        self._fh.close()


# ── Decryption ────────────────────────────────────────────────────────────


def decrypt_log(
    log_path: str | Path,
    key_path: Path = DEFAULT_KEY_PATH,
) -> Iterator[dict]:
    """
    Yield decrypted log entries (dicts) from *log_path* one at a time.

    Skips blank lines and lines that fail to decrypt/parse.
    """
    fernet = get_fernet(key_path)
    log_path = Path(log_path)

    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    with log_path.open("rb") as fh:
        for lineno, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                decrypted = fernet.decrypt(line)
                entry = json.loads(decrypted.decode("utf-8"))
                yield entry
            except Exception as exc:
                print(
                    f"[secure_logger] Warning – could not decrypt line {lineno}: {exc}"
                )
