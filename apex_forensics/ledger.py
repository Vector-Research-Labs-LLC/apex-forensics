"""
APEX Forensics — append-only, hash-chained provenance ledger.

Each tool invocation produces a receipt that references the previous
receipt's hash, making the log tamper-evident as a sequence. Modify any
prior receipt and every subsequent hash breaks on verify().

Public API:
    record(tool, args, raw_output, parsed_finding, confidence) -> dict
    verify() -> (ok: bool, broken_at_seq: int | None)
    open_ledger(path) -> None
"""

import sqlite3
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64

_DB_PATH = None
_RAW_DIR = None


def open_ledger(path):
    """Open or create a ledger at the given path. Creates the schema if needed."""
    global _DB_PATH, _RAW_DIR
    _DB_PATH = Path(path).resolve()
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _RAW_DIR = _DB_PATH.parent / "raw_outputs"
    _RAW_DIR.mkdir(exist_ok=True)

    with sqlite3.connect(_DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                seq               INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc            TEXT    NOT NULL,
                tool              TEXT    NOT NULL,
                args_json         TEXT    NOT NULL,
                raw_output_sha256 TEXT    NOT NULL,
                parsed_json       TEXT    NOT NULL,
                confidence        TEXT    NOT NULL,
                prev_hash         TEXT    NOT NULL,
                this_hash         TEXT    NOT NULL
            )
        """)
        conn.commit()


def _require_open():
    if _DB_PATH is None:
        raise RuntimeError("Ledger not opened. Call open_ledger(path) first.")
    return _DB_PATH


def _sha256_text(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def _compute_receipt_hash(seq, ts, tool, args_json, raw_hash, parsed_json, confidence, prev_hash):
    """Canonical hash of every other field, in fixed order. Defines the chain."""
    payload = f"{seq}|{ts}|{tool}|{args_json}|{raw_hash}|{parsed_json}|{confidence}|{prev_hash}"
    return _sha256_text(payload)


def record(tool, args, raw_output, parsed_finding, confidence):
    """
    Write one receipt to the ledger. Returns the full receipt dict.

    raw_output is stored separately in raw_outputs/<sha256>.bin so the
    ledger stays small; the receipt records only its hash.
    """
    db = _require_open()
    if confidence not in ("confirmed", "inferred", "uncertain"):
        raise ValueError(f"confidence must be confirmed|inferred|uncertain, got {confidence!r}")

    raw_bytes = raw_output.encode("utf-8") if isinstance(raw_output, str) else raw_output
    raw_hash = _sha256_bytes(raw_bytes)

    raw_path = _RAW_DIR / f"{raw_hash}.bin"
    if not raw_path.exists():
        raw_path.write_bytes(raw_bytes)

    args_json = json.dumps(args, sort_keys=True, separators=(",", ":"))
    parsed_json = json.dumps(parsed_finding, sort_keys=True, separators=(",", ":"))
    ts = datetime.now(timezone.utc).isoformat(timespec="microseconds")

    with sqlite3.connect(db) as conn:
        row = conn.execute("SELECT this_hash FROM receipts ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = row[0] if row else GENESIS_HASH

        row = conn.execute("SELECT COALESCE(MAX(seq), 0) FROM receipts").fetchone()
        next_seq = row[0] + 1

        this_hash = _compute_receipt_hash(
            next_seq, ts, tool, args_json, raw_hash, parsed_json, confidence, prev_hash
        )

        conn.execute(
            "INSERT INTO receipts (seq, ts_utc, tool, args_json, raw_output_sha256, "
            "parsed_json, confidence, prev_hash, this_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (next_seq, ts, tool, args_json, raw_hash, parsed_json, confidence, prev_hash, this_hash),
        )
        conn.commit()

    return {
        "seq": next_seq, "ts_utc": ts, "tool": tool, "args": args,
        "raw_output_sha256": raw_hash, "parsed_finding": parsed_finding,
        "confidence": confidence, "prev_hash": prev_hash, "this_hash": this_hash,
    }


def verify():
    """
    Re-walk the entire ledger and verify every hash. Returns (True, None) if
    the chain is intact, or (False, seq) at the first broken receipt.
    """
    db = _require_open()
    with sqlite3.connect(db) as conn:
        rows = conn.execute(
            "SELECT seq, ts_utc, tool, args_json, raw_output_sha256, parsed_json, "
            "confidence, prev_hash, this_hash FROM receipts ORDER BY seq ASC"
        ).fetchall()

    expected_prev = GENESIS_HASH
    for (seq, ts, tool, args_json, raw_hash, parsed_json, confidence,
         prev_hash, this_hash) in rows:
        if prev_hash != expected_prev:
            return (False, seq)
        recomputed = _compute_receipt_hash(
            seq, ts, tool, args_json, raw_hash, parsed_json, confidence, prev_hash
        )
        if recomputed != this_hash:
            return (False, seq)
        expected_prev = this_hash
    return (True, None)

