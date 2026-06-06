"""
APEX Forensics — read-only MCP server (Volatility 3 backend).

Exposes typed, read-only forensic tools to AI agents over the Model
Context Protocol. The agent CANNOT issue raw shell commands here; the
only available operations are the typed functions decorated with @mcp.tool().

Every tool invocation produces a tamper-evident ledger receipt: the
input args, the SHA-256 of the raw tool output, the parsed finding,
and a confidence tag, hash-chained to the previous receipt.
"""

import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from apex_forensics import ledger

# --- configuration ---------------------------------------------------------

# Read-only fence: the server will refuse to operate on any path outside
# this root. This is architectural, not advisory.
EVIDENCE_ROOT = Path("/cases").resolve()

# Where the ledger lives for this server instance.
LEDGER_PATH = Path("/cases/apex_ledger/ledger.db")

# Vol3 binary path (resolved at startup).
VOL_BIN = os.environ.get("APEX_VOL_BIN", "/home/sansforensics/.local/bin/vol")

# Per-tool subprocess timeout (seconds). Vol plugins can take minutes on
# a large memory image; do not set this too low.
TOOL_TIMEOUT_SEC = 1800  # 30 minutes


# --- server instance -------------------------------------------------------

mcp = FastMCP("apex-forensics")
ledger.open_ledger(LEDGER_PATH)


# --- helpers ---------------------------------------------------------------

def _validate_evidence_path(path_str: str) -> Path:
    """
    Resolve and verify an evidence file path. Refuses paths outside
    EVIDENCE_ROOT or that do not exist. This is the architectural
    spoliation guard: the agent cannot ask us to read /etc/shadow.
    """
    p = Path(path_str).resolve()
    if not str(p).startswith(str(EVIDENCE_ROOT) + os.sep):
        raise ValueError(
            f"Refused: path {p} is outside the evidence root {EVIDENCE_ROOT}."
        )
    if not p.is_file():
        raise FileNotFoundError(f"Refused: path {p} does not exist or is not a file.")
    return p


def _run_vol_plugin(image: Path, plugin: str) -> str:
    """
    Run a Volatility 3 plugin against an image and return its stdout.
    Raises on nonzero exit or timeout. Read-only by construction:
    we only invoke plugins, never execute arbitrary shell.
    """
    cmd = [VOL_BIN, "-q", "-f", str(image), plugin]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=TOOL_TIMEOUT_SEC,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"vol3 plugin {plugin!r} failed (exit {proc.returncode}): "
            f"{proc.stderr[:500]}"
        )
    return proc.stdout


def _parse_pslist(stdout: str) -> list[dict[str, Any]]:
    """
    Parse `windows.pslist` plugin output into a list of process dicts.
    Vol3 default output is a fixed-width table; we split on whitespace
    after the header row.
    """
    lines = stdout.splitlines()
    rows: list[dict[str, Any]] = []
    header_seen = False
    for line in lines:
        if not line.strip():
            continue
        if line.startswith("Volatility") or line.startswith("Progress"):
            continue
        # The header row begins with "PID" (Vol3 windows.pslist).
        if not header_seen:
            if line.lstrip().startswith("PID"):
                header_seen = True
            continue
        # Skip the separator row of asterisks/dashes, if present.
        if set(line.strip()) <= set("*-= "):
            continue
        parts = line.split(maxsplit=8)
        if len(parts) < 6:
            continue
        try:
            rows.append({
                "pid": int(parts[0]),
                "ppid": int(parts[1]),
                "name": parts[2],
                "offset": parts[3],
                "threads": int(parts[4]) if parts[4].isdigit() else None,
                "handles": parts[5] if len(parts) > 5 else None,
                "start_time": parts[7] if len(parts) > 7 else None,
            })
        except (ValueError, IndexError):
            continue
    return rows


# --- tools (the only operations the agent can perform) --------------------

@mcp.tool()
def list_processes(image_path: str) -> dict[str, Any]:
    """
    List processes in a Windows memory image using Volatility 3's
    windows.pslist plugin.

    Args:
        image_path: Absolute path to a raw memory image under /cases/.

    Returns:
        {"process_count": int, "processes": [{pid, ppid, name, ...}, ...],
         "receipt_seq": int, "receipt_hash": str}
    """
    image = _validate_evidence_path(image_path)
    stdout = _run_vol_plugin(image, "windows.pslist")
    processes = _parse_pslist(stdout)
    parsed = {"process_count": len(processes), "processes": processes}

    receipt = ledger.record(
        tool="windows.pslist",
        args={"image": str(image)},
        raw_output=stdout,
        parsed_finding=parsed,
        confidence="confirmed",
    )

    return {
        "process_count": len(processes),
        "processes": processes,
        "receipt_seq": receipt["seq"],
        "receipt_hash": receipt["this_hash"],
    }




# --- windows.netscan parser and tool ---------------------------------------

def _parse_netscan(stdout: str) -> list[dict[str, Any]]:
    """
    Parse `windows.netscan` plugin output into a list of network endpoint dicts.
    Columns (Vol3): Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created.
    Lines with empty/dash values are normalized to None.
    """
    lines = stdout.splitlines()
    rows: list[dict[str, Any]] = []
    header_seen = False
    for line in lines:
        if not line.strip():
            continue
        if line.startswith("Volatility") or line.startswith("Progress"):
            continue
        if not header_seen:
            if line.lstrip().startswith("Offset"):
                header_seen = True
            continue
        if set(line.strip()) <= set("*-= "):
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            def _opt(v):
                return None if v in ("-", "*", "") else v
            def _opt_int(v):
                try:
                    return int(v)
                except (ValueError, TypeError):
                    return None
            rows.append({
                "offset": parts[0],
                "proto": parts[1],
                "local_addr": _opt(parts[2]),
                "local_port": _opt_int(parts[3]),
                "foreign_addr": _opt(parts[4]) if len(parts) > 4 else None,
                "foreign_port": _opt_int(parts[5]) if len(parts) > 5 else None,
                "state": _opt(parts[6]) if len(parts) > 6 else None,
                "pid": _opt_int(parts[7]) if len(parts) > 7 else None,
                "owner": parts[8] if len(parts) > 8 else None,
            })
        except (ValueError, IndexError):
            continue
    return rows


@mcp.tool()
def list_network_connections(image_path: str) -> dict[str, Any]:
    """
Enumerate network endpoints and connections from a Windows memory image
    using Volatility 3 windows.netscan. Returns sockets, listening ports,
    and established/closed TCP connections.

    Args:
        image_path: Absolute path to a raw memory image under /cases/.

    Returns:
        {"endpoint_count": int, "endpoints": [{proto, local_addr, local_port,
         foreign_addr, foreign_port, state, pid, owner, ...}, ...],
         "established_count": int, "listening_count": int,
         "receipt_seq": int, "receipt_hash": str}
    """
    image = _validate_evidence_path(image_path)
    stdout = _run_vol_plugin(image, "windows.netscan")
    endpoints = _parse_netscan(stdout)

    established = sum(1 for e in endpoints if (e.get("state") or "").upper() == "ESTABLISHED")
    listening = sum(1 for e in endpoints if (e.get("state") or "").upper() == "LISTENING")

    parsed = {
        "endpoint_count": len(endpoints),
        "established_count": established,
        "listening_count": listening,
        "endpoints": endpoints,
    }

    receipt = ledger.record(
        tool="windows.netscan",
        args={"image": str(image)},
        raw_output=stdout,
        parsed_finding=parsed,
        confidence="confirmed",
    )

    return {
        "endpoint_count": len(endpoints),
        "established_count": established,
        "listening_count": listening,
        "endpoints": endpoints,
        "receipt_seq": receipt["seq"],
        "receipt_hash": receipt["this_hash"],
    }


# --- entrypoint ------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
