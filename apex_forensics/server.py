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




# --- windows.malfind parser, classifier, and tool --------------------------

# Processes commonly flagged by malfind as a false positive due to JIT.
# Lowercase comparison. The classifier downgrades these to 'uncertain'.
_JIT_PROCESS_NAMES = {
    "msmpeng.exe", "msmpengcp.exe",       # Windows Defender
    "teams.exe", "ms-teams.exe",           # Electron
    "code.exe", "discord.exe", "slack.exe",  # Electron
    "msedge.exe", "chrome.exe", "firefox.exe",  # Browsers
    "searchapp.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "applicationframehost.exe", "runtimebroker.exe",  # UWP shims
    "powershell.exe", "powershell_ise.exe",
    "devenv.exe", "dotnet.exe",            # .NET dev tooling
}


def _parse_malfind(stdout):
    """
    Parse `windows.malfind` plugin output into per-region findings.
    Vol3 emits a header row, then alternating data rows and hex dumps.
    We capture: PID, Process, Start VPN, End VPN, Tag, Protection, CommitCharge, PrivateMemory, Notes, HasMZHeader.
    """
    lines = stdout.splitlines()
    findings = []
    header_seen = False
    current = None
    for line in lines:
        if not line.strip():
            continue
        if line.startswith("Volatility") or line.startswith("Progress"):
            continue
        if not header_seen:
            if line.lstrip().startswith("PID"):
                header_seen = True
            continue
        if set(line.strip()) <= set("*-= "):
            continue

        # A data row begins with a numeric PID.
        first = line.split(None, 1)[0]
        if first.isdigit():
            if current is not None:
                findings.append(current)
            parts = line.split()
            try:
                current = {
                    "pid": int(parts[0]),
                    "process": parts[1],
                    "start_vpn": parts[2] if len(parts) > 2 else None,
                    "end_vpn": parts[3] if len(parts) > 3 else None,
                    "tag": parts[4] if len(parts) > 4 else None,
                    "protection": parts[5] if len(parts) > 5 else None,
                    "commit_charge": parts[6] if len(parts) > 6 else None,
                    "private_memory": parts[7] if len(parts) > 7 else None,
                    "notes": " ".join(parts[8:]) if len(parts) > 8 else None,
                    "has_mz_header": False,
                }
            except (ValueError, IndexError):
                current = None
            continue

        # Continuation / hex-dump lines for the current region.
        if current is None:
            continue
        stripped = line.strip()
        # Disassembly disasm lines look like '0x...:  ...'.
        # Hex-dump lines start with offset bytes; the first 2 bytes after
        # the offset will read '4d 5a' if a PE header is present.
        if " 4d 5a " in line.lower() or line.lower().lstrip().startswith("4d 5a"):
            current["has_mz_header"] = True

    if current is not None:
        findings.append(current)
    return findings


def _classify_malfind(region):
    """
    Assign per-region confidence:
      - 'uncertain' if the owning process is in the JIT/false-positive list,
      - 'inferred' otherwise (real injection still needs human confirmation),
    Returns (confidence, reason).
    """
    proc = (region.get("process") or "").lower()
    if proc in _JIT_PROCESS_NAMES:
        return ("uncertain",
                "owning process is a known JIT/Electron/Defender false-positive source")
    if region.get("has_mz_header"):
        return ("inferred",
                "RWX region contains PE header (MZ) bytes — possible reflective load")
    return ("inferred",
            "RWX region without PE header — possible shellcode, not confirmed")


@mcp.tool()
def find_injected_code(image_path):
    """
    Search a Windows memory image for potentially injected/anomalous code
    regions using Volatility 3 windows.malfind.

    Per-region findings carry an INDIVIDUAL confidence tag:
      - 'inferred'  : RWX region in a non-JIT process
      - 'uncertain' : owning process is on the known-JIT/false-positive list

    No malfind hit is automatically 'confirmed' — confirmation requires
    correlation with disk artifacts, hash/signature, and human review.

    Args:
        image_path: Absolute path to a raw memory image under /cases/.

    Returns:
        {"region_count": int, "regions": [...with per-region confidence...],
         "confidence_counts": {"inferred": N, "uncertain": M},
         "receipt_seq": int, "receipt_hash": str}
    """
    image = _validate_evidence_path(image_path)
    stdout = _run_vol_plugin(image, "windows.malfind")
    regions = _parse_malfind(stdout)
    for r in regions:
        conf, reason = _classify_malfind(r)
        r["confidence"] = conf
        r["confidence_reason"] = reason

    confidence_counts = {"inferred": 0, "uncertain": 0}
    for r in regions:
        confidence_counts[r["confidence"]] = confidence_counts.get(r["confidence"], 0) + 1

    # The tool-level receipt is recorded with the LOWEST confidence present,
    # so the ledger never overclaims at the tool level.
    overall_conf = "uncertain" if confidence_counts.get("uncertain", 0) > 0 else "inferred"

    parsed = {
        "region_count": len(regions),
        "regions": regions,
        "confidence_counts": confidence_counts,
    }

    receipt = ledger.record(
        tool="windows.malfind",
        args={"image": str(image)},
        raw_output=stdout,
        parsed_finding=parsed,
        confidence=overall_conf,
    )

    return {
        "region_count": len(regions),
        "regions": regions,
        "confidence_counts": confidence_counts,
        "receipt_seq": receipt["seq"],
        "receipt_hash": receipt["this_hash"],
    }




# --- self-correction tool (criterion 1: autonomous execution quality) ------

# Hand-authored expectation rules. Each rule is:
#   (trigger_tool, trigger_predicate, expected_followup_tool, gap_description)
# Transparent and inspectable — a senior analyst would write this list.
_COVERAGE_RULES = [
    {
        "trigger_tool": "windows.netscan",
        "trigger": lambda parsed: any(
            (e.get("local_port") == 3389 or e.get("foreign_port") == 3389)
            for e in parsed.get("endpoints", [])
        ),
        "expected_followup": "windows.sessions",
        "gap": "RDP port-3389 activity observed; logon-session enumeration "
               "(windows.sessions) is needed to determine whether any session "
               "actually authenticated. APEX has not yet wrapped windows.sessions.",
    },
    {
        "trigger_tool": "windows.netscan",
        "trigger": lambda parsed: parsed.get("established_count", 0) > 0,
        "expected_followup": "windows.netstat",
        "gap": "ESTABLISHED TCP connections present; netstat correlation "
               "(windows.netstat) recommended to confirm scanner findings "
               "against the live socket table. Not yet wrapped.",
    },
    {
        "trigger_tool": "windows.malfind",
        "trigger": lambda parsed: any(
            r.get("confidence") == "inferred"
            for r in parsed.get("regions", [])
        ),
        "expected_followup": "windows.dlllist",
        "gap": "malfind reported one or more 'inferred' (non-JIT) RWX regions; "
               "DLL enumeration on those PIDs (windows.dlllist --pid <PID>) is "
               "needed to determine loaded module set. Not yet wrapped.",
    },
    {
        "trigger_tool": "windows.pslist",
        "trigger": lambda parsed: parsed.get("process_count", 0) > 0,
        "expected_followup": "windows.pstree",
        "gap": "Process list enumerated but parent-child tree (windows.pstree) "
               "not built; orphaned processes / suspicious parents are not "
               "detectable from pslist alone. Not yet wrapped.",
    },
]


def _read_session_receipts():
    """Read all receipts from the ledger as parsed dicts."""
    import sqlite3, json
    db = ledger._require_open()
    with sqlite3.connect(db) as conn:
        rows = conn.execute(
            "SELECT seq, tool, args_json, parsed_json, confidence, this_hash "
            "FROM receipts ORDER BY seq ASC"
        ).fetchall()
    return [
        {
            "seq": seq,
            "tool": tool,
            "args": json.loads(args_json),
            "parsed": json.loads(parsed_json),
            "confidence": confidence,
            "this_hash": this_hash,
        }
        for (seq, tool, args_json, parsed_json, confidence, this_hash) in rows
    ]


@mcp.tool()
def self_correct(image_path: str) -> dict[str, Any]:
    """
    Audit the prior tool-call sequence in the ledger and emit a structured
    'gaps and next steps' meta-finding. Does NOT re-run forensic tools or
    touch the image; reads the ledger only.

    This implements the self-correction discipline: the agent reviews its
    own audit trail, identifies uncertain findings and coverage gaps, and
    writes the audit *itself* as a receipt — making meta-reasoning part
    of the chain of custody.

    Args:
        image_path: The image being investigated (recorded in the receipt
                    for traceability; not opened or analyzed).

    Returns:
        {"reviewed_receipt_count": int,
         "uncertainty_summary": [{"seq", "tool", "confidence", "what"}, ...],
         "coverage_gaps":       [{"after_seq", "trigger_tool", "expected", "gap"}, ...],
         "recommended_next_steps": [str, ...],
         "receipt_seq": int, "receipt_hash": str}
    """
    image = _validate_evidence_path(image_path)
    receipts = _read_session_receipts()

    # 1. Surface uncertainty across all prior receipts.
    uncertainty_summary = []
    for r in receipts:
        # Tool-level uncertainty
        if r["confidence"] in ("inferred", "uncertain"):
            uncertainty_summary.append({
                "seq": r["seq"],
                "tool": r["tool"],
                "confidence": r["confidence"],
                "what": "tool-level: overall finding tagged " + r["confidence"],
            })
        # Per-finding uncertainty (malfind regions, etc.)
        for region in r["parsed"].get("regions", []):
            if region.get("confidence") in ("inferred", "uncertain"):
                uncertainty_summary.append({
                    "seq": r["seq"],
                    "tool": r["tool"],
                    "confidence": region["confidence"],
                    "what": "per-finding: PID " + str(region.get("pid"))
                            + " (" + str(region.get("process")) + ") — "
                            + str(region.get("confidence_reason", "")),
                })

    # 2. Coverage gaps: rules whose trigger fired but expected followup missing.
    tools_called = {r["tool"] for r in receipts}
    coverage_gaps = []
    for rule in _COVERAGE_RULES:
        triggered = False
        trigger_seq = None
        for r in receipts:
            if r["tool"] != rule["trigger_tool"]:
                continue
            try:
                if rule["trigger"](r["parsed"]):
                    triggered = True
                    trigger_seq = r["seq"]
                    break
            except Exception:
                continue
        if triggered and rule["expected_followup"] not in tools_called:
            coverage_gaps.append({
                "after_seq": trigger_seq,
                "trigger_tool": rule["trigger_tool"],
                "expected": rule["expected_followup"],
                "gap": rule["gap"],
            })

    recommended_next_steps = [g["gap"] for g in coverage_gaps]

    parsed = {
        "reviewed_receipt_count": len(receipts),
        "uncertainty_summary": uncertainty_summary,
        "coverage_gaps": coverage_gaps,
        "recommended_next_steps": recommended_next_steps,
    }

    # The self-correction receipt is itself 'confirmed' (it is a deterministic
    # audit of the ledger), but the gaps it surfaces are not.
    receipt = ledger.record(
        tool="apex.self_correct",
        args={"image": str(image), "reviewed_seqs": [r["seq"] for r in receipts]},
        raw_output=str(parsed),
        parsed_finding=parsed,
        confidence="confirmed",
    )

    return {
        "reviewed_receipt_count": len(receipts),
        "uncertainty_summary": uncertainty_summary,
        "coverage_gaps": coverage_gaps,
        "recommended_next_steps": recommended_next_steps,
        "receipt_seq": receipt["seq"],
        "receipt_hash": receipt["this_hash"],
    }


# --- entrypoint ------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
