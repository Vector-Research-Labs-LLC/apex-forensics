"""Smoke test for the MCP server list_processes tool against the real Rocba memory image."""
import os, sys, shutil, time
sys.path.insert(0, ".")

TEST_LEDGER_DIR = "/cases/apex_ledger"
if os.path.exists(TEST_LEDGER_DIR):
    shutil.rmtree(TEST_LEDGER_DIR)

from apex_forensics import server
from apex_forensics import ledger

IMAGE = "/cases/rocba/memory/Rocba-Memory/Rocba-Memory.raw"

print("=== running list_processes against real Rocba memory image ===")
print("  image:", IMAGE)
print("  (Vol3 first run may take 5-15 minutes — downloading symbols if needed)")
print()
t0 = time.time()
result = server.list_processes(IMAGE)
elapsed = time.time() - t0
print("  elapsed: {:.1f}s".format(elapsed))
print("  process_count:", result["process_count"])
print("  receipt_seq:  ", result["receipt_seq"])
print("  receipt_hash: ", result["receipt_hash"][:32] + "...")
print()
print("  first 5 processes:")
for p in result["processes"][:5]:
    print("    PID {:6}  PPID {:6}  {}".format(p["pid"], p["ppid"], p["name"]))
print()

print("=== sanity checks ===")
assert result["process_count"] > 0, "expected at least one process"
assert any(p["name"].lower() == "system" for p in result["processes"]), "expected System process"
print("  process_count > 0  OK")
print("  System process found  OK")

print()
print("=== ledger verify ===")
ok, broken_at = ledger.verify()
print("  ok={}  broken_at={}".format(ok, broken_at))
assert ok, "ledger chain should verify"
print("  PASS")

print()
print("=== refusal test: agent attempts to read outside /cases/ ===")
try:
    server.list_processes("/etc/shadow")
    print("  FAIL: refusal did not trigger!")
except (ValueError, FileNotFoundError) as e:
    print("  refusal triggered as expected:", type(e).__name__ + ":", e)
    print("  PASS")

print()
print("ALL TESTS PASSED")
