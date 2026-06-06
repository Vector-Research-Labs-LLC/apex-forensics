"""Smoke test for list_network_connections against real Rocba memory image."""
import os, sys, shutil, time
sys.path.insert(0, ".")

TEST_LEDGER_DIR = "/cases/apex_ledger"
if os.path.exists(TEST_LEDGER_DIR):
    shutil.rmtree(TEST_LEDGER_DIR)

from apex_forensics import server
from apex_forensics import ledger

IMAGE = "/cases/rocba/memory/Rocba-Memory/Rocba-Memory.raw"

print("=== list_network_connections against real Rocba memory image ===")
print("  image:", IMAGE)
print()
t0 = time.time()
result = server.list_network_connections(IMAGE)
elapsed = time.time() - t0
print("  elapsed: {:.1f}s".format(elapsed))
print("  endpoint_count:    ", result["endpoint_count"])
print("  established_count: ", result["established_count"])
print("  listening_count:   ", result["listening_count"])
print("  receipt_seq:       ", result["receipt_seq"])
print("  receipt_hash:      ", result["receipt_hash"][:32] + "...")
print()

# Look for the RDP brute-force signal we saw in the baseline:
# many connection attempts to port 3389.
rdp_endpoints = [e for e in result["endpoints"] if e.get("local_port") == 3389 or e.get("foreign_port") == 3389]
print("=== RDP signal check (port 3389) ===")
print("  endpoints touching 3389:", len(rdp_endpoints))
if rdp_endpoints:
    print("  sample:")
    for e in rdp_endpoints[:5]:
        print("   ", e.get("proto"), e.get("local_addr"), ":", e.get("local_port"),
              "->", e.get("foreign_addr"), ":", e.get("foreign_port"),
              "state=", e.get("state"), "pid=", e.get("pid"))
print()

print("=== sanity checks ===")
assert result["endpoint_count"] > 0, "expected at least one endpoint"
print("  endpoint_count > 0  OK")

print()
print("=== ledger verify ===")
ok, broken_at = ledger.verify()
print("  ok={}  broken_at={}".format(ok, broken_at))
assert ok, "ledger chain should verify"
print("  PASS")

print()
print("ALL TESTS PASSED")
