"""End-to-end test: run 3 tools then self_correct, verify it surfaces gaps and uncertainty."""
import os, sys, shutil
sys.path.insert(0, ".")

TEST_LEDGER_DIR = "/cases/apex_ledger"
if os.path.exists(TEST_LEDGER_DIR):
    shutil.rmtree(TEST_LEDGER_DIR)

from apex_forensics import server
from apex_forensics import ledger

IMAGE = "/cases/rocba/memory/Rocba-Memory/Rocba-Memory.raw"

print("=== running full investigation sequence ===")
print("  1/4 list_processes...")
r1 = server.list_processes(IMAGE)
print("       ", r1["process_count"], "processes,", "receipt seq", r1["receipt_seq"])

print("  2/4 list_network_connections...")
r2 = server.list_network_connections(IMAGE)
print("       ", r2["endpoint_count"], "endpoints,", r2["established_count"], "established, receipt seq", r2["receipt_seq"])

print("  3/4 find_injected_code...")
r3 = server.find_injected_code(IMAGE)
print("       ", r3["region_count"], "regions, conf=", r3["confidence_counts"], "receipt seq", r3["receipt_seq"])

print("  4/4 self_correct...")
r4 = server.self_correct(IMAGE)
print("       ", "reviewed", r4["reviewed_receipt_count"], "receipts, receipt seq", r4["receipt_seq"])
print()

print("=== uncertainty surfaced by self_correct ===")
print("  count:", len(r4["uncertainty_summary"]))
for u in r4["uncertainty_summary"][:5]:
    print("   seq", u["seq"], "(" + u["tool"] + ", " + u["confidence"] + "):", u["what"][:80])
if len(r4["uncertainty_summary"]) > 5:
    print("   ... (" + str(len(r4["uncertainty_summary"]) - 5) + " more)")
print()

print("=== coverage gaps identified ===")
print("  count:", len(r4["coverage_gaps"]))
for g in r4["coverage_gaps"]:
    print("   after seq", g["after_seq"], "(" + g["trigger_tool"] + " -> need " + g["expected"] + "):")
    print("       ", g["gap"][:100])
print()

print("=== sanity checks ===")
assert r4["reviewed_receipt_count"] == 3, "expected 3 reviewed receipts (before self_correct receipt)"
assert len(r4["coverage_gaps"]) > 0, "expected at least one coverage gap on this image"
assert len(r4["uncertainty_summary"]) > 0, "expected per-finding uncertainty (malfind regions)"
print("  reviewed_receipt_count == 3  OK")
print("  coverage_gaps > 0           OK")
print("  uncertainty_summary > 0     OK")
print()

print("=== ledger verify ===")
ok, broken_at = ledger.verify()
print("  ok=" + str(ok) + ", broken_at=" + str(broken_at))
assert ok, "ledger should verify"
print("  PASS")

print()
print("ALL TESTS PASSED")
