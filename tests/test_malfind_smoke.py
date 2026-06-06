"""Smoke test for find_injected_code against real Rocba memory image."""
import os, sys, shutil, time
sys.path.insert(0, ".")

TEST_LEDGER_DIR = "/cases/apex_ledger"
if os.path.exists(TEST_LEDGER_DIR):
    shutil.rmtree(TEST_LEDGER_DIR)

from apex_forensics import server
from apex_forensics import ledger

IMAGE = "/cases/rocba/memory/Rocba-Memory/Rocba-Memory.raw"

print("=== find_injected_code against real Rocba memory image ===")
print("  image:", IMAGE)
print()
t0 = time.time()
result = server.find_injected_code(IMAGE)
elapsed = time.time() - t0
print("  elapsed: {:.1f}s".format(elapsed))
print("  region_count:      ", result["region_count"])
print("  confidence_counts: ", result["confidence_counts"])
print("  receipt_seq:       ", result["receipt_seq"])
print("  receipt_hash:      ", result["receipt_hash"][:32] + "...")
print()

print("=== regions found ===")
for r in result["regions"]:
    print("  PID {:6}  {:30}  prot={:20}  mz={}  conf={}".format(
        r.get("pid"),
        (r.get("process") or "")[:30],
        (r.get("protection") or "")[:20],
        r.get("has_mz_header"),
        r.get("confidence"),
    ))
    print("    reason:", r.get("confidence_reason"))
print()

print("=== classifier check: known JIT processes downgraded ===")
jit_hits = [r for r in result["regions"]
            if (r.get("process") or "").lower() in server._JIT_PROCESS_NAMES]
non_jit_hits = [r for r in result["regions"]
                if (r.get("process") or "").lower() not in server._JIT_PROCESS_NAMES]
print("  JIT-process hits:    ", len(jit_hits), "(should all be uncertain)")
print("  non-JIT-process hits:", len(non_jit_hits), "(should be inferred)")

if jit_hits:
    all_jit_uncertain = all(r["confidence"] == "uncertain" for r in jit_hits)
    print("  all JIT hits classified 'uncertain':", all_jit_uncertain)
    assert all_jit_uncertain, "JIT classifier failed"
    print("  PASS")
else:
    print("  (no JIT hits in this image; classifier not exercised here)")

if non_jit_hits:
    all_non_jit_inferred = all(r["confidence"] == "inferred" for r in non_jit_hits)
    print("  all non-JIT hits classified 'inferred':", all_non_jit_inferred)
    assert all_non_jit_inferred, "non-JIT classifier failed"
    print("  PASS")

print()
print("=== MRC.exe check (baseline said benign) ===")
mrc_hits = [r for r in result["regions"]
            if (r.get("process") or "").lower() == "mrc.exe"]
print("  MRC.exe regions flagged by malfind:", len(mrc_hits))
if mrc_hits:
    print("  APEX disagrees with baseline — MRC.exe DOES have suspicious regions")
    for r in mrc_hits:
        print("   ", r)
else:
    print("  APEX agrees with baseline — MRC.exe not flagged by malfind")
print()

print("=== ledger verify ===")
ok, broken_at = ledger.verify()
print("  ok={}  broken_at={}".format(ok, broken_at))
assert ok, "ledger chain should verify"
print("  PASS")

print()
print("ALL TESTS PASSED")
