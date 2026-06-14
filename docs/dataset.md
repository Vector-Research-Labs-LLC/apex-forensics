# Dataset Documentation

## Evidence Source

**Case:** ROCBA / Stark Research Labs intrusion
**Provenance:** SANS-authored teaching scenario (FOR500 / GCFE courseware)
**Distribution:** Provided to hackathon participants via Egnyte by Rob T. Lee (SANS CAIO, judge)

## Files Analyzed

| File | Size | Purpose |
|---|---|---|
| `rocba-cdrive.e01` | 22 GB | Windows 10 C: drive image (EWF format) |
| `Rocba-Memory.zip` | 5.3 GB | Compressed memory capture (nested: zip → 7z → raw) |
| `Rocba-Memory.raw` | 18 GB | Extracted memory image (analysis target) |

## Integrity

SHA-256 intake hashes, recorded at acquisition and re-verified post-analysis:

    rocba-cdrive.e01:  f2eb856d6fb48e3928e6b6d388b2f116a57b735137354a7eaddca951d81b5c67
    Rocba-Memory.zip:  32cec94018051f6ce20ec75f1b7b53ad2f6eb5e8bbaec7b402e30409af552b09

Recorded in `/cases/rocba/EVIDENCE-HASHES.txt`. Bytes verified unchanged across a multi-day analysis pause (May 26 → June 6, 2026).

## Scenario Summary

- **System:** Windows 10, hostname `SRL-FORGE`, single user `frocba` (Fred Rocba)
- **Capture:** 2020-11-16 ~02:32 UTC (EST5EDT timezone)
- **Timeline of events:**
  - 2020-10-24: Fred hired at Stark Research Labs
  - 2020-10-26 → 2020-11-10: WFH cloud period (O365, Dropbox, OneDrive, GDrive, iCloud)
  - 2020-11-10: Fred's vacation begins
  - 2020-11-13: Intrusion observed
  - 2020-11-16: System captured for analysis

## Known Accounts

- `frocba@stark-research-labs.com` (corporate)
- `fred.rocba@gmail.com` (personal)
- `fred.rocba@outlook.com` (personal)
- Phone: 339-223-3317

## Evaluation Questions

Per SANS-provided rubric (Slide 7 of the case briefing deck):

1. What projects did Fred have access to?
2. What was stolen?
3. Where was it transferred?
4. How was it stolen?
5. When?

APEX Forensics' calibrated scoring against these questions is in [`accuracy-report.md`](accuracy-report.md).

## Reproducibility

A reviewer can place the memory image at `/cases/rocba/memory/Rocba-Memory.raw` and reproduce every finding in this submission via `python3 tests/test_self_correct.py` from the repo root. Receipts produced will be hash-comparable to the receipts documented in the build log.

The evidence files themselves are not redistributed in this repo (provided under hackathon-specific access terms by SANS). Hashes above let any reviewer verify identical bytes if they have legitimate access.
