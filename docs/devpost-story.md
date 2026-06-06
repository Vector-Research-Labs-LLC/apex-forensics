# APEX Forensics — Devpost Project Story

*Drafted to map directly onto Devpost's standard project_details sections. Paste each section into its corresponding field.*

---

## Inspiration

SANS' Protocol SIFT is impressive: an AI agent that can drive a forensic workstation through natural language, automating triage steps a junior analyst would do manually. But the project's own README carries a quiet, devastating disclaimer:

> "Protocol SIFT is not validated for forensic soundness or evidentiary reliability."

That single sentence is the gap. Forensic work is not just *finding* the right answer; it is being able to *prove* — to opposing counsel, to a court, to a senior investigator reviewing the case three years later — that the evidence was not modified, that the reasoning is reproducible, and that the confidence levels were honest. An AI agent that can do the work but cannot stand behind it is not yet a forensic tool. It is an assistant.

APEX Forensics is the architectural attempt to close that gap. Not by being smarter than Protocol SIFT, but by *constraining* the agent to a surface where soundness is enforced — not promised.

The thesis: **read-only enforcement should be architectural, not prompted. Audit trails should be cryptographic, not narrative. Confidence should be per-finding, not per-tool. And the agent should audit its own work.**

---

## What it does

APEX Forensics wraps Volatility 3 behind a small read-only MCP (Model Context Protocol) server with four typed tools:

- `list_processes` (windows.pslist) — process enumeration
- `list_network_connections` (windows.netscan) — sockets and connections
- `find_injected_code` (windows.malfind) — RWX regions with per-region confidence
- `self_correct` — reads the prior ledger, surfaces uncertainty and coverage gaps, writes its own receipt

An AI agent (Claude Code) connects to the server via MCP and can call only those four functions. There is no general shell. There is no file write. The agent cannot request operations outside the evidence directory. The function signatures are the *complete* surface.

Every tool invocation produces a SQLite receipt: input arguments, SHA-256 of the raw tool output, the parsed finding, a confidence tag (`confirmed | inferred | uncertain`), and the hash of the previous receipt. Receipts form a tamper-evident chain. A six-line Python verifier can re-walk the chain in three seconds and prove either that the audit is intact or that exactly which receipt was modified.

The agent investigates by chaining the typed tools, narrating its findings in plain English, and surfacing the receipt sequence and hash in its responses. When prompted to audit itself, the `self_correct` tool reads back the ledger, identifies uncertainty in prior findings, and emits a structured "gaps and next steps" document — for example, "RDP port-3389 activity was observed, but `windows.sessions` enumeration was not performed; logon-session analysis is needed to determine whether any attempt actually authenticated." That gaps document is itself a receipt. Meta-reasoning is part of the chain of custody.

The result: AI-assisted forensic triage where every claim is backed by a cryptographically-linked receipt, every uncertainty is named, and the architecture enforces the discipline that policy alone could not.

---

## How we built it

A single-author build over twelve days, with three multi-day pauses for federal proposal work in parallel.

**The platform:** SIFT Workstation 2024 imported into VirtualBox on Windows. Protocol SIFT installed for baseline comparison. Claude Code authenticated and connected. A working `/cases/rocba/` evidence directory was staged with the SANS-authored ROCBA scenario evidence (22 GB disk image + 18 GB memory image), SHA-256 hashed on intake and re-verified across the multi-day pause.

**Baseline run:** unmodified Protocol SIFT was run against the memory image first to establish what the unconstrained agent could (and could not) do. It correctly identified an active RDP brute-force from two foreign IPs, correctly dismissed a vintage application (MRC.exe) as benign, and — significantly — contradicted itself within a single run on whether the brute-force had succeeded, first claiming high confidence in authentication then high confidence against. The reliability gap was demonstrated live, in the same session. This is the gap APEX is built to close.

**The architecture, ~600 lines of Python in two files:**

- `apex_forensics/ledger.py` (~145 lines, stdlib only — sqlite3 + hashlib + json) implements the hash-chained ledger. Each receipt's `this_hash` is SHA-256 of the canonical encoding of every other field plus the previous receipt's `this_hash`. The genesis hash is 64 zeros. Raw outputs are content-addressed into a `raw_outputs/` directory so the ledger stays small while the underlying evidence remains addressable.

- `apex_forensics/server.py` (~480 lines) uses FastMCP to expose the four typed tools. The path validator (`_validate_evidence_path`) refuses anything outside `/cases/` at the function boundary, raising `ValueError` — verified live against `/etc/shadow`. The `find_injected_code` tool ships with a transparent JIT-process classifier that auto-downgrades known false-positive sources (MsMpEng, SearchApp, Teams, etc.) to `uncertain`. The `self_correct` tool reads the ledger and applies a hand-authored coverage-rule table — transparent, inspectable, easy for a senior analyst to read.

**Wiring:** a small `pyproject.toml` makes the package editable-installable, an `apex_forensics/__main__.py` launches the server via `python3 -m apex_forensics`, and a project-local `.mcp.json` lets Claude Code auto-discover the server when launched from the repo directory. Tested end-to-end: Claude Code connects, lists the four tools, invokes them with permission, produces receipts, and surfaces receipt hashes in its natural-language responses.

**Validation:** every component has a smoke test against the real 18 GB memory image. Pslist found 2,186 processes with the canonical Windows boot chain present. Netscan re-detected the RDP brute-force with exact precision (124 attempts versus the baseline's "118+"), same attacker IPs, same owning PID. Malfind correctly classified 12 hits in known JIT processes as `uncertain` and correctly did not flag MRC.exe. `self_correct` surfaced four coverage gaps and 57 uncertainty entries across the prior receipts. Ledger `verify()` returned `True` after every run.

---

## Challenges I ran into

**Editor friction on SIFT.** The SIFT Workstation ships without `nano` or `gedit`. Using `vim` for code paste captured `:set paste` *into* the file in INSERT mode (typed as text rather than executed as a vim command), leaving a junk first line. Bash heredocs fragmented on long multi-line pastes. Resolved by writing files via `python3 << 'PYEOF'` inline. Lesson: don't fight the editor; use the language runtime.

**Bracketed-paste sequences bled from vim into bash** after paste sessions, corrupting every subsequent paste with `^[[200~` markers. Resolved with `bind 'set enable-bracketed-paste off'`. A small thing, but it cost an hour and is worth documenting for the next person on a forensic VM.

**The malfind parser overcounts.** The text-based parser misreads hex-dump rows that follow real findings, producing phantom entries like `PID 48 name="89"` (where `48 89` is actually two hex bytes from a disassembly continuation). Real findings (~15-20 regions in MsMpEng, SearchApp, Teams, etc.) are correctly identified and confidence-tagged. The bug overcounts but does not corrupt the architectural argument: every phantom finding is traceable to its source via the raw-output stash, which is exactly the audit-trail value APEX delivers. The bug is itself a story for the value of receipts — it is *catchable* in a way that opaque AI errors are not. Fix path documented: switch to Vol3's `--renderer=json` for structured output.

**The agent's narrative voice was hard to predict.** When Claude Code first called `find_injected_code` and reported its findings, it spontaneously narrated: "These are plausible injection targets but require disk-artifact correlation, hash/signature checks, and human review before being called confirmed — consistent with the tool's policy that no malfind hit is auto-confirmed." The tool's confidence vocabulary had become part of the agent's reasoning. That was a stronger outcome than I would have predicted — and a useful demonstration that architecting the *tool surface* shapes the agent's *reasoning*, not just its actions.

---

## Accomplishments I'm proud of

**The integrity proof is three seconds long.** A judge — or a reviewing senior analyst, or opposing counsel — can verify the entire audit trail of an APEX session with one six-line Python invocation that returns either `True` or the exact sequence number where the chain broke. The proof is not in the architecture diagram; it is in the math, reproducible by anyone.

**Spoliation guard is architectural.** Demonstrated live: `list_processes("/etc/shadow")` raises `ValueError` at the function boundary, not because the LLM was asked nicely. The agent literally cannot invoke what the server does not expose.

**The self-correction discipline is encoded.** The agent does not get to hide what it didn't check. `self_correct` reads the ledger, identifies uncertainty across prior receipts, names coverage gaps via a transparent rule table, and writes the audit *itself* as a receipt. Meta-reasoning is part of the chain of custody.

**The accuracy report is calibrated.** APEX answers 2 of the 5 ROCBA evaluation questions strongly, 1 partially, and *correctly identifies the other 2 as out of memory-only scope*. The discipline that prevents spoliation also prevents overclaim. Calibrated honesty is a competitive feature, not a hedge.

---

## What I learned

**Architectural enforcement is dramatically more credible than prompt-based guardrails.** When the function signature is the surface, the agent has no degrees of freedom to be talked around. This pattern generalizes far beyond forensics.

**Hash-chained provenance is cheaper than I expected.** The entire ledger module is ~145 lines, stdlib only. The cost of getting tamper-evident audit trails approaches zero; the cost of *not* having them is paid in unverifiable claims.

**Per-finding confidence shapes agent reasoning.** Tagging individual malfind regions (rather than the tool's overall output) caused the agent to adopt the tool's confidence vocabulary in its natural-language responses. The tool surface is a reasoning prior.

**Calibrated honesty is a competitive feature in forensics.** A forensically-trained reviewer reads "answered 2 of 5; correctly identified the others as out of scope" and recognizes the discipline. An agent that confidently and wrongly answers all 5 is the *anti-pattern* this hackathon exists to address.

---

## What's next

The architecture extends cleanly. The immediate roadmap, all explicitly named in `self_correct`'s output as current coverage gaps:

- `windows.sessions` — determine whether any RDP attempt successfully authenticated
- `windows.pstree` — parent-child process tree for orphan/suspicious-parent detection
- `windows.dlllist` — DLL enumeration for the malfind-flagged PIDs

Each is approximately 30 lines following the same pattern. Adding them closes the partial-answer questions (Q1, Q2) and tightens Q3.

Beyond the immediate: **disk-image analysis** (filesystem, MFT, ShellBags, jump lists, $UsnJrnl), **timeline construction** (super-timeline tools wrapped under the same receipted surface), and **PDF report generation** with embedded receipt verification.

The deeper pattern — *read-only typed surface + hash-chained provenance + per-finding confidence + self-audit* — is not specific to forensics. The same architecture applies wherever AI agents must operate on high-integrity data: financial audit, clinical research, legal e-discovery, regulatory compliance. APEX Forensics is one face of that pattern.

— Jason Wold · Vector Research Labs · jason.wold@vectorresearchlabs.com
