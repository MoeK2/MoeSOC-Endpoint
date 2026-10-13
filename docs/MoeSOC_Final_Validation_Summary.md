# MoeSOC Endpoint v1.0.0: Validation Summary

**Audit:** 2026-10-08. Commit `62ca492` (tag `v1.0.0`, local only). Windows 11 Pro 10.0.26200, Python 3.13.15, PySide6 6.11.2, pywin32 312.
**Scope:** tested and inspected as-is; no product code changed. Full report: [MoeSOC_Final_Validation_Report.md](MoeSOC_Final_Validation_Report.md). Gap analysis and roadmap: [MoeSOC_Gap_Analysis.md](MoeSOC_Gap_Analysis.md).

## What it is

MoeSOC is a local, observe-only Windows detection and investigation console. It runs as a GUI, a CLI and a packaged exe over SQLite. It reads Security, Sysmon, PowerShell 4104 and Defender events. It runs 8 detections and 4 correlations with explainable confidence and risk. On top of that it offers triage, timelines, process trees, stories, search and pivots, tuning and suppressions, retention, and redacted HTML reports.

## Measured results

| Check | Result |
|---|---|
| Ruff lint + format | clean (Linux 144 files, Windows 143 files) |
| pytest | 452 collected. Windows elevated **452/452**; Windows non-elevated 451 + 1 skip; Linux 450 + 2 skips, ×3 runs, no flakiness |
| GUI smoke (real window, offscreen, elevated) | **76/76** each |
| MoeSOC.exe `--self-test` | PASSED (version, 12 rules, schema v8, icon, pywin32, 9 GUI pages) |
| Real Security scan (elevated, DB copy) | 1,269 records read, 515 new, **0 parse failures**, 0.36 s; rescan 0 read, 0 new, **0 duplicates** |
| Evidence re-verification of real findings | **24/24 verified** in the live log |
| Migrations v1…v7 → v8 | all data kept, integrity ok; newer DB refused untouched |
| HTML report | hostile input escaped (no script or event-handler tags); redaction removed every identifier tested |
| Benchmark (Windows, synthetic, 100k events) | parse 5.23 s, store 5.87 s, detect 7.39 s; 176 MB (1.8 KB/event) |

## Real vs synthetic (the key point)

| Rule | Status |
|---|---|
| DET-001 Multiple Failed Logins | **REAL WINDOWS ✅** (2 real findings) |
| DET-005 New User Account | **REAL WINDOWS ✅** |
| COR-001 Failed then Success | **REAL WINDOWS ✅** (HIGH/LOW, explained) |
| DET-006 Privileged Group | partial: real 4732 parsed, no real positive ⚠ |
| DET-007 Suspicious PowerShell | partial: 41 real 4104 parsed, 0 false positives; positive **SYNTHETIC ONLY ⚠** |
| DET-002, DET-003, DET-004, DET-008, COR-002, COR-003 | **SYNTHETIC ONLY ⚠** |
| COR-004 Defender → Sysmon source | **SYNTHETIC ONLY ⚠** (Sysmon not installed: cannot fire here) |

Telemetry on the test PC:

- **Sysmon:** not installed.
- **Script Block Logging:** disabled.
- **Defender log:** 0 detection events.

## Defects found (not fixed: audit was read-only)

1. **A-1 MEDIUM: duplicate findings in live mode.** One 3-hour slow-guessing campaign produced **22 DET-004 findings** instead of 1.
2. **A-2 MEDIUM: identity split on the client-supplied domain field of Event 4625.** Varying it evades DET-001 and makes DET-002 misreport a spray.
3. **A-3 MEDIUM: evidence verification flags genuine Sysmon, PowerShell and Defender evidence as "mismatch".** It parses every record as Security XML.
4. **A-4 MEDIUM (unconfirmed): live monitoring never shown to receive an event.** It starts, stops and restarts correctly on real Windows, but delivered 0 events in the test.
5. **Low severity:** CLI broken-pipe traceback; empty MITRE line for COR-004; risk double counting; launcher vs exe UAC-decline behaviour differs; missing LICENSE file; stale benchmark version string.

## Release readiness

| Item | State |
|---|---|
| Ready | version, CHANGELOG, release notes, demo, redacted screenshots |
| Partial | tag (local only), README (headline overstates validation), CI (local mirror only; **GitHub CI never run**) |
| Not done | LICENSE, checksums |
| Blocked | installer (**Inno Setup not installed**), git history (**old screenshots show the real computer name**) |

## Scores (junior SOC portfolio scale)

| Area | Score | Area | Score |
|---|---|---|---|
| Architecture | 8 | Investigation workflow | 8 |
| Windows knowledge | 8 | Testing | 7 |
| Detection engineering | 6 | Code quality | 8 |
| Correlation | 6 | Security / privacy | 7 |
| UI/UX | 6 | Documentation | 8 |
| Real-world validation | **3** | Packaging | 5 |
| **Portfolio value** | **7** | | |

## Verdict

A careful, honest, well-tested project whose real Security-log pipeline works.

- **GitHub:** ready after cleaning the git history and adding a LICENSE.
- **CV:** ready, if described accurately.
- **v1.0 credibility:** needs the real-telemetry validations and fixes for A-1, A-2 and A-3.
- **Installer:** not ready.
