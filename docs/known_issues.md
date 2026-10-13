# Known issues and fixed defects

Status labels: TESTED — REAL WINDOWS, TESTED — AUTOMATED, TESTED — SYNTHETIC, PARTIALLY TESTED, NOT TESTED, BLOCKED.

The defects come from the independent audit of v1.0.0 (`MoeSOC_Final_Validation_Report.md`). The full write-up of the fixes is in [MoeSOC_Correctness_Fix_Report.md](MoeSOC_Correctness_Fix_Report.md).

## Fixed

| ID | Defect | Status |
|---|---|---|
| A-1 | A long live campaign became many findings (36 slow failures → 22 DET-004 findings) | Fixed. TESTED — AUTOMATED |
| A-2 | The client-supplied 4625 domain split one account (DET-001 evaded, DET-002 false spray) | Fixed. TESTED — AUTOMATED |
| A-3 | Evidence verification parsed every record as Security XML (false "mismatch" for Sysmon, PowerShell, Defender) | Fixed. TESTED — AUTOMATED |
| A-4 | Live subscription waited for a signal before its first drain | Fixed. PARTIALLY TESTED (automated only; real delivery: MANUAL VALIDATION REQUIRED) |
| A-5 | CLI printed a BrokenPipeError traceback when piped into `more`/`head` | Fixed. TESTED — AUTOMATED |
| A-6 | COR-004 `show` printed an empty MITRE line (per-finding T1105 not shown) | Fixed. TESTED — AUTOMATED |
| A-7 | Stored risk from an older model was unexplained | Fixed. TESTED — AUTOMATED (display only; stored rows unchanged) |
| A-8 | Risk double counting (DET-008, COR-004 severity + modifier; weak COR-003 link counted as corroboration) | Fixed. TESTED — AUTOMATED |
| A-9 | A declined UAC prompt: launcher started nothing, exe opened limited mode | Fixed. TESTED — AUTOMATED (both open limited mode) |
| A-10 | No LICENSE file; benchmark JSON said 0.2.0; README "verified on Windows 11" overstated | Fixed. NOT TESTED (metadata only) |
| A-11 | `casefold` merged `Straße` and `STRASSE`; Windows treats them as different accounts | Fixed. TESTED — AUTOMATED |

## Open

- ~~**Live delivery on real Windows (A-4).**~~ Resolved: the always-on sensor received real Security events live, without a manual scan, and raised DET-001 and COR-001 from them. See the final report.
- **Varying claimed domains on a computer with unknown authority (A-2 limit).** When MoeSOC has no evidence about the computer's accounts (no local-SID evidence, no local configuration, for example an imported log from another machine), `alice` under six invented domains is kept as six claimed identities. DET-001 does not fire, and DET-002 does not report a spray because the candidates count as one account. On the PC MoeSOC runs on, its own configuration provides the proof, and DET-001 fires.
- **Detection cost.** The A-2 and A-11 work adds per-event identity resolution. 100k synthetic events, Linux, detect stage: 8.88 s before → 10.1 s now (cached).
- **Audit items still manual:** A-M1 (network brute force from a second machine), A-M4 (DET-006 / COR-002 real positive), and the owner decisions A-M5 to A-M7.

## Always-On reliability (B-series)

Full write-up: [MoeSOC_AlwaysOn_Reliability_Report.md](MoeSOC_AlwaysOn_Reliability_Report.md), and for B-7 and the final validation, [MoeSOC_AlwaysOn_Final_Report.md](MoeSOC_AlwaysOn_Final_Report.md).

| ID | Defect | Status |
|---|---|---|
| B-1 | Reinstall/update broke the access rights under `C:\ProgramData\MoeSOC` | Fixed. TESTED — REAL WINDOWS |
| B-2 | A failed update left the sensor stopped and the program folder half replaced | Fixed (rollback-safe swap). TESTED — REAL WINDOWS |
| B-3 | The deep link opened several consoles | Fixed. TESTED — REAL WINDOWS |
| B-4 | Sensor health disappeared when the database failed (IPC started after the DB) | Fixed. TESTED — REAL WINDOWS |
| B-5 | Multi-client IPC fix not verified on the deployed build | Verified. TESTED — REAL WINDOWS |
| B-6 | A normal (non-admin) user's tray could not connect to the sensor pipe | Fixed. TESTED — REAL WINDOWS |
| B-7 | A normal-user console could not read the sensor database reliably (the sensor's keeper connection never opened the WAL files) and could not save triage or notes | Fixed: the keeper keeps the WAL files; triage and notes go through the sensor; no UAC prompt with the sensor installed. TESTED — REAL WINDOWS |
| B-8 | Reinstall right after an uninstall: the program-folder rename was refused while the closed tray was still exiting | Fixed: bounded rename retry; a lasting lock still rolls back. TESTED — REAL WINDOWS |

## Intentional (documented)

- A rule-version change starts a new finding. The old finding and its triage history are kept unchanged (A-7 explains the old score; it never rewrites it).
- The campaign continuation gap equals the rule window. A quiet gap longer than the window starts a new finding, by design: it is a new campaign for triage.
