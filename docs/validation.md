# Real-event validation: DET-001 and COR-001

**Status: TESTED on real Windows logons (Oct 7, 2026, Windows 11 workstation).** DET-001 and COR-001 fired on events Windows itself wrote, every evidence EventRecordID was re-read from the live log with identical raw XML, and the GUI showed the findings, timelines and evidence. The results are at the end of this page. MoeSOC never types passwords itself; a person generated the logons with a dedicated test account.

## Goal

Generate at least 5 failed logons followed by a successful one, then prove each of these:

1. Windows recorded Events 4625 and 4624.
2. MoeSOC collected, normalized and stored them.
3. DET-001 and COR-001 triggered.
4. The evidence points to the real EventRecordIDs, and `verify-evidence` re-finds them in the live log.
5. The GUI shows the finding, its timeline and the raw XML.

## Safety rules

- Use a **dedicated local test account**, never your own or a real user's.
- Do not add the test account to Administrators.
- MoeSOC does **not** change audit policy, lockout policy or any Windows setting. The script only reads them.
- Stay below the account lockout threshold, and delete the test account afterwards.

## Steps

All commands run in the `MoeSoc EndPoint` folder.

**1. Create the test account** (PowerShell as administrator). Use a throwaway password that you use nowhere else:

```powershell
net user moesoc-test * /add          # prompts for the password, so it is not echoed
```

**2. Check the policies (read-only).** `scripts\validate_real_auth.bat` prints both of these. You can also check them yourself:

```powershell
net accounts                                                       # "Lockout threshold": stay below it
auditpol /get /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}  # Logon: must include Failure
```

Windows 10 and 11 audit Logon "Success and Failure" by default. If yours does not, enabling it is your decision; MoeSOC will not do it.

**3a. Generate interactive failures** (normal, non-admin terminal). This runs `runas` 6 times with a wrong password and once with the right one:

```cmd
runas /user:%COMPUTERNAME%\moesoc-test cmd
```

In **PowerShell** the variable is written differently; `%COMPUTERNAME%` is not expanded there and Windows receives it literally (see the results below):

```powershell
runas /user:$env:COMPUTERNAME\moesoc-test cmd
```

Expected: six 4625 events (logon type 2, failure reason "Incorrect password") and one 4624 (type 2).

**3b. Optional: generate network failures** over SMB to this machine (requires the Server service). Run it with a wrong password 6 times, then with the right one:

```cmd
net use \\127.0.0.1\IPC$ /user:%COMPUTERNAME%\moesoc-test
net use \\127.0.0.1\IPC$ /delete
```

Expected: 4625 and 4624 with logon type 3 from `127.0.0.1` or `::1`.

**4. Run the validation** by double-clicking `scripts\validate_real_auth.bat` and approving the admin prompt. Then double-click `scripts\validate_real_gui.bat` (no admin needed) for the GUI checks and screenshots. It writes `validation_output.txt`, which contains:

- the audit policy and lockout policy;
- the scan summary and recent 4625 events;
- the findings;
- `verify-evidence` for the latest DET-001 and COR-001 findings. Each evidence record should report `verified`.

**5. Check the GUI.** `scripts\validate_real_gui.bat` opens the validation database (no scan, no changes) and checks, for the latest COR-001 and DET-001:

- the finding is listed and its detail explains the confidence;
- **Open Timeline** highlights exactly the evidence EventRecordIDs stored in the finding;
- **Evidence Events** lists exactly those records, and the raw XML viewer shows the original event.

It writes `validation_gui_output.txt` and screenshots `docs/screenshots/real-*.png` (private: git-ignored, because they show real account data).

**6. Clean up:**

```powershell
net user moesoc-test /delete
```

## What COR-001 confidence should say

The confidence is derived from the evidence (see detections.md), so the two variants differ:

| Variant | Expected factors | Expected confidence |
| --- | --- | --- |
| 3a, `runas` (local, type 2) | −1 local interactive logon; −1 same workstation and type, no remote address | LOW: looks like a user typing errors |
| 3b, `net use` over loopback (type 3) | +2 network logon type; −1 same workstation and type, no remote address | MEDIUM |

This is the intended behavior. The same "failures then success" sequence is only strong evidence when the success arrives from the network.

## Results (Oct 7, 2026)

Machine: Windows 11 workstation, Logon auditing "Success and Failure" (default), lockout threshold 10 attempts / 10 min, so the test stayed below lockout. Test: variant 3a (`runas`), test account `moesoc-test`.

| Check | Result | Evidence |
| --- | --- | --- |
| 4625 events recorded by Windows | TESTED | 7 failures, records 576141–576153, 18:01:34–18:01:51, logon type 2, "Incorrect password" (0xC000006A) |
| 4624 success recorded | TESTED | Record 576157 at 18:02:03, type 2, 11 s after the last failure |
| Collected, normalized and stored | TESTED | Scan read 549 records, 0 parse failures; all 8 events stored |
| Identity correct | TESTED | 4625 carries the NULL SID (S-1-0-0); the 4624 carries the account SID (…-1005). The resolver linked them by name (`sid_resolved_from_name: true` on DET-001) |
| DET-001 triggered | TESTED | Finding #2, 7 evidence events, MEDIUM / MEDIUM |
| COR-001 triggered | TESTED | Finding #3, 8 evidence events, HIGH severity, confidence **LOW** (−1 local interactive success, −1 same workstation and type, no remote address), exactly as predicted above |
| `verify-evidence` | TESTED | DET-001: 7 of 7 verified; COR-001: 8 of 8 verified, raw XML identical |
| GUI: findings, timeline, drill-down, raw XML | TESTED | `validate_real_gui.bat`: 19 of 19 checks passed |
| Network variant 3b (`net use`, type 3) | NOT TESTED | Optional; expected MEDIUM confidence |

Screenshots of these real findings (`docs/screenshots/real-*.png`) are written by `validate_real_gui.bat` on the validating machine. They show its hostname, username and account SIDs, so they are git-ignored and kept private. Sanitize before sharing.

### What the real events taught us

- **Interactive `runas` logons record `::1` as the source address**, not "no address". COR-001 still scored them as local because the logon type is 2 and the workstation matches; the address alone did not mislead it.
- **A typo became a separate, correct finding.** The first attempt ran in PowerShell, where `%COMPUTERNAME%` is not expanded, so Windows logged 8 failures for the literal domain `%COMPUTERNAME%` with "Account does not exist" (0xC0000064). MoeSOC kept `%COMPUTERNAME%\moesoc-test` apart from `DESKTOP\moesoc-test` and raised its own DET-001 (#1). Merging them would have been wrong: one account exists and one does not.
- **The failure events' Logon ID is the caller's session**, not a new logon, so it cannot link a 4625 to the later 4624. Identity linking uses SID and name instead.

### Clean-up

Delete the test account when you are done: `net user moesoc-test /delete`. The validation data stays in `.verify-data`, separate from the normal MoeSOC database.

## Windows checkpoints (automated, `scripts\verify_windows.bat`, not elevated)

| Date | After | pytest | GUI smoke | Real telemetry observed |
|---|---|---|---|---|
| Oct 7, 2026 | Phases 2–6 | 229 passed | passed | — |
| Oct 7, 2026 | Phases 7–9 | 267 passed | passed | — |
| Oct 7, 2026 | Phase 10 | 279 passed | passed | live monitor reports ERROR (access denied) when not elevated, as designed |
| Oct 7, 2026 | Phases 11–13 | 307 passed | passed (process tree) | Sysmon: not installed |
| Oct 7, 2026 | Phases 14–20 | 350 passed, 1 skipped | passed (DET-007/DET-008 detail rendering) | Health read the real Script Block Logging policy (not enabled → Limited) and the real Defender Operational log (readable) |
| Oct 8, 2026 | Final (1.0.0) | 451 passed, 1 skipped; Ruff clean | passed, 76 checks, screenshots refreshed; demo screenshots captured on Windows; `MoeSOC.exe` 1.0.0 self-test passed | real database on schema v8 with all events; the demo review found inconsistent redaction placeholders and real Health shown in demo mode (both fixed) |
| Oct 8, 2026 | Phases 27–28 | 437 passed, 1 skipped (3 consecutive runs) | first two runs **failed** "suppression listed" (a dropped Tuning reload; fixed in two steps), then passed three times in a row; reports exported (redacted and plain) | benchmark run on the PC: see [benchmarks.md](benchmarks.md) |
| Oct 8, 2026 | Phases 23–26 | 424 passed, 1 skipped | passed (parent filter, tuning page, suppression prefill, audit log, retention preview) | real database migrated v6 → v8 in place; 998 events intact; screenshot review found event IDs offered as tunable and an unused DET-008 parameter (both fixed, with tests) |
| Oct 8, 2026 | Phases 21–22 | 371 passed, 1 skipped | first run **failed** (Story page import error, fixed in the next commit); re-run passed (Story page, COR-004 activity chain) | the real database migrated v5 → v6 in place; all 998 stored events still listed |

Elevated paths (real Security-log scan, live subscription, real 4104 and Defender events) are listed in [manual_validation_queue.md](manual_validation_queue.md).

## Correctness fixes after the v1.0.0 audit (Oct 9–10, 2026)

Each defect is written up as Before / Root cause / Fix / Regression test / Status in [MoeSOC_Correctness_Fix_Report.md](MoeSOC_Correctness_Fix_Report.md). Summary:

| ID | Status | Evidence |
|---|---|---|
| A-1 finding identity across live windows | FIXED / AUTOMATED TESTED | audit probe: 36 slow failures, one per live batch → 22 findings before, **1** after; `tests/test_campaign_continuity.py` (9) |
| A-2 failed-logon identity | FIXED / AUTOMATED TESTED | audit probe: varied domains → false DET-002 before, none after; mixed empty/host domain → DET-001 fires; `tests/test_failed_logon_identity.py` (18) |
| A-3 source-aware evidence verification | FIXED / AUTOMATED TESTED | Security, Sysmon, PowerShell and Defender fixtures: verified / mismatch / missing / unreadable; `tests/test_evidence_sources.py` (23) |
| A-4 live subscription start-up | IMPLEMENTED / AUTOMATED TESTED — REAL DELIVERY VALIDATION PENDING | fake pywin32 layer, `tests/test_subscription_source.py` (12); one real run was inconclusive (no trigger event written), manual check A-M2 |

The real-Windows checks of DET-001 and COR-001 above are unaffected: DET-001 still fires once per burst (regression test `test_det001_long_brute_force_live_is_one_finding_and_bursts_stay_separate`).
