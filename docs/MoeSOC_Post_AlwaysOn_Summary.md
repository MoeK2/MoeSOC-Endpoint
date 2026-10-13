# MoeSOC Post-Always-On Validation: Summary

Commit `7c845f4`, version 1.0.0, audited 2026-10-10/11. No product code changed. Full report: [MoeSOC_Post_AlwaysOn_Validation_Report.md](MoeSOC_Post_AlwaysOn_Validation_Report.md).

**Verdict: PARTIAL.** The detection product shows no regressions, and the always-on design is correct and very light when idle. But the **install/update path is broken on real Windows**, and the toast-and-click flow is not yet proven.

## Measured

| Item | Result |
|---|---|
| Linux tests | 609 passed, 2 skipped (Windows-only) |
| Windows tests | 610 passed + 1 skipped (non-elevated); 611 passed (elevated, ×2) |
| Ruff | clean |
| GUI smoke | 76/76 |
| Sensor idle (real, 10 min) | **0.0 % CPU avg** (peak 0.02 %), **36.6 MB** working set / 23.2 MB private, flat |
| Tray (real) | 0.000 % CPU, 31–33 MB / 19 MB, 2–5 threads, ~175 handles, 0 sockets |
| Console RAM | NOT TESTED (audit-tooling error) |
| Real unattended run | **19 h, 146 live batches, 218 events, 0 duplicates**, `quick_check` ok |
| Network | no listeners (code; tray and console netstat); no outbound calls |
| IPC abuse by an unprivileged user | not possible (allow-list of 6 commands; hostile inputs rejected on the real pipe) |
| Load, 100k events (synthetic) | detect +16 % vs v1.0 (correctness work); a live burst of 10k records costs ~17 s CPU |

## Bugs

| ID | Severity | Summary |
|---|---|---|
| B-1 | HIGH | Re-running `install` strips access rights from the sensor's existing files. The service shows Running but cannot open its DB, so **no monitoring** |
| B-2 | HIGH | A failed update (tray holds files) leaves the sensor **stopped** and the folder partly copied |
| B-3 | MEDIUM | Deep link `--finding` opened a new console each time on real Windows |
| B-4 | MEDIUM | No IPC/health while the DB is unavailable, so the outage is silent |
| B-5 | MEDIUM | Installed build serves one IPC client at a time (fixed in code, not deployed) |
| P-1 | LOW–MED | Live burst detection cost grows quadratically |
| L-1 | LOW | The `net use` test makes only one 4625 |

## Status of the always-on claims

| Claim | Status |
|---|---|
| Sensor works without the GUI | TESTED — REAL WINDOWS ✅ |
| Live delivery (natural events) | TESTED — REAL WINDOWS ✅ |
| Live delivery (deliberate event) | FAILED ❌: the sensor had been stopped by B-2; repeat after repair |
| Tray starts at sign-in | TESTED — REAL WINDOWS ✅ |
| Sensor auto-start at boot | configured; reboot NOT TESTED |
| Notifications + dedup | TESTED — AUTOMATED ✅; real toast BLOCKED BY USER INTERACTION |
| Deep link | FAILED ❌ (B-3) |
| Sleep / resume | PARTIALLY TESTED ⚠ |

## State of the test PC

**The sensor is not monitoring** (B-1): it shows Running, but it cannot open its database. To fix it, double-click `audit\post_audit_c.bat` and approve UAC. It repairs the permissions without deleting anything, restarts the sensor and finishes the measurements. Alternatively, `scripts\sensor_uninstall.bat` removes the service and keeps the data.
