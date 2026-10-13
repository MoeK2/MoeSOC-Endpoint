# MoeSOC Always-On Reliability Report

**Session:** 2026-10-11. Fix → rebuild → real Windows validation of the Always-On operational defects B-1…B-5 found by the post-Always-On audit. A sixth defect (B-6) was found and fixed during this validation.
**Labels:** TESTED — REAL WINDOWS ✅ · TESTED — AUTOMATED ✅ · TESTED — SYNTHETIC ⚠ · PARTIALLY TESTED ⚠ · NOT TESTED · BLOCKED BY ENVIRONMENT · BLOCKED BY USER INTERACTION · FAILED ❌
**Evidence:** audit-tooling outputs on the test PC (`audit\out\reliability.txt`, `check_*.txt`, `sensor_update_output.txt`). The audit scripts live outside git.

## Baseline

| Item | Value |
|---|---|
| Start commit | `b8da3ff` (code as audited at `7c845f4`); version 1.0.0, schema v9 |
| Tests at start | Linux 609 passed / 2 skipped; Windows 611 passed elevated; GUI smoke 76/76; Ruff clean |
| PC state at start | Service `MoeSOCSensor` **RUNNING** but not monitoring. `moesoc.db`, `sensor.log` and `sensor.json` were inaccessible even to Administrators (B-1 damage). IPC was unreachable (B-4). |
| Data location | `C:\ProgramData\MoeSOC\data\moesoc.db` (707 events, 0 findings); backup copy made once the files were readable (`audit\out\sensor-db-backup.db`) |

## B-1

### Before

Re-running `install` (the update path) ran `icacls /inheritance:r /grant:r … /T` and `/setowner /T` over every existing file under `C:\ProgramData\MoeSOC`. Files created by the service ended with no usable access entries and owned by the service account, so even Administrators were denied (real, twice). `install` then crashed writing `sensor.json`.

### Root Cause

The ACL was applied recursively to existing children (`/T`). `/inheritance:r` removed the inherited entries those files depended on, and the explicit grants and owner change did not land on them.

### Fix

`e04ab3b`: the protected ACL is set **on the root folder only**, with no `/T`. Its inheritable entries propagate to children that inherit.

A second install now:

1. detects children that do not inherit (DACL protected, no inherited ACE, or unreadable);
2. repairs only in that case: `takeown /A /R` to Administrators, then `icacls <root>\* /reset /T`.

File contents are never touched, and the step is idempotent.

### Automated Tests

`tests/test_sensor_update.py` (2 tests):

- the commands touch only the root, with no `/T`, users read-only and no Everyone;
- damaged children are detected, and the repair commands are correct.

TESTED — AUTOMATED ✅.

### Real Windows Test

`audit\reliability.bat`, elevated:

- **R1, first run of the fixed build:** it reported "Repairing access rights of 7 item(s) left by an earlier install" (data, moesoc.db, -shm, -wal, logs, sensor.log, sensor.json).
  - Afterwards every file shows **inherited** entries: service M, Users RX, Administrators F, SYSTEM F.
  - `quick_check` ok, 707 events, 0 duplicates.
- **R2, R4, R5 and two later updates:** **no ACL change and no repair needed**. The ACLs were identical after each run.

The database stayed intact: 707 → 730 events (new events only), `quick_check` ok and 0 duplicates after every step.

### Result

**FIXED: TESTED — REAL WINDOWS ✅.** Install was run 7 times in total and never damaged access again.

## B-2

### Before

`install` stopped the service first, then copied over the live folder file by file. A file locked by the auto-started tray made the copy fail midway, leaving the sensor **stopped** and the folder half updated (real).

### Root Cause

The live directory was overwritten in place while other processes could hold its files. There was no staging, no rollback and no restart on failure.

### Fix

`e04ab3b`: `moesoc/sensor/update.py`, used by `install --copy-to-program-files`.

1. Recover leftovers.
2. Stage to `MoeSOC Endpoint.new` and validate the required files. The service is not touched.
3. Close the tray through its own WM_CLOSE exit path, and reopen it in the user's session afterwards.
4. Refuse if a console runs from the folder. Nothing has changed and the sensor keeps running.
5. Stop the service, rename live → `.old`, rename `.new` → live, start the service, then health-check it over IPC.
6. Any failure puts the old folder back and starts it. If the new build does not answer, it moves to `.failed` and the old build is restored.
7. `.old` is deleted only after success.

### Failure/Rollback Test

`test_sensor_update.py` (12 state-transition tests) covers:

- success;
- tray running (closed and reopened);
- console open (refused before any change);
- copy failure (nothing touched);
- incomplete build;
- locked live folder (old version kept and restarted);
- failure after moving the old folder (put back);
- new version not answering (rolled back, kept as `.failed`);
- a stopped service stays stopped;
- fresh install;
- recovery of an interrupted swap;
- re-run after a failure.

TESTED — AUTOMATED ✅.

### Real Windows Test

| Scenario | Result |
|---|---|
| A: sensor running, tray and console closed (R1) | exit 0, RUNNING, IPC ok, no leftovers ✅ |
| B: tray running (R2) | tray closed and reopened, exit 0, RUNNING ✅ |
| C: console `MoeSOC.exe` open from Program Files (R3) | **refused**: "MoeSOC programs are running from … (MoeSOC.exe). Close the MoeSOC console … Nothing was changed; the sensor keeps running." Exit 1; service RUNNING, IPC MONITORING ✅ |
| D: file held open inside the live folder (R4) | "The update could not replace … (Access is denied) … The previous version was kept and the sensor was started again." Exit 1; RUNNING; hello ok; no leftovers; DB `quick_check` ok ✅ |
| E: update again after the failure (R5) | exit 0, MONITORING ✅ |
| Two later real updates (B-6 deployment) | exit 0, "Sensor is running and answers over IPC" ✅ |

### Result

**FIXED: TESTED — REAL WINDOWS ✅.**

## B-3

### Before

With a console open, each `app.py --finding <id>` start opened **another console** (real: 3 consoles).

### Root Cause

This was **confirmed on real Windows** with `audit\link_diag.bat`:

- `waitForConnected=True`;
- **`waitForBytesWritten=False`**;
- `waitForReadyRead=True`, with the reply `b'ok'`.

On Windows a small `QLocalSocket` write completes inside `flush()`, so `waitForBytesWritten()` returns False although the console already received the request. The sender trusted that False and started a new console.

### Fix

`f6c321c`:

- Delivery is decided by the console's **reply** (`ok`/`invalid`). Any reply means a console is running.
- The console assembles split requests.
- A packaged start that finds a running instance retries the hand-over for a few seconds (startup race).
- The console logs `Deep link: opened finding #N` / `not found`.

### Automated Test

7 new tests (`test_tray_and_deeplink.py`):

- the hand-over succeeds although `waitForBytesWritten` is False (it fails on the old code);
- `invalid` reply → handled;
- no server → start;
- the console shuts down without replying → start;
- a split reply is assembled;
- the server waits for a complete request;
- the frozen start retries during a startup race.

Also the existing validation tests. TESTED — AUTOMATED ✅.

### Real Deep-Link Test

Development console open; 5 valid and 1 invalid `--finding` starts:

- console processes after each request: **[1, 1, 1, 1, 1, 1]**;
- the log shows **6 × "Handed the request to the running console", 0 new console starts**, and "Deep link: finding #999999999 not found" for the invalid ID.

The sensor DB has **no findings yet**, so "the selected finding matches" could not be shown with a real finding (the requested `#1` does not exist and was reported as not found).

### Result

**FIXED: TESTED — REAL WINDOWS ✅** for "no duplicate console, request handed over". Selecting an existing finding from a real notification click: **BLOCKED BY USER INTERACTION** (see Toast Click).

## B-4

### Before

IPC started only after the database opened. With the DB inaccessible, the service showed RUNNING but the tray showed "Offline" and nobody could read the reason (real).

### Root Cause

Startup order in `SensorCore.run`. Unexpected storage exceptions also escaped the retry loop.

### Fix

`af4bb53`:

- IPC starts **first**.
- Any storage failure is reported and retried with the existing back-off.
- `status` adds `state: ERROR`, `degraded`, `monitoring` and `last_error`.
- The tray shows "Sensor error (not monitoring)" with the reason and the warning icon.
- DB-dependent commands answer with a readable error.

### Degraded Health Test

**Automated (6 tests):** access denied, unexpected exception, corrupt file, schema too new. Each gives IPC reachable, `ERROR`, the reason, no crash, and recovery after the repair. Also a readable reply for preferences while the DB is down, and the tray tooltip. They fail on the old code. TESTED — AUTOMATED ✅.

**Real:** a deny ACE for `NT SERVICE\MoeSOCSensor` on `moesoc.db` was added and the service restarted. Status over IPC:

```
state ERROR, database "error: Could not open the local database …",
monitoring false, degraded true, ipc listening
```

After the deny was removed: `state MONITORING, database ok, last_error None` (existing retry). TESTED — REAL WINDOWS ✅.

### Result

**FIXED: TESTED — REAL WINDOWS ✅.**

## B-5 Deployment Verification

On the deployed build, as administrator, with the tray connected:

- **3 concurrent `wait_notifications` clients:** `['ok', 'ok', 'ok']`.
- **During the waits:** `status` ok (0.00 s), `get_prefs` ok (0.01 s), `scan` ok (0.00 s).
- **Errors:** no winerror 121, no starvation, no deadlock.
- **Hostile inputs:** malformed, unknown command, oversized and invalid preferences were all rejected with readable errors.

**FIXED: TESTED — REAL WINDOWS ✅.**

### B-6 (new, found and fixed in this session): the tray could not reach the sensor as a normal user

All earlier IPC tests ran as administrator. A check as a **normal user** gave `access denied` (winerror 5).

There were two causes:

1. The client requested `GENERIC_READ | GENERIC_WRITE`. GENERIC_WRITE includes create-pipe-instance and write-EA rights, which the pipe deliberately does not grant to users.
2. Verifying the server needed the service account's token, which normal users may not open.

Fixes:

- `e5f70fa`: the client requests exactly the granted mask (one shared constant).
- `cb8b181`, then `b2502c0`: when the token cannot be read, the server must be in **session 0**. This is asked of the pipe itself with `GetNamedPipeServerSessionId`; `ProcessIdToSessionId` is also denied to users (real). An ordinary user cannot run a process in session 0.

Result: a normal user's client gets `state MONITORING` from the deployed sensor (real). Automated: 2 tests. The deployed tray reconnected after the update. Its online state is not logged, so the definitive proof is the toast test.

**FIXED: TESTED — REAL WINDOWS ✅** (normal-user status call); the tray end-to-end proof is BLOCKED BY USER INTERACTION.

## Build Results

| Artifact | Result |
|---|---|
| `MoeSOC.exe`, `MoeSOCSensor.exe`, `MoeSOCTray.exe` (one folder, shared `_internal`) | built 3 times this session (last 2026-10-11 13:58, from `b2502c0` code); 10 PyInstaller steps "completed successfully" |
| `MoeSOC.exe --self-test` | **PASSED** (each build) |
| Installer | not built (Inno Setup not installed) |
| Version | 1.0.0 (unchanged) |

## Full Regression Results

| Suite | Code | Passed | Failed | Skipped |
|---|---|---|---|---|
| Linux pytest (final) | `b2502c0` | **640** | 0 | 2 (Windows-only) |
| Windows pytest, non-elevated (`verify_windows.bat`) | `b52c502` (before the B-6 fixes) | **639** | 0 | 1 (Security scan needs elevation) |
| Windows pytest, elevated (`reliability.bat`) | `b52c502` | **640** | 0 | 0 |
| Ruff check / format | final | clean (180 files) | | |
| GUI smoke | `b52c502` | **76/76** | 0 | |
| Migration / schema, service, IPC, notification, tray/deep-link, live-monitor, A-1…A-11 | within the suites above | all passed | 0 | |

The final B-6 commits (`e5f70fa`, `cb8b181`, `b2502c0`) were tested on Linux (640 passed) and in their real-Windows effect (normal-user status). **The full Windows suite was not re-run after them** (NOT TESTED). They change only the pipe client's access mask and the server check; all IPC tests pass.

## Real Service Test

After the final update:

- service RUNNING;
- IPC available (admin and normal user);
- database `ok (schema v9)`;
- Security, PowerShell and Defender **live**; Sysmon "not installed" (correct for this PC).

TESTED — REAL WINDOWS ✅.

## Update / Reinstall Test

The update was run 7 times (see B-1 and B-2): 5 passed, 1 correctly refused (console open), and 1 correctly failed with rollback (locked folder). After each run the service ran, IPC answered, `quick_check` was ok, there were 0 duplicate rows, and the ACLs were unchanged. TESTED — REAL WINDOWS ✅.

Findings, notes and history preservation: the sensor DB had **0 findings, notes and history rows** (only benign activity on this PC). Preservation is proven automatically (`test_triage_notes_and_history_survive_campaign_extension`, the migration tests), not with real rows: **PARTIALLY TESTED ⚠**.

## Live Event Delivery

The sensor was running and the GUI closed. The test made failed network logons for a **non-existent** account with a dummy string.

- **Windows wrote 3 Event 4625** (records 580998, 581000, 581002; read from the Security log).
- **MoeSOC stored all 3 exactly once, without Scan Now.**

**PASSED: TESTED — REAL WINDOWS ✅.**

No DET-001: 3 failures are below its threshold of 5. This test method cannot produce 5 (L-1).

## Real Notification

The user was asked to run the lock-screen test: 6 wrong passwords, then sign in. Expected: DET-001 (MEDIUM, no toast by default), then COR-001 (HIGH) → one toast. **BLOCKED BY USER INTERACTION** (not yet performed at the time of writing).

## Toast Click / Deep Link

Clicking the toast and "Recent finding" with the console open: **BLOCKED BY USER INTERACTION**. Routing is TESTED — AUTOMATED ✅; console reuse is TESTED — REAL WINDOWS ✅ (B-3).

## Console / Tray Independence

TESTED — REAL WINDOWS ✅:

- **Console closed:** the sensor stayed MONITORING.
- **Exit Tray** (WM_CLOSE, the tray's own exit): tray not running, sensor MONITORING.
- **Tray restarted:** running; `tray.log` shows "Tray exited (the sensor keeps monitoring)" / "Tray started".
- **Console opened again:** it ran.

## Reboot

NOT TESTED. Reboot validation is prepared (`audit\check_reboot.bat`) and needs your approval and action.

## Sleep / Resume

NOT TESTED on real hardware (automated: TESTED — AUTOMATED ✅). Prepared: `audit\check_sleep.bat`.

## Uninstall / Reinstall

NOT TESTED. Prepared: `scripts\sensor_uninstall.bat`, then `audit\check_uninstall.bat`, `scripts\sensor_update.bat` and `audit\check_reinstall.bat`. It needs your approval.

## Database Integrity

After every install, update, restart, deny/restore and live test:

- `PRAGMA quick_check` = **ok**;
- **0** duplicate `(channel, record_id)` rows;
- schema 9;
- 707 → 730 events, all real.

A backup copy was taken before the tests. TESTED — REAL WINDOWS ✅.

## IPC Security

| Check | Result |
|---|---|
| Listeners | `netstat`: sensor, tray and console each have **0 sockets** (real) |
| Outbound | none (code; netstat) |
| Pipe ACL | unchanged: SYSTEM, Administrators and the service full; INTERACTIVE read/write-data/attributes **without** create-instance; NETWORK denied; remote clients rejected. B-6 changed the **client's request**, not the server's grant. |
| Server verification | readable token → service SID; otherwise **session 0** via the pipe (a normal user cannot run there) |
| Commands | unchanged allow-list of 6; hostile inputs rejected (real) |
| Program Files | admin-protected (inherited; Users RX) |
| ProgramData | protected root; Users RX; service M |

No security was loosened to fix B-1 or B-6.

## Resource Usage

All figures are real, packaged build, `reliability.bat`:

| Process / mode | Avg CPU | Peak CPU (10 s) | Working set | Private | Threads | Handles |
|---|---|---|---|---|---|---|
| Sensor only (10 min, tray and console closed) | **0.001 %** | 0.02 % | **36.4–36.5 MB** | 22.8 MB | 8 | 183 |
| Sensor + Tray (3 min): sensor | 0.001 % | 0.01 % | 36.6 MB | 22.9 MB | 9 | 185 |
| Sensor + Tray: tray | 0.000 % | 0.00 % | 31.6 MB | 18.6 MB | 2–5 | 171 |
| + Console (2 min): console | 0.004 % | 0.05 % | **105.8 MB** | 62.3 MB | 4–8 | ~450 |

There is no regression against the baseline (sensor 0.0 % / 36.6 MB, tray 31–33 MB).

## Remaining Known Issues

| ID | Severity | Issue |
|---|---|---|
| B-7 | MEDIUM | A **non-elevated** process cannot read the sensor DB **while the sensor runs** (SQLite read-only WAL needs write access to `-shm`; real "unable to open database file"). The console asks for elevation by default; **declining UAC shows no data** while the sensor runs. Not fixed: it needs a design choice (data over IPC, or a writable `-shm` for users). |
| P-1 | LOW–MEDIUM | Live-burst detection cost (unchanged; out of scope) |
| L-1 | LOW | The `net use` test cannot reach the DET-001 threshold |
| — | — | Toast click works only while the toast is shown; there is no installer; Sysmon is not installed on the test PC |
| — | process | The file-transfer tool can serve a stale copy when one staging path is reused; the audit used unique paths after noticing it |

## Final Verdict

**PARTIAL.**

- **B-1, B-2, B-3, B-4 and B-5 are fixed and proven on real Windows.**
- **B-6** was found and fixed, and its normal-user effect was verified.
- Full tests pass, Ruff and the GUI smoke pass, the DB is intact, the live event arrived without a scan, there are no listeners, and idle cost is unchanged.

Before PASS, three things are needed: the real toast-and-click test (needs you), reboot / sleep / uninstall-reinstall (need your approval), and a decision on B-7.
