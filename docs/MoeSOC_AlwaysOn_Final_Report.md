# MoeSOC Always-On Final Report

Scope: fix B-7, rebuild, and finish the real-Windows validation of the Always-On sensor milestone. No new features, detections, telemetry sources or GUI redesign.

Test PC: Windows 11 (10.0.26200), 16 logical CPUs, PyInstaller build of MoeSOC 1.0.0. Earlier work: [MoeSOC_AlwaysOn_Reliability_Report.md](MoeSOC_AlwaysOn_Reliability_Report.md) (B-1 to B-6).

"Normal user" in this report means the signed-in account running **without elevation**: the filtered UAC token, Medium integrity, with Administrators as a deny-only group. No separate standard account was used, because that would need a password typed for it. For file access and the pipe, the filtered token is what a standard user has.

Status labels: TESTED — REAL WINDOWS ✅ · TESTED — AUTOMATED ✅ · TESTED — SYNTHETIC ⚠ · PARTIALLY TESTED ⚠ · NOT TESTED · BLOCKED BY USER INTERACTION · BLOCKED BY ENVIRONMENT · FAILED ❌

## Summary

| ID | Defect | Fix | Status |
|---|---|---|---|
| B-1 | Reinstall/update broke the access rights under `C:\ProgramData\MoeSOC` | Rights set on the root only, then inherited; damaged children repaired | TESTED — REAL WINDOWS ✅ |
| B-2 | A failed update left the sensor stopped and the program folder half replaced | Stage, validate, swap folders, health check, roll back | TESTED — REAL WINDOWS ✅ |
| B-3 | The deep link opened several consoles | Delivery decided by the console's reply | TESTED — REAL WINDOWS ✅ |
| B-4 | Sensor health disappeared when the database failed | IPC starts first; ERROR state with `last_error` | TESTED — REAL WINDOWS ✅ |
| B-5 | Multi-client IPC fix not verified on the deployed build | Verified | TESTED — REAL WINDOWS ✅ |
| B-6 | A normal user's tray could not connect to the pipe | Exact client access mask; server trust by session 0 | TESTED — REAL WINDOWS ✅ |
| B-7 | A normal-user console could not use the sensor's data | See below | TESTED — REAL WINDOWS ✅ |
| B-8 (found here) | Reinstall right after an uninstall was refused: the program folder could not be renamed while the closed tray was still exiting | Bounded rename retry (≈10 s, PermissionError only); a lasting lock still rolls back | TESTED — REAL WINDOWS ✅ |

## B-7

### Reproduction (real Windows, normal user, sensor running)

`audit\b7_diag.py`, run without elevation:

- `moesoc.db-wal` and `moesoc.db-shm` were **missing** while the sensor was running.
- `sqlite3.connect(db)` and `sqlite3.connect("file:…?mode=ro")` both failed: `SQLITE_CANTOPEN unable to open database file`.
- The console's `Database` class only "worked" by falling back to `immutable=1`. That mode tells SQLite the file never changes, which is **not safe** while the sensor writes: reads can be stale or torn.
- A write by the console was refused: "read-only for your account. Open MoeSOC as administrator".

`audit\b7_shm_test.py` (temporary folder, same SQLite 3.50.4) confirmed the cause and the fix:

| Test | Result |
|---|---|
| Keeper connection that never ran a statement, three short-lived writers, then close | `-wal=no -shm=no`: the files are deleted |
| Keeper connection that ran one read | `-wal=yes -shm=yes` |
| A `mode=ro` reader that may not write the db, `-wal` or `-shm`, while another process writes | 72 reads, 0 errors, row counts increasing (400 → 6180), `quick_check` ok each time, writes refused |

### Root cause

The sensor kept a "keeper" connection, meant to keep the WAL files in place for read-only consoles. It never ran a statement. SQLite opens the WAL index lazily, on a connection's first read, so the keeper never held the `-shm`. The last short-lived writer therefore checkpointed and deleted both files. A normal user may not create files in the protected data folder, so `mode=ro` failed.

A second cause appeared during the fix, also on real Windows. SQLite silently opens a database it may not write in read-only mode, and on that read-only WAL connection `BEGIN IMMEDIATE` **succeeds**. The first write probe therefore never noticed read-only access, and the console kept trying to write directly. `audit\b7_probe.py` showed `BEGIN IMMEDIATE: ok`, then `UPDATE: SQLITE_READONLY`.

### Fix (smallest secure change)

| Area | Change |
|---|---|
| Sensor (`core.open_keeper`) | The keeper runs one read and is fully reset, so it holds the WAL files open but no read transaction. Checkpoints are not blocked (tested). |
| Console reads | Unchanged: `mode=ro` with WAL, now consistent while the sensor writes. `immutable=1` is used only when no `-wal` exists (sensor stopped). |
| Write detection (`Database._probe_writable`) | Once per process, ask the **file** for write access: `os.open(O_RDWR)` on Windows, which is a plain CreateFile and changes nothing; `os.access` elsewhere. |
| Triage, verdict, notes | A read-only console sends `set_triage` / `add_note` over the existing pipe. The sensor validates the request (known status, positive integer ID, text body, existing finding), saves it with the same repository code, and logs `Triage by console (pid …, session …)`. The sensor stays the only writer. |
| Suppressions, rule changes, retention | **Not** offered over IPC: they change what is detected or kept. A normal-user console says they need "MoeSOC opened as administrator". The retention page no longer says "saved" before the result is known. |
| Start-up | With the sensor installed, `MoeSOC.exe` no longer asks for UAC, also from a toast click. Without a sensor it asks as before. |
| Health (sensor mode) | The Overview shows what the sensor reports over IPC: sensor state, each channel, Script Block Logging policy, Sysmon service. "Not reachable" is reported, never guessed. |
| Tray log | Logs "Sensor connected: STATE" on (re)connect, so a reconnect can be verified. |

Unchanged: the ProgramData rights (Users: read), the pipe access list, the WAL and SQLite settings, and the detection pipeline. There is still no network listener.

### Automated tests (`tests/test_b7_console_access.py`, 27 tests, plus 1 tray test)

- A keeper that never reads lets the WAL files disappear (documents the root cause); the fixed keeper keeps them and does not block `wal_checkpoint(TRUNCATE)`.
- A `mode=ro` reader on files and a folder it may not write: on Linux this runs only as a non-root user (run as `nobody`: passed; skipped as root and on Windows).
- The dispatcher accepts valid triage and notes, and rejects an unknown status, a bool, negative, string or oversized ID, a non-text body, and the commands `add_suppression` and `set_retention`.
- A real `SensorCore` saves triage and notes, records history, refuses a missing finding and an empty note.
- `console_write`: the reply, the refusal message, sensor unreachable, and a message too large.
- A read-only console routes to the sensor and writes nothing itself; a writable console writes directly.
- The Windows write probe uses the file rights (denied → read-only), and probes only once.
- No UAC prompt with the sensor installed; it still asks without one.
- Sensor-mode health: live, not installed, unreachable and ERROR.
- The tray logs reconnects.

### Real Windows validation (normal user, deployed build, sensor running)

`audit\b7_console_check.py pages` drives the real console window: same code as the build, sensor mode, the real sensor database. **PASSED** at 17:56.

| Check | Result |
|---|---|
| `-wal` / `-shm` present while the sensor runs | yes / yes |
| Database detected as read-only; writes go through the sensor | yes |
| Startup (health, data load, event search) | no errors |
| Overview event count | 842 = database count |
| Health | Sensor Available; Security Available (live); PowerShell **Limited** (live, but Script Block Logging not enabled by policy: truthful); Defender Available; Sysmon Unavailable (not installed: truthful); Database Available |
| Events / search | 500 listed; filter 4624 → 777 = database count; raw XML shown |
| Timeline (pivot) | loads (6 items) |
| Process Tree | no crash. This PC has **0** process-creation events (no Sysmon, process auditing off), so the page explains "needs a process-creation event". A real tree: BLOCKED BY ENVIRONMENT |
| Reports | summary report saved by the normal user |
| Tuning | loads |
| Retention preview | works |
| Retention change | refused: "…suppressions, rule changes and retention need MoeSOC opened as administrator." |
| Background reads during the run | 15 reads, 0 errors, 0 lock errors |
| `PRAGMA quick_check` / duplicates | ok / 0 |

`audit\b7_console_check.py finding` ran on the real COR-001 finding #2 from the notification test, as a normal user with the sensor running. **PASSED** at 18:39.

| Check | Result |
|---|---|
| Finding detail; risk and confidence explanation | shown |
| Evidence drill-down | lists the 9 linked events (9 in the database) |
| Finding timeline / story / finding report | loads, highlights evidence / narrative shown / saved |
| Triage "Start Investigation" | status line "saved by the MoeSOC Sensor"; database `INVESTIGATING` |
| Analyst note | saved through the sensor; shown after refresh |
| Verdict "Benign" (authorized test) | database `BENIGN`, verdict `BENIGN` |
| History | `NEW → INVESTIGATING → BENIGN` |
| Sensor log (audit trail) | `Triage by console (pid 15132, session 5): finding #2 NEW -> INVESTIGATING`, `Note #1 added by console …`, `… INVESTIGATING -> BENIGN` |
| Concurrent reads while the sensor wrote | 22 reads, 0 errors, 0 lock errors |
| `quick_check` / duplicates | ok / 0 (945 events) |

The console never wrote the file itself: the database is read-only for this account. All three changes were written by the sensor while the console kept reading.

## Build

| Build | Code | Self-test |
|---|---|---|
| 1 (17:45) | `7687c56` | PASSED |
| 2 (17:57) | `6308911` (write-probe fix) | PASSED |
| 3 (18:03, deployed 18:05) | `d731f00` (tray reconnect log) | PASSED |
| **4 (19:09, final, deployed 19:11 by the reinstall)** | **`5e282f0`** (B-8 rename retry) | **PASSED**: version, 12 rules, schema v9, icon, Windows API, GUI 9 pages |

All 110 build inputs (`app.py`, `moesoc/`, `packaging/`, `rules/`) on the PC were compared with `d731f00` before build 3: 0 differences. For build 4, the one changed module (`moesoc/sensor/manage.py`) and its tests were synced and compared again: identical. No other code changed between `d731f00` and `5e282f0`.

## Deployment

`audit\final_deploy.bat` (one UAC prompt) runs `dist\MoeSOC\MoeSOCSensor.exe install --copy-to-program-files`, the B-2 rollback-safe update. 18:05:51:

- Sensor stopped, folders swapped, sensor started, "Sensor is running and answers over IPC"; exit 0.
- Installed `MoeSOC.exe`, `MoeSOCSensor.exe` and `MoeSOCTray.exe` dated 18:04:20; no `.old`, `.new` or `.failed` folder left.
- Data rights unchanged: inherited; service M, Users RX, Administrators F, SYSTEM F.
- `-wal` and `-shm` present after the restart.
- The tray was closed with WM_CLOSE and reopened in the user's session ("Sensor connected: MONITORING" at 18:06:01).

## Final Full Tests (final code `5e282f0`)

| Suite | Passed | Failed | Skipped | Notes |
|---|---|---|---|---|
| Windows pytest, **elevated** (19:18) | **672** | 0 | 1 | the skip: B-7 POSIX-permission test (Windows covered by the real test) |
| Windows pytest, **non-elevated** (`verify_windows.bat`, 19:14) | **671** | 0 | 2 | plus `test_windows_integration`: "Not elevated: Security log access correctly reported as denied" |
| Linux pytest (root) | **670** | 0 | 3 | 2 Windows-only, 1 needs a non-root user (same 673 tests) |
| Linux, B-7 + storage tests as user `nobody` | 31 | 0 | 0 | |
| Ruff check / format | clean | | | Windows 182 files, Linux 184 files |
| GUI smoke (Windows, non-elevated, 19:14) | **76 / 76** | 0 | | "GUI SMOKE: PASSED" |

The suites include the service, IPC, notification, tray and deep-link, live-monitor and subscription, migration and schema tests, the A-1 to A-11 regressions and the B-1 to B-8 regressions. Build 3 (`d731f00`) had also passed the same suites: elevated 669/1, non-elevated 668/2.

## Real Windows Health Check (after deployment, 18:12, normal user)

| Item | Result |
|---|---|
| Sensor | RUNNING (service state 4) |
| IPC | AVAILABLE: `status` answered as a normal user |
| Database | AVAILABLE: `ok (schema v9)` |
| Security | LIVE |
| PowerShell | LIVE subscription; Script Block Logging **not enabled** by policy (reported as Limited: truthful) |
| Defender | LIVE |
| Sysmon | not installed (truthful; MoeSOC never installs it) |
| Tray | CONNECTED: "Sensor connected: MONITORING"; autostart entry present |
| Console (normal user) | WORKING (see B-7) |
| Notification policy | HIGH and CRITICAL on, MEDIUM off, not paused, cooldown 60 min |
| TCP / UDP sockets of MoeSOC processes | **0 / 0**: no listener, no outbound connection |
| `quick_check` | ok |
| Duplicate channel/record rows | 0 (851 events) |

## Real Notification

The user did the lock-screen test: wrong passwords, then a normal sign-in. Evidence comes from `audit\out\check_toast.txt` (18:39), the console log and the user's observations.

| Question | Answer | Evidence |
|---|---|---|
| Windows events generated? | **Yes**: 7 × Event 4625 in the last hour | database |
| Events ingested without Scan Now? | **Yes** | last catch-up 15:06:00 UTC (the 18:06 sensor start); last event 15:35:42 UTC; 16 live batches, 60 events stored live since then |
| Finding generated? | **Yes**: DET-001 #1 (MEDIUM, risk 40, 7 occurrences) and **COR-001 #2 (HIGH, risk 70, 9 evidence events)** | database |
| Number of toasts | **1** (COR-001) | user saw 1; sensor `seq` = 1; `notification_state (2, HIGH, COR-001, times_notified=1)`. DET-001 is MEDIUM, and MEDIUM notifications are off: recorded, not shown, as designed. |
| Notification state persisted? | **Yes** | `notification_state` row for #2 |

Status: TESTED — REAL WINDOWS ✅

## Toast Click / Deep Link

| Question | Answer | Evidence |
|---|---|---|
| Toast click received? | **Yes** | 18:30:30 `Packaged start: started` |
| UAC prompt? | **No** | user; `admin=False`; "Opened … read-only (this account may not write it)" |
| Correct finding opened? | **Yes**: COR-001 #2 | `Deep link: opened finding #2`; user saw COR-001 with the 4625 evidence |
| Tray → Recent finding | **same console reused** | 18:35:31 `Handed the request to the running console` → `Deep link: opened finding #2` |
| Duplicate console? | **No** | one `MoeSOC` process (started 18:30:29); user saw no second window |

Status: TESTED — REAL WINDOWS ✅

## Reboot

The user approved the reboot and restarted the PC themselves (no automatic reboot), then signed in without opening the console. Evidence: `audit\out\check_reboot.txt` (18:55, normal user), the sensor log and the tray log.

| Check | Result |
|---|---|
| Clean stop at shutdown | 18:50:43 the subscription ended (`EvtNext` winerror 1818, the event log service going away), "Monitor OFF", 18:50:48 "MoeSOC Sensor stopped" |
| Boot | 18:51:03 |
| Sensor starts automatically | **Yes**: 18:53:31, automatic (delayed) start, without sign-in or console; state MONITORING |
| Sensor before the console | **Yes**: the console never started (no `MoeSOC` process; the console log has no entry after the reboot) |
| Tray starts after login | **Yes**: 18:51:57 (HKCU Run) |
| Console does not auto-start | **Yes** |
| IPC reconnects | **Yes**: the tray started before the delayed service, waited, and logged "Sensor connected: MONITORING" at 18:53:42 |
| Catch-up | 18:53:32; 94 events stored from the offline gap |
| Live subscriptions | Security, PowerShell, Defender **live**; Sysmon not installed |
| Database | `quick_check` ok; schema v9 |
| Duplicates | **0** (1 043 events) |
| Analyst data kept | finding #2 still BENIGN; 1 note; 4 history rows |
| No repeated notification | `notification_state` unchanged (times_notified 1); sensor `seq` 0 |
| Network | 0 TCP, 0 UDP |

Status: TESTED — REAL WINDOWS ✅

## Sleep / Resume

The user put the PC to sleep and woke it (no automatic sleep). Evidence: `audit\out\check_sleep.txt` (19:03, normal user) and the sensor log.

| Check | Result |
|---|---|
| Resume detected | 19:02:24 "Resume from sleep: catching up and resubscribing". It was logged twice, because Windows sent two power events; the handling is idempotent and caused no duplicates. |
| Catch-up runs | **Yes**: `last_catch_up_at` 19:02:31 local; events 1 043 → 1 091 |
| Subscriptions recover | **Yes**: 19:02:31 "Monitor ON: Monitoring live: Security, PowerShell, Defender"; state MONITORING |
| IPC alive | **Yes**: `status` and `get_prefs` answered a normal user after resume |
| Tray | The service process survived sleep, so the pipe stayed reachable. The tray logged no disconnect and stayed connected (last "Sensor connected" at 18:53:42; no "Sensor offline" afterwards). |
| Duplicates | **0** |
| Database | `quick_check` ok; finding #2 BENIGN, note and history kept |
| Network | 0 TCP, 0 UDP |

Status: TESTED — REAL WINDOWS ✅

## Uninstall / Reinstall

The user approved the uninstall. Evidence: `audit\out\uninstall_reinstall.txt` (19:06), `audit\out\reinstall_only.txt` (19:11), `audit\out\check_reinstall.txt` (19:13, normal user) and the tray log.

**Uninstall (19:06):**

| Check | Result |
|---|---|
| Service removed cleanly | "Sensor stopped. Service registration removed."; `sc query` → 1060 (does not exist); the service account was removed from Event Log Readers |
| Tray startup entry removed | `HKCU\…\Run\MoeSOC Tray` gone (reg exit 1); `sensor.json` marker removed |
| `C:\ProgramData\MoeSOC\data` remains | yes; `moesoc.db` 6.5 MB |
| Database not deleted | `quick_check` ok, schema 9, 1 137 events, 0 duplicates; findings #1 NEW and #2 BENIGN/BENIGN; 1 note, 4 history rows, 1 notification state |

**First reinstall (19:06): FAILED ❌, then fixed (B-8).** `install --copy-to-program-files` reported: "The update could not replace C:\Program Files\MoeSOC Endpoint (PermissionError: [WinError 5] … -> 'MoeSOC Endpoint.old'). The previous version was kept."

- The B-2 rollback worked: nothing was half replaced, no service was registered, data was untouched, and the tray was reopened.
- **Root cause** (from the tray log): the update closed the still-running tray (WM_CLOSE). The tray logged "exited" at 19:06:22.25, and the folder rename followed within about a second. `close_tray` waited for the tray *window* to disappear, plus 1 s, but the PyInstaller process was still unloading its files from the folder.
- A normal update hides this, because stopping the service takes several seconds before the rename. After an uninstall the service is already gone, so the rename came at once.
- **Fix** `5e282f0`: the folder rename is retried on `PermissionError` only, for at most about 10 s. Any other error is not retried, and a lasting lock still goes to the rollback. Three new unit tests; build 4 self-test PASSED.

**Reinstall with build 4 (19:11):**

| Check | Result |
|---|---|
| Before | `MoeSOCTray` running from the program folder; service not installed |
| Reinstall | "Updated the application … Service registered … Sensor started. Sensor is running and answers over IPC."; exit 0 |
| Program folder | `MoeSOC.exe`, `MoeSOCSensor.exe`, `MoeSOCTray.exe` dated 19:10; no `.old`, `.new` or `.failed` left |
| Tray | closed at 19:11:59, reopened at 19:12:01, "Sensor connected: MONITORING" at 19:12:06; Run entry restored; marker present |
| Old data readable | yes, as a normal user (19:13): findings #1 and #2 (BENIGN), note and history intact |
| Catch-up | the scan read the events from the gap: 10 new, 2 detections (0 new, so no duplicate findings or notifications) |
| Database | `quick_check` ok; 1 151 events; **0 duplicates**; data rights inherited (service M, Users RX) |
| Network | 0 TCP, 0 UDP |

Status: TESTED — REAL WINDOWS ✅ (after the B-8 fix; the first attempt is recorded as FAILED ❌ above)

## Resource Usage

`audit\res_idle.py`, a normal user reading Windows performance counters: 60 samples × 10 s = 10 minutes, PC idle, 18:13–18:23, deployed build. CPU is normalised to the 16 logical CPUs.

| Process | CPU avg | CPU peak (10 s) | Working set | Private | Handles | Threads |
|---|---|---|---|---|---|---|
| MoeSOCSensor | **0.0094 %** | 0.263 % | **36.8–37.0 MB** | 20.9–21.2 MB | 186–192 | 7–9 |
| MoeSOCTray | **0.0002 %** | 0.010 % | **33.2–33.3 MB** | 16.2–16.3 MB | 180 | 2–4 |

Compared with the previous build (sensor 36.4 MB working set, average 0.001 %), the keeper's one read adds no measurable memory. The higher average comes from the single peak sample, a live event batch. No growth over the 10 minutes. Status: TESTED — REAL WINDOWS ✅

## Remaining Known Issues

| ID | Severity | Issue |
|---|---|---|
| P-1 | LOW–MEDIUM | Live-burst detection cost (unchanged; out of scope) |
| L-1 | LOW | The `net use` test cannot reach the DET-001 threshold (test-method limit) |
| L-2 | LOW | The sensor logs a missing optional Sysmon channel at ERROR level on each start (`winerror=15007`); the status is correct ("not installed") |
| L-3 | LOW | Uninstall removes the tray's startup entry but leaves an already running tray open (it shows "offline" until sign-out or Exit) |
| L-4 | LOW | The suspend/resume handler logs "Resume from sleep" twice when Windows sends two power events (harmless; no duplicates) |
| L-5 | INFO | Suppressions, rule changes and retention need an administrator console. This is by design (B-7) and documented |
| — | — | No installer (Inno Setup not installed); Sysmon not installed on the test PC; no process-creation telemetry, so the Process Tree cannot be shown with real data |

## Final Verdict

**PASS.**

- B-1 to B-7 are fixed and TESTED — REAL WINDOWS ✅. B-8, found during the uninstall/reinstall test, is fixed and its fix tested on real Windows.
- Every requested real-Windows test was performed on the final build:
  - non-admin console;
  - live delivery;
  - one real toast, the click, and console reuse;
  - reboot;
  - sleep/resume;
  - uninstall/reinstall with data kept.
- Final suites on `5e282f0`: Windows elevated 672 passed / 0 failed / 1 skipped; non-elevated 671 / 0 / 2; Linux 670 / 0 / 3; Ruff clean; GUI smoke 76/76.
- The database is intact (`quick_check` ok, 0 duplicates), there are no network sockets, and idle cost is tiny (sensor 0.009 % CPU / 37 MB; tray 0.0002 % / 33 MB).

Limits, stated plainly:
- "Normal user" was the filtered UAC token of the signed-in account, not a separate standard account.
- The Process Tree could not be shown with real data, because this PC has no process-creation telemetry (BLOCKED BY ENVIRONMENT).
- Remaining items are LOW (table above).
